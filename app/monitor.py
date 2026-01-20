from __future__ import annotations
import threading
import time
import subprocess
from typing import Optional, List, Dict, Any, Set
from datetime import datetime
from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, EAPOL, sniff

from .state import get_state
from .storage import get_storage
from .logging import log

class ChannelHopper:
    """Handles cycling through WiFi frequencies using the 'iw' command."""
    
    def __init__(self, interface: str, band: str = 'abg'):
        self.interface = interface
        self.band = band
        self.active = False
        self._thread: Optional[threading.Thread] = None
        
        # Channels to hop (simplified)
        self.channels = self._get_channels_for_band(band)
        self.hop_interval = 0.25 # 250ms per channel
        
    def _get_channels_for_band(self, band: str) -> List[int]:
        if band == 'bg':
            return list(range(1, 14))
        elif band == 'a':
            return [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
        else: # abg
            return list(range(1, 14)) + [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]

    def _hop_loop(self):
        idx = 0
        while self.active:
            try:
                channel = self.channels[idx % len(self.channels)]
                subprocess.run(['iw', 'dev', self.interface, 'set', 'channel', str(channel)], 
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                idx += 1
            except Exception:
                pass
            time.sleep(self.hop_interval)

    def start(self):
        if not self.active:
            self.active = True
            self._thread = threading.Thread(target=self._hop_loop, daemon=True)
            self._thread.start()
            
    def stop(self):
        self.active = False
        if self._thread:
            self._thread.join(timeout=1)
            self._thread = None

class WirelessMonitor:
    """
    Unified background monitoring engine.
    Sniffs management frames to discover networks and clients in real-time.
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.state = get_state()
        self.storage = get_storage()
        self.active = False
        self._thread: Optional[threading.Thread] = None
        self.hopper: Optional[ChannelHopper] = None
        
        # Internal cache to avoid excessive storage writes
        self._last_flush = time.time()
        self._flush_interval = 5.0
        self._pending_networks: Dict[str, Dict[str, Any]] = {}

    def _packet_callback(self, pkt):
        if not self.active: return
        
        try:
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                bssid = pkt[Dot11].addr3.upper()
                
                # Safer ESSID extraction
                essid = "Unknown"
                if pkt.haslayer(Dot11Elt):
                    elt = pkt.getlayer(Dot11Elt)
                    if elt.ID == 0: # SSID
                        essid = elt.info.decode('utf-8', 'ignore')
                
                # Safer channel extraction
                channel = None
                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 3: # DS Parameter Set (Channel)
                        try:
                            channel = ord(elt.info)
                        except:
                            pass
                        break
                    elt = elt.payload.getlayer(Dot11Elt)
                
                # Signal strength (RadioTap)
                dbm_signal = -70
                if hasattr(pkt, 'dBm_AntSignal'):
                    dbm_signal = pkt.dBm_AntSignal
                
                # Update local cache
                self._pending_networks[bssid] = {
                    'essid': essid,
                    'channel': channel,
                    'power': str(dbm_signal),
                    'last_seen': datetime.now().isoformat(),
                    'encryption': 'WPA2' if 'WPA2' in str(pkt) else 'Open'
                }
                
            elif pkt.haslayer(Dot11):
                # Discover clients/stations
                addr1 = pkt.addr1.upper() if pkt.addr1 else None # Receiver
                addr2 = pkt.addr2.upper() if pkt.addr2 else None # Transmitter
                addr3 = pkt.addr3.upper() if pkt.addr3 else None # BSSID
                
                if addr3 and addr3 != 'FF:FF:FF:FF:FF:FF':
                    # If addr2 is a station (not BSSID)
                    if addr2 and addr2 != addr3:
                        self._add_station(addr3, addr2)
                    # If addr1 is a station (not BSSID/Broadcast)
                    if addr1 and addr1 != addr3 and addr1 != 'FF:FF:FF:FF:FF:FF':
                        self._add_station(addr3, addr1)

            # Periodic flush to storage
            if time.time() - self._last_flush >= self._flush_interval:
                self.flush()
                
        except Exception:
            pass

    def _add_station(self, bssid: str, station_mac: str):
        if bssid not in self._pending_networks:
            self._pending_networks[bssid] = {'stations': set()}
        if 'stations' not in self._pending_networks[bssid]:
            self._pending_networks[bssid]['stations'] = set()
        
        self._pending_networks[bssid]['stations'].add(station_mac)

    def flush(self):
        """Commit pending updates to state/storage."""
        if not self._pending_networks: return
        
        payload = []
        for bssid, info in self._pending_networks.items():
            stations = list(info.get('stations', []))
            payload.append({
                'bssid': bssid,
                'essid': info.get('essid'),
                'channel': info.get('channel'),
                'power': info.get('power'),
                'encryption': info.get('encryption', 'WPA2-PSK'),
                'stations': stations,
                'has_clients': len(stations) > 0,
                'clients': len(stations),
            })
            
        self.state.merge_scan_results(payload)
        self._pending_networks.clear()
        self._last_flush = time.time()

    def start(self):
        if self.active: return
        self.active = True
        
        # Start hopper
        band = self.state.settings.get('band', 'abg')
        self.hopper = ChannelHopper(self.interface, band)
        self.hopper.start()
        
        # Start sniffer thread
        def _sniff_thread():
            log(f"WirelessMonitor: Starting sniff on {self.interface}", "info")
            sniff(iface=self.interface, prn=self._packet_callback, store=0, stop_filter=lambda x: not self.active)
            log("WirelessMonitor: Sniff thread stopped", "info")
            
        self._thread = threading.Thread(target=_sniff_thread, daemon=True)
        self._thread.start()

    def stop(self):
        self.active = False
        if self.hopper:
            self.hopper.stop()
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None
        self.flush()

# Singleton for the background monitor
_monitor: Optional[WirelessMonitor] = None

def get_monitor(interface: str = None) -> WirelessMonitor:
    global _monitor
    if not _monitor:
        if not interface:
            state = get_state()
            interface = state.monitor_interface
        if not interface:
            raise Exception("No monitor interface available for WirelessMonitor")
        _monitor = WirelessMonitor(interface)
    return _monitor
