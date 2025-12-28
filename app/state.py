"""
Application state manager.

Centralizes all runtime state in one place with clean accessors.
Delegates persistence to the Storage layer.
"""

from __future__ import annotations
import threading
from queue import Queue
from datetime import datetime
from typing import Optional, List, Dict, Any

from .storage import get_storage, Storage
from .models import Network, Device, HashFile, Stats, Settings, CrackTask


class AppState:
    """
    Central state manager for the application.
    
    Holds transient runtime state (flags, queues) and provides
    a clean interface to the persistent Storage layer.
    """
    
    def __init__(self, storage: Optional[Storage] = None):
        self._storage = storage or get_storage()
        self._lock = threading.RLock()
        
        # Runtime flags (not persisted)
        self.scanning = False
        self.attacking = False
        self.cracking = False
        self.vigilant = False  # Constant passive scanning mode
        self.rolling_cracking = False  # Auto-solve background cracking
        self.wordlist_order: List[str] = []  # User-specified wordlist order for auto-solve
        
        # Current operation targets
        self.monitor_interface: Optional[str] = None
        self.current_network: Optional[Network] = None
        self.current_crack: Optional[CrackTask] = None
        
        # Queues
        self.log_queue: Queue = Queue()
        self.crack_queue: List[CrackTask] = []
    
    # ─────────────────────────────────────────────────────────────
    # Storage delegation
    # ─────────────────────────────────────────────────────────────
    
    @property
    def storage(self) -> Storage:
        return self._storage
    
    @property
    def settings(self) -> Settings:
        return self._storage.settings
    
    @property
    def stats(self) -> Stats:
        return self._storage.stats
    
    # Network accessors
    def get_network(self, bssid: str) -> Optional[Network]:
        return self._storage.get_network(bssid)
    
    def get_all_networks(self) -> List[Network]:
        return self._storage.get_all_networks()
    
    def upsert_network(self, bssid: str, **kwargs) -> Network:
        return self._storage.upsert_network(bssid, **kwargs)
    
    # Device accessors
    def get_device(self, mac: str) -> Optional[Device]:
        return self._storage.get_device(mac)
    
    def get_all_devices(self) -> List[Device]:
        return self._storage.get_all_devices()
    
    def upsert_device(self, mac: str, network_bssid: str = None) -> Device:
        return self._storage.upsert_device(mac, network_bssid)
    
    # Hash accessors
    def get_hash(self, path: str) -> Optional[HashFile]:
        return self._storage.get_hash(path)
    
    def get_all_hashes(self) -> List[HashFile]:
        return self._storage.get_all_hashes()
    
    def upsert_hash(self, path: str, **kwargs) -> HashFile:
        return self._storage.upsert_hash(path, **kwargs)
    
    # ─────────────────────────────────────────────────────────────
    # High-level operations
    # ─────────────────────────────────────────────────────────────
    
    def merge_scan_results(self, networks_payload: List[Dict[str, Any]]) -> None:
        """Merge live scan results into storage."""
        if not networks_payload:
            self._storage.mark_all_cached(set())
            return
        
        now = datetime.now().isoformat()
        active_bssids = set()
        
        with self._storage.batch_update():
            for net in networks_payload:
                bssid = (net.get('bssid') or '').upper()
                if not bssid:
                    continue
                active_bssids.add(bssid)
                
                stations = [mac.upper() for mac in net.get('stations', [])]
                self._storage.upsert_network(
                    bssid,
                    essid=net.get('essid'),
                    channel=net.get('channel'),
                    power=net.get('power'),
                    encryption=net.get('encryption', 'WPA2-PSK'),
                    stations=stations,
                    cached=False,
                    last_seen=now,
                )
                
                for mac in stations:
                    self._storage.upsert_device(mac, bssid)
            
            self._storage.mark_all_cached(active_bssids)
    
    def reset_cache(self) -> None:
        """Clear all cached data (on interface change)."""
        self._storage.reset_cache()
        self._storage.reset_stats()
    
    def save(self) -> None:
        """Persist any pending changes."""
        self._storage.flush()
    
    # ─────────────────────────────────────────────────────────────
    # Status helpers
    # ─────────────────────────────────────────────────────────────
    
    def is_busy(self) -> bool:
        """Check if any operation is in progress."""
        return self.scanning or self.attacking or self.cracking or self.vigilant
    
    def get_status_dict(self) -> Dict[str, Any]:
        """Get full status for API response."""
        return {
            'scanning': self.scanning,
            'attacking': self.attacking,
            'cracking': self.cracking,
            'vigilant': self.vigilant,
            'rolling_cracking': self.rolling_cracking,
            'monitor_interface': self.monitor_interface,
            'stats': dict(self.stats),
            'settings': dict(self.settings),
            'current_network': dict(self.current_network) if self.current_network else None,
        }


# Singleton instance
_state: Optional[AppState] = None


def get_state() -> AppState:
    """Get the global application state."""
    global _state
    if _state is None:
        _state = AppState()
    return _state


def reset_state() -> None:
    """Reset the global state (for testing)."""
    global _state
    if _state:
        _state.save()
    _state = None
