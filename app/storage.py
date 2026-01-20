"""
Persistent storage layer with JSON file backing.

Provides atomic writes, automatic saves, and clean separation
between in-memory state and disk persistence.
"""

from __future__ import annotations
import json
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from contextlib import contextmanager

from .models import (
    Network, Device, HashFile, Stats, Settings,
    create_network, create_device, create_hash_file, create_stats, create_settings
)


class Storage:
    """
    JSON-backed persistent storage for application state.
    
    Maintains in-memory indices for fast lookups with periodic
    persistence to disk. Uses a write-through strategy: changes
    are immediately reflected in memory and periodically flushed.
    """
    
    DATA_DIR = 'data'
    NETWORKS_FILE = 'networks.json'
    DEVICES_FILE = 'devices.json'
    HASHES_FILE = 'hashes.json'
    SETTINGS_FILE = 'settings.json'
    PASSWORDS_FILE = 'passwords.json'
    
    def __init__(self, data_dir: Optional[str] = None):
        self.data_dir = Path(data_dir or self.DATA_DIR)
        self._lock = threading.RLock()
        
        # In-memory indices (primary key -> record)
        self._networks: Dict[str, Network] = {}
        self._devices: Dict[str, Device] = {}
        self._hashes: Dict[str, HashFile] = {}
        self._passwords: Dict[str, Dict[str, Any]] = {} # BSSID -> {password, hex, salt, timestamp}
        self._settings: Settings = create_settings()
        self._stats: Stats = create_stats()
        
        # Dirty flags for lazy persistence
        self._dirty_networks = False
        self._dirty_devices = False
        self._dirty_hashes = False
        self._dirty_settings = False
        self._dirty_passwords = False
        
        # Ensure directories exist
        self.data_dir.mkdir(parents=True, exist_ok=True)
        for subdir in ('captures', 'hashes', 'wordlists', 'cracked'):
            Path(subdir).mkdir(exist_ok=True)
        
        # Lazy persistence settings
        self._last_flush_time = 0.0
        self._flush_interval = 10.0 # Save to disk at most every 10 seconds
        
        # Load existing data
        self._load_all()
    
    # ─────────────────────────────────────────────────────────────
    # File I/O
    # ─────────────────────────────────────────────────────────────
    
    def _file_path(self, filename: str) -> Path:
        return self.data_dir / filename
    
    def _load_json(self, filename: str) -> Any:
        """Load JSON file, return empty dict on error."""
        path = self._file_path(filename)
        if not path.exists():
            return {}
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"[!] Error loading {filename}: {e}")
            return {}
    
    def _save_json(self, filename: str, data: Any) -> bool:
        """Atomically save JSON file."""
        path = self._file_path(filename)
        tmp_path = path.with_suffix('.tmp')
        try:
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            tmp_path.replace(path)
            return True
        except Exception as e:
            print(f"[!] Error saving {filename} ({type(e).__name__}): {e}")
            if tmp_path.exists():
                tmp_path.unlink()
            return False
    
    def _load_all(self) -> None:
        """Load all data from disk."""
        with self._lock:
            self._networks = self._load_json(self.NETWORKS_FILE) or {}
            self._devices = self._load_json(self.DEVICES_FILE) or {}
            self._hashes = self._load_json(self.HASHES_FILE) or {}
            self._passwords = self._load_json(self.PASSWORDS_FILE) or {}
            settings = self._load_json(self.SETTINGS_FILE)
            if settings:
                self._settings.update(settings)
    
    def save_all(self, force: bool = False) -> None:
        """
        Save dirty data to disk with rate limiting.
        Set force=True to bypass the timer (e.g. on shutdown).
        """
        with self._lock:
            now = time.time()
            if not force and (now - self._last_flush_time) < self._flush_interval:
                return

            if self._dirty_networks:
                self._save_json(self.NETWORKS_FILE, self._networks)
                self._dirty_networks = False
            if self._dirty_devices:
                self._save_json(self.DEVICES_FILE, self._devices)
                self._dirty_devices = False
            if self._dirty_hashes:
                self._save_json(self.HASHES_FILE, self._hashes)
                self._dirty_hashes = False
            if self._dirty_settings:
                self._save_json(self.SETTINGS_FILE, self._settings)
                self._dirty_settings = False
            if self._dirty_passwords:
                self._save_json(self.PASSWORDS_FILE, self._passwords)
                self._dirty_passwords = False
            
            self._last_flush_time = now
    
    def flush(self) -> None:
        """Alias for save_all, flushes all pending changes immediately."""
        self.save_all(force=True)
    
    def _ensure_status(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure the status field exists in a network record."""
        if 'status' not in record or record['status'] is None:
            record['status'] = {'has_hash': False, 'cracked': False}
        return record['status']
    
    # ─────────────────────────────────────────────────────────────
    # Network operations
    # ─────────────────────────────────────────────────────────────
    
    def get_network(self, bssid: str) -> Optional[Network]:
        """Get network by BSSID."""
        with self._lock:
            return self._networks.get(bssid.upper())
    
    def get_all_networks(self) -> List[Network]:
        """Get all networks as a list."""
        with self._lock:
            return list(self._networks.values())
    
    def upsert_network(self, bssid: str, **updates) -> Network:
        """Create or update a network record."""
        with self._lock:
            key = bssid.upper()
            now = datetime.now().isoformat()
            
            if key in self._networks:
                record = self._networks[key]
            else:
                record = create_network(key)
            
            # Apply updates
            for field, value in updates.items():
                if value is None:
                    continue
                if field == 'stations':
                    record['stations'] = [m.upper() for m in value]
                    record['device_ids'] = record['stations']
                    record['has_clients'] = len(value) > 0
                    record['clients'] = len(value)
                elif field == 'hash_ids':
                    record['hash_ids'] = value
                    self._ensure_status(record)['has_hash'] = len(value) > 0
                elif field == 'status':
                    self._ensure_status(record).update(value)
                elif field == 'manual_cracked':
                    record['manual_cracked'] = value
                    # If manually marked as solved, also update status for UI consistency
                    self._ensure_status(record)['cracked'] = value
                    if value:
                        # Register in universal password registry
                        pw = record.get('cracked_password') or ''
                        self._passwords[key] = {
                            'password': pw,
                            'timestamp': datetime.now().isoformat()
                        }
                        self._dirty_passwords = True
                        
                        # Propagate to linked hashes
                        for hash_record in self._hashes.values():
                            if hash_record.get('network_bssid') == key:
                                hash_record['cracked'] = True
                                hash_record['cracked_password'] = pw
                                hash_record['cracked_at'] = datetime.now().isoformat()
                                self._dirty_hashes = True
                else:
                    record[field] = value
            
            # Universalizing: Check against known passwords registry
            if key in self._passwords and not self._ensure_status(record)['cracked']:
                pw_info = self._passwords[key]
                self._ensure_status(record)['cracked'] = True
                record['cracked_password'] = pw_info['password']
                if 'hex' in pw_info: record['cracked_hex'] = pw_info['hex']
                if 'salt' in pw_info: record['cracked_salt'] = pw_info['salt']
            
            record['last_seen'] = updates.get('last_seen', now)
            self._networks[key] = record
            self._dirty_networks = True
            return record
    
    def mark_all_cached(self, active_bssids: set) -> None:
        """Mark networks as cached if not in the active set."""
        with self._lock:
            active = {b.upper() for b in active_bssids}
            for key, record in self._networks.items():
                record['cached'] = key not in active
            self._dirty_networks = True
    
    def find_bssid_by_essid(self, essid: str) -> Optional[str]:
        """Find network BSSID by ESSID (case-insensitive)."""
        if not essid:
            return None
        target = essid.lower()
        with self._lock:
            for record in self._networks.values():
                if record.get('essid', '').lower() == target:
                    return record['bssid']
        return None
    
    def link_hash_to_network(self, hash_path: str, bssid: str) -> None:
        """Associate a hash file with a network."""
        if not hash_path or not bssid:
            return
        with self._lock:
            key = bssid.upper()
            if key not in self._networks:
                self.upsert_network(key)
            record = self._networks[key]
            hash_ids = record.get('hash_ids', [])
            if hash_path not in hash_ids:
                hash_ids.append(hash_path)
                record['hash_ids'] = hash_ids
                self._ensure_status(record)['has_hash'] = True
                self._dirty_networks = True
    
    def mark_network_cracked(self, bssid: str, password: str, 
                              hex_repr: str = None, salt: str = None,
                              hash_path: str = None) -> None:
        """Mark a network as cracked with the recovered password."""
        with self._lock:
            key = bssid.upper()
            if key not in self._networks:
                return
            record = self._networks[key]
            self._ensure_status(record)['cracked'] = True
            record['cracked_password'] = password
            record['cracked_hex'] = hex_repr
            record['cracked_salt'] = salt
            record['cracked_hash_path'] = hash_path
            self._dirty_networks = True

            # Register in universal password registry (The Registry of Known Truths)
            self._passwords[key] = {
                'password': password,
                'hex': hex_repr,
                'salt': salt,
                'hash_path': hash_path,
                'timestamp': datetime.now().isoformat()
            }
            self._dirty_passwords = True

            # Contagion: also mark all hashes linked to this network as cracked
            for hash_record in self._hashes.values():
                if hash_record.get('network_bssid') == key and not hash_record.get('cracked'):
                    hash_record['cracked'] = True
                    hash_record['cracked_password'] = password
                    hash_record['cracked_at'] = datetime.now().isoformat()
                    self._dirty_hashes = True
    
    def clear_networks(self) -> None:
        """Clear all network data (e.g., on interface change)."""
        with self._lock:
            self._networks.clear()
            self._dirty_networks = True
    
    # ─────────────────────────────────────────────────────────────
    # Device operations
    # ─────────────────────────────────────────────────────────────
    
    def get_device(self, mac: str) -> Optional[Device]:
        """Get device by MAC address."""
        with self._lock:
            return self._devices.get(mac.upper())
    
    def get_all_devices(self) -> List[Device]:
        """Get all devices as a list."""
        with self._lock:
            return list(self._devices.values())
    
    def upsert_device(self, mac: str, network_bssid: str = None) -> Device:
        """Create or update a device record."""
        with self._lock:
            key = mac.upper()
            now = datetime.now().isoformat()
            
            if key in self._devices:
                record = self._devices[key]
            else:
                record = create_device(key)
            
            record['last_seen'] = now
            if network_bssid:
                bssid = network_bssid.upper()
                if bssid not in record['networks']:
                    record['networks'].append(bssid)
            
            self._devices[key] = record
            self._dirty_devices = True
            return record
    
    def clear_devices(self) -> None:
        """Clear all device data."""
        with self._lock:
            self._devices.clear()
            self._dirty_devices = True
    
    # ─────────────────────────────────────────────────────────────
    # Hash file operations
    # ─────────────────────────────────────────────────────────────
    
    def get_hash(self, path: str) -> Optional[HashFile]:
        """Get hash file by path."""
        with self._lock:
            return self._hashes.get(path)
    
    def get_all_hashes(self) -> List[HashFile]:
        """Get all hash files as a list."""
        with self._lock:
            return list(self._hashes.values())
    
    def upsert_hash(self, path: str, **updates) -> HashFile:
        """Create or update a hash file record."""
        with self._lock:
            if path in self._hashes:
                record = self._hashes[path]
            else:
                record = create_hash_file(path)
            
            for field, value in updates.items():
                if value is not None:
                    record[field] = value
            
            # Universalizing: inherit cracked status from network if matched
            bssid = record.get('network_bssid')
            if bssid and not record.get('cracked'):
                # 1. Check current network suspects
                net = self._networks.get(bssid.upper())
                if net and (net.get('status', {}).get('cracked') or net.get('manual_cracked')):
                    record['cracked'] = True
                    record['cracked_password'] = net.get('cracked_password')
                    record['cracked_at'] = datetime.now().isoformat()
                
                # 2. Check universal password registry
                elif bssid.upper() in self._passwords:
                    pw_info = self._passwords[bssid.upper()]
                    record['cracked'] = True
                    record['cracked_password'] = pw_info['password']
                    record['cracked_at'] = pw_info['timestamp']

            self._hashes[path] = record
            self._dirty_hashes = True
            return record
    
    def mark_hash_cracked(self, path: str, password: str,
                           hex_repr: str = None, salt: str = None,
                           output_file: str = None) -> None:
        """Mark a hash file as cracked."""
        with self._lock:
            if path not in self._hashes:
                return
            record = self._hashes[path]
            record['cracked'] = True
            record['cracked_password'] = password
            record['cracked_hex'] = hex_repr
            record['cracked_salt'] = salt
            record['cracked_output'] = output_file
            record['cracked_at'] = datetime.now().isoformat()
            self._dirty_hashes = True
            
            # Also mark associated network
            bssid = record.get('network_bssid')
            if bssid:
                self.mark_network_cracked(bssid, password, hex_repr, salt, path)
    
    def remove_hash(self, path: str) -> None:
        """Remove a hash file record."""
        with self._lock:
            if path in self._hashes:
                del self._hashes[path]
                self._dirty_hashes = True
                # Remove from network hash_ids
                for net in self._networks.values():
                    if path in net.get('hash_ids', []):
                        net['hash_ids'] = [h for h in net['hash_ids'] if h != path]
                        self._ensure_status(net)['has_hash'] = len(net['hash_ids']) > 0
                        self._dirty_networks = True
    
    def clear_hashes(self) -> None:
        """Clear all hash data."""
        with self._lock:
            self._hashes.clear()
            self._dirty_hashes = True
    
    def add_cracking_attempt(self, path: str, wordlist: str, rule: str = None) -> bool:
        """
        Record a failed cracking attempt for a hash.
        Returns True if added, False if duplicate or not found.
        """
        with self._lock:
            if path not in self._hashes:
                return False
            
            record = self._hashes[path]
            attempts = record.get('cracking_attempts', [])
            
            # Check for duplicate (same wordlist+rule combo)
            attempt = {'wordlist': wordlist, 'rule': rule or ''}
            for existing in attempts:
                if existing.get('wordlist') == wordlist and existing.get('rule', '') == (rule or ''):
                    return False
            
            attempts.append(attempt)
            record['cracking_attempts'] = attempts
            self._dirty_hashes = True
            return True
    
    def has_attempted(self, path: str, wordlist: str, rule: str = None) -> bool:
        """Check if a wordlist+rule combo was already attempted."""
        with self._lock:
            if path not in self._hashes:
                return False
            
            attempts = self._hashes[path].get('cracking_attempts', [])
            for attempt in attempts:
                if attempt.get('wordlist') == wordlist and attempt.get('rule', '') == (rule or ''):
                    return True
            return False
    
    # ─────────────────────────────────────────────────────────────
    # Settings & Stats
    # ─────────────────────────────────────────────────────────────
    
    @property
    def settings(self) -> Settings:
        """Get current settings."""
        return self._settings
    
    def update_settings(self, **updates) -> Settings:
        """Update settings."""
        with self._lock:
            for key, value in updates.items():
                if key in self._settings:
                    self._settings[key] = value
            self._dirty_settings = True
            return self._settings
    
    @property
    def stats(self) -> Stats:
        """Get current stats (not persisted)."""
        return self._stats
    
    def update_stats(self, **updates) -> Stats:
        """Update runtime stats."""
        for key, value in updates.items():
            if key in self._stats:
                self._stats[key] = value
        return self._stats
    
    def increment_stat(self, key: str, amount: int = 1) -> None:
        """Increment a numeric stat."""
        if key in self._stats and isinstance(self._stats[key], int):
            self._stats[key] += amount
    
    def reset_stats(self) -> None:
        """Reset runtime stats to initial state."""
        self._stats = create_stats()
    
    # ─────────────────────────────────────────────────────────────
    # Bulk operations
    # ─────────────────────────────────────────────────────────────
    
    def reset_cache(self) -> None:
        """Clear all cached data (networks, devices, hashes)."""
        with self._lock:
            self._networks.clear()
            self._devices.clear()
            self._hashes.clear()
            self._dirty_networks = True
            self._dirty_devices = True
            self._dirty_hashes = True
    
    @contextmanager
    def batch_update(self):
        """
        Context manager for batching multiple updates.
        Defers disk writes until the batch completes.
        """
        with self._lock:
            try:
                yield self
            finally:
                self.save_all()


# Singleton storage instance
_storage: Optional[Storage] = None


def get_storage() -> Storage:
    """Get the global storage instance."""
    global _storage
    if _storage is None:
        _storage = Storage()
    return _storage


def reset_storage() -> None:
    """Reset the global storage instance (for testing)."""
    global _storage
    if _storage:
        _storage.save_all()
    _storage = None
