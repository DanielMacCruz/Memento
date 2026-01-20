"""
Data models and type definitions.

Using TypedDict for structured data with clear schemas.
These define the shape of all data flowing through the system.
"""

from __future__ import annotations
from typing import TypedDict, Optional, List
from datetime import datetime


class NetworkStatus(TypedDict, total=False):
    """Status flags for a network."""
    has_hash: bool
    cracked: bool


class Network(TypedDict, total=False):
    """
    A WiFi network record.
    
    Primary key: bssid (uppercase MAC address)
    """
    bssid: str
    essid: str
    channel: str
    power: str
    encryption: str
    has_clients: bool
    clients: int
    stations: List[str]      # MACs of connected devices
    device_ids: List[str]    # Alias for stations
    cached: bool             # True if not seen in latest scan
    hash_ids: List[str]      # Paths to associated hash files
    status: NetworkStatus
    manual_cracked: bool     # Manual "solved" override
    cracked_password: Optional[str]
    cracked_hex: Optional[str]
    cracked_salt: Optional[str]
    cracked_hash_path: Optional[str]
    first_seen: str          # ISO timestamp
    last_seen: str           # ISO timestamp


class Device(TypedDict, total=False):
    """
    A client device (station) seen on networks.
    
    Primary key: mac (uppercase MAC address)
    """
    mac: str
    networks: List[str]      # BSSIDs this device has connected to
    first_seen: str
    last_seen: str


class HashFile(TypedDict, total=False):
    """
    A captured hash file (.hc22000).
    
    Primary key: path (relative to working directory)
    """
    path: str
    name: str
    essid: str
    network_bssid: Optional[str]
    hash_mode: str
    size: int
    size_human: str
    timestamp: str
    cracked: bool
    cracked_password: Optional[str]
    cracked_hex: Optional[str]
    cracked_salt: Optional[str]
    cracked_output: Optional[str]
    cracked_at: Optional[str]
    cracking_attempts: List[dict]  # [{wordlist: str, rule: str}] - max 32


class CaptureFile(TypedDict, total=False):
    """A .cap capture file with metadata."""
    file: str
    hash: Optional[str]
    timestamp: float
    timestamp_iso: str


class CaptureGroup(TypedDict, total=False):
    """Captures grouped by network ESSID."""
    essid: str
    file: str
    hash: Optional[str]
    timestamp: str
    capture_count: int
    all_files: List[str]
    all_hashes: List[str]


class CrackTask(TypedDict):
    """A single cracking job."""
    hash: str
    hash_rel: str
    wordlist: str
    hash_name: str
    wordlist_name: str


class Stats(TypedDict, total=False):
    """Runtime statistics."""
    networks_scanned: int
    networks_attacked: int
    handshakes_captured: int
    hashes_cracked: int
    scan_start_time: Optional[str]
    current_operation: str


class Settings(TypedDict, total=False):
    """User-configurable settings."""
    band: str
    interface: Optional[str]
    # Phantom Gate (Evil Portal) settings
    portal_in_adapter: Optional[str]    # Internet source (eth0, wwan0, etc)
    portal_out_adapter: Optional[str]   # Evil Twin adapter (wlan0)
    portal_capture_traffic: bool        # Save victim traffic to captures/
    portal_forced_mode: bool            # Force phishing on ALL requests


# Factory functions for creating properly initialized records

def create_network(bssid: str, **kwargs) -> Network:
    """Create a new Network record with defaults."""
    now = datetime.now().isoformat()
    return Network(
        bssid=bssid.upper(),
        essid=kwargs.get('essid', 'Unknown'),
        channel=kwargs.get('channel', ''),
        power=kwargs.get('power', '-100'),
        encryption=kwargs.get('encryption', 'WPA2-PSK'),
        has_clients=kwargs.get('has_clients', False),
        clients=kwargs.get('clients', 0),
        stations=kwargs.get('stations', []),
        device_ids=kwargs.get('device_ids', []),
        cached=kwargs.get('cached', True),
        hash_ids=kwargs.get('hash_ids', []),
        status=kwargs.get('status', NetworkStatus(has_hash=False, cracked=False)),
        manual_cracked=kwargs.get('manual_cracked', False),
        cracked_password=kwargs.get('cracked_password'),
        cracked_hex=kwargs.get('cracked_hex'),
        cracked_salt=kwargs.get('cracked_salt'),
        cracked_hash_path=kwargs.get('cracked_hash_path'),
        first_seen=kwargs.get('first_seen', now),
        last_seen=kwargs.get('last_seen', now),
    )


def create_device(mac: str, **kwargs) -> Device:
    """Create a new Device record with defaults."""
    now = datetime.now().isoformat()
    return Device(
        mac=mac.upper(),
        networks=kwargs.get('networks', []),
        first_seen=kwargs.get('first_seen', now),
        last_seen=kwargs.get('last_seen', now),
    )


def create_hash_file(path: str, **kwargs) -> HashFile:
    """Create a new HashFile record with defaults."""
    return HashFile(
        path=path,
        name=kwargs.get('name', ''),
        essid=kwargs.get('essid', 'Unknown'),
        network_bssid=kwargs.get('network_bssid'),
        hash_mode=kwargs.get('hash_mode', '22000'),
        size=kwargs.get('size', 0),
        size_human=kwargs.get('size_human', '0 B'),
        timestamp=kwargs.get('timestamp', ''),
        cracked=kwargs.get('cracked', False),
        cracked_password=kwargs.get('cracked_password'),
        cracked_hex=kwargs.get('cracked_hex'),
        cracked_salt=kwargs.get('cracked_salt'),
        cracked_output=kwargs.get('cracked_output'),
        cracked_at=kwargs.get('cracked_at'),
        cracking_attempts=kwargs.get('cracking_attempts', []),
    )


def create_stats() -> Stats:
    """Create initial statistics object."""
    return Stats(
        networks_scanned=0,
        networks_attacked=0,
        handshakes_captured=0,
        hashes_cracked=0,
        scan_start_time=None,
        current_operation='Idle',
    )


def create_settings() -> Settings:
    """Create default settings object."""
    return Settings(
        band='abg',
        interface=None,
        portal_in_adapter=None,
        portal_out_adapter=None,
        portal_capture_traffic=True,
        portal_forced_mode=False,
    )

