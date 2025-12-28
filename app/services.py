"""
Business logic services.

Contains the core operations: scanning, capturing, hash management.
Separates business logic from HTTP routes and storage.
"""

from __future__ import annotations
import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

from .storage import get_storage
from .state import get_state
from .logging import log, get_logger
from .models import Network, HashFile, CaptureGroup

# Import cracking module
import cracking


class HashService:
    """Manages hash file discovery and cracking operations."""
    
    HASHES_DIR = 'hashes'
    WORDLISTS_DIR = 'wordlists'
    
    @staticmethod
    def extract_essid_from_filename(filename: str) -> str:
        """
        Extract ESSID from capture/hash filename.
        
        Expected formats:
        - capture_ESSID_YYYYMMDD_HHMMSS-01.cap
        - ESSID_YYYYMMDD_HHMMSS.hc22000
        """
        essid = 'Unknown'
        try:
            base = filename
            # Remove known suffixes
            for suffix in ('.cap', '.hc22000', '-01'):
                base = base.replace(suffix, '')
            
            parts = base.split('_')
            
            # Check if starts with 'capture'
            if parts and parts[0].lower() == 'capture':
                parts = parts[1:]  # Remove 'capture' prefix
            
            # Find where the date/time portion starts
            # Look for YYYYMMDD pattern (8 digits)
            date_idx = -1
            for i, part in enumerate(parts):
                if len(part) == 8 and part.isdigit():
                    date_idx = i
                    break
            
            if date_idx > 0:
                # ESSID is everything before the date
                essid = '_'.join(parts[:date_idx]) or 'Unknown'
            elif len(parts) >= 1:
                # Fallback: use first part
                essid = parts[0] or 'Unknown'
                
        except Exception:
            pass
        return essid
    
    @classmethod
    def sync_inventory(cls) -> List[HashFile]:
        """
        Scan hashes/ directory and sync with storage.
        Returns updated list of hash records.
        """
        storage = get_storage()
        
        os.makedirs(cls.HASHES_DIR, exist_ok=True)
        os.makedirs(cls.WORDLISTS_DIR, exist_ok=True)
        
        cwd = os.path.abspath(os.getcwd())
        active_paths = set()
        
        for filename in sorted(os.listdir(cls.HASHES_DIR)):
            if not filename.endswith('.hc22000'):
                continue
            
            full_path = os.path.join(cls.HASHES_DIR, filename)
            if not os.path.isfile(full_path):
                continue
            
            rel_path = os.path.relpath(full_path, cwd)
            active_paths.add(rel_path)
            
            essid = cls.extract_essid_from_filename(filename)
            candidate_bssid = storage.find_bssid_by_essid(essid)
            size_bytes = os.path.getsize(full_path)
            timestamp = datetime.fromtimestamp(os.path.getmtime(full_path)).isoformat()
            
            # Preserve cracked status if already known
            existing = storage.get_hash(rel_path)
            
            storage.upsert_hash(
                rel_path,
                name=filename,
                essid=essid,
                network_bssid=candidate_bssid,
                size=size_bytes,
                size_human=cracking.human_readable_size(size_bytes),
                timestamp=timestamp,
            )
            
            if candidate_bssid:
                storage.link_hash_to_network(rel_path, candidate_bssid)
        
        # Remove stale entries
        for hash_record in storage.get_all_hashes():
            if hash_record['path'] not in active_paths:
                storage.remove_hash(hash_record['path'])
        
        storage.flush()
        return storage.get_all_hashes()
    
    @classmethod
    def get_wordlists(cls) -> List[Dict[str, Any]]:
        """Get list of available wordlist files."""
        os.makedirs(cls.WORDLISTS_DIR, exist_ok=True)
        wordlists = []
        
        # Valid wordlist extensions
        valid_extensions = ('.txt', '.lst', '.wordlist', '.dict', '.dic')
        # Files to ignore
        ignore_files = {'.gitkeep', '.gitignore', '.DS_Store', 'README.md', 'README.txt'}
        
        for filename in sorted(os.listdir(cls.WORDLISTS_DIR)):
            # Skip hidden files, ignore files, and directories
            if filename.startswith('.') or filename in ignore_files:
                continue
            
            full_path = os.path.join(cls.WORDLISTS_DIR, filename)
            if not os.path.isfile(full_path):
                continue
            
            # Check extension - allow common wordlist formats or no extension (for large wordlists)
            has_valid_ext = any(filename.lower().endswith(ext) for ext in valid_extensions)
            has_no_ext = '.' not in filename
            
            if not has_valid_ext and not has_no_ext:
                continue
            
            size = os.path.getsize(full_path)
            wordlists.append({
                'name': filename,
                'path': os.path.relpath(full_path, os.getcwd()),
                'size': size,
                'size_human': cracking.human_readable_size(size),
            })
        
        return wordlists
    
    @staticmethod
    def parse_cracked_line(line: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Parse hashcat outfile line into (password, hex, salt)."""
        if not line:
            return None, None, None
        parts = line.strip().split(':')
        plain = parts[0] if parts else None
        hex_repr = parts[1] if len(parts) > 1 else None
        salt = parts[2] if len(parts) > 2 else None
        return plain, hex_repr, salt
    
    @classmethod
    def mark_cracked(cls, hash_path: str, output_file: str) -> None:
        """Update storage when a hash is cracked."""
        storage = get_storage()
        
        rel_path = os.path.relpath(hash_path, os.getcwd()) if os.path.isabs(hash_path) else hash_path
        
        plain = hex_repr = salt = None
        if output_file and os.path.exists(output_file):
            try:
                with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                    first_line = f.readline().strip()
                    plain, hex_repr, salt = cls.parse_cracked_line(first_line)
            except Exception as e:
                log(f'Error reading cracked output {output_file}: {e}', 'error')
        
        storage.mark_hash_cracked(rel_path, plain, hex_repr, salt, output_file)
        storage.flush()
    
    @staticmethod
    def resolve_path(candidate: str, base_dir: str) -> str:
        """Resolve and validate a path stays within base directory."""
        base_abs = os.path.abspath(base_dir)
        target_abs = os.path.abspath(os.path.join(os.getcwd(), candidate))
        if not target_abs.startswith(base_abs):
            raise ValueError(f'Path {candidate} is outside {base_dir}')
        return target_abs


class CaptureService:
    """Manages capture file discovery and organization."""
    
    CAPTURES_DIR = 'captures'
    HASHES_DIR = 'hashes'
    
    @classmethod
    def get_captures(cls) -> List[CaptureGroup]:
        """Get captures grouped by network ESSID."""
        os.makedirs(cls.CAPTURES_DIR, exist_ok=True)
        os.makedirs(cls.HASHES_DIR, exist_ok=True)
        
        # Sync hash inventory first
        HashService.sync_inventory()
        
        cap_files = [f for f in os.listdir(cls.CAPTURES_DIR) if f.endswith('.cap')]
        network_captures: Dict[str, List] = {}
        
        for cap_file in cap_files:
            cap_path = os.path.join(cls.CAPTURES_DIR, cap_file)
            essid = HashService.extract_essid_from_filename(cap_file)
            
            # Find corresponding hash
            hash_file = None
            base_name = cap_file.replace('.cap', '').replace('capture_', '').replace('-01', '')
            possible_hash = f"{base_name}.hc22000"
            hash_path = os.path.join(cls.HASHES_DIR, possible_hash)
            
            if os.path.exists(hash_path):
                hash_file = hash_path
            else:
                for hf in os.listdir(cls.HASHES_DIR):
                    if hf.endswith('.hc22000') and essid in hf:
                        hash_file = os.path.join(cls.HASHES_DIR, hf)
                        break
            
            timestamp = os.path.getmtime(cap_path)
            
            if essid not in network_captures:
                network_captures[essid] = []
            
            network_captures[essid].append({
                'file': cap_path,
                'hash': hash_file,
                'timestamp': timestamp,
                'timestamp_iso': datetime.fromtimestamp(timestamp).isoformat(),
            })
        
        # Build grouped results
        captures = []
        for essid, caps in network_captures.items():
            caps.sort(key=lambda x: x['timestamp'], reverse=True)
            latest = caps[0]
            all_hashes = list(set(c['hash'] for c in caps if c['hash']))
            
            captures.append(CaptureGroup(
                essid=essid,
                file=latest['file'],
                hash=all_hashes[0] if all_hashes else None,
                timestamp=latest['timestamp_iso'],
                capture_count=len(caps),
                all_files=[c['file'] for c in caps],
                all_hashes=all_hashes,
            ))
        
        captures.sort(key=lambda x: x['timestamp'], reverse=True)
        return captures


class NetworkService:
    """High-level network operations."""
    
    @staticmethod
    def get_networks_response() -> Dict[str, Any]:
        """Build the /api/networks response."""
        HashService.sync_inventory()
        storage = get_storage()
        
        return {
            'networks': storage.get_all_networks(),
            'devices': storage.get_all_devices(),
            'hashes': storage.get_all_hashes(),
            'count': len(storage.get_all_networks()),
        }
    
    @staticmethod
    def is_cracked(bssid: str) -> bool:
        """Check if a network has been cracked."""
        network = get_storage().get_network(bssid)
        if not network:
            return False
        return network.get('status', {}).get('cracked', False)
