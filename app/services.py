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
from . import cracking


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
        - ESSID_vigilance.hc22000
        """
        essid = 'Unknown'
        try:
            base = filename
            # Remove known file extensions
            for suffix in ('.cap', '.hc22000', '-01'):
                base = base.replace(suffix, '')
            
            parts = base.split('_')
            
            # Check if starts with 'capture'
            if parts and parts[0].lower() == 'capture':
                parts = parts[1:]  # Remove 'capture' prefix
            
            # Find where the metadata/date portion starts
            # Look for YYYYMMDD pattern (8 digits) OR 'vigilance' keyword
            meta_idx = -1
            for i, part in enumerate(parts):
                if (len(part) == 8 and part.isdigit()) or part.lower() == 'vigilance':
                    meta_idx = i
                    break
            
            if meta_idx > 0:
                # ESSID is everything before the metadata
                essid = '_'.join(parts[:meta_idx]) or 'Unknown'
            elif meta_idx == 0 and len(parts) > 1:
                # If metadata is at start (unlikely for capture), use rest or fallback
                essid = parts[1]
            elif len(parts) >= 1:
                # Fallback: if no metadata found, the whole thing might be the ESSID
                # (excluding the 'capture' if it was removed)
                # But if it ends with 'vigilance' (exact match), remove it
                if parts[-1].lower() == 'vigilance':
                    essid = '_'.join(parts[:-1]) or 'Unknown'
                else:
                    essid = '_'.join(parts) or 'Unknown'
                
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
            
            # IMPROVEMENT: Try to get BSSID from hash content first (more reliable than filename)
            bssid_from_content = None
            try:
                with open(full_path, 'r') as f:
                    first_line = f.readline().strip()
                    if first_line:
                        parts = first_line.split('*')
                        if len(parts) >= 4:
                            # hc22000 AP MAC is at index 3
                            bssid_from_content = parts[3].upper()
                            # Insert colons if missing
                            if ':' not in bssid_from_content and len(bssid_from_content) == 12:
                                bssid_from_content = ':'.join(bssid_from_content[i:i+2] for i in range(0, 12, 2))
            except:
                pass

            candidate_bssid = bssid_from_content or storage.find_bssid_by_essid(essid)
            
            size_bytes = os.path.getsize(full_path)
            timestamp = datetime.fromtimestamp(os.path.getmtime(full_path)).isoformat()
            
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
    
    @classmethod
    def consolidate_hashes(cls) -> Dict[str, int]:
        """
        Deduplicate and group all hashes.
        - Merges multiple files for the same ESSID into one.
        - Removes duplicate hash lines within files.
        - Returns stats on what was cleaned up.
        """
        os.makedirs(cls.HASHES_DIR, exist_ok=True)
        all_hashes: Dict[str, Set[str]] = {} # essid -> set of lines
        cleaned = {'files_merged': 0, 'lines_removed': 0}
        
        initial_file_count = len([f for f in os.listdir(cls.HASHES_DIR) if f.endswith('.hc22000')])
        
        # 1. Collect all unique lines across all files
        for filename in os.listdir(cls.HASHES_DIR):
            if not filename.endswith('.hc22000'):
                continue
            
            full_path = os.path.join(cls.HASHES_DIR, filename)
            essid = cls.extract_essid_from_filename(filename)
            
            if essid not in all_hashes:
                all_hashes[essid] = set()
            
            try:
                with open(full_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            if line in all_hashes[essid]:
                                cleaned['lines_removed'] += 1
                            else:
                                all_hashes[essid].add(line)
                
                # After reading, remove the old file (we will rewrite consolidated ones)
                os.remove(full_path)
            except Exception as e:
                log(f"Consolidation read error for {filename}: {e}", "error")

        # 2. Write back consolidated files
        for essid, lines in all_hashes.items():
            if not lines:
                continue
            
            safe_essid = re.sub(r'[^a-zA-Z0-9_-]', '_', essid)
            # Use a clean naming convention: ESSID_consolidated.hc22000
            new_filename = f"{safe_essid}_consolidated.hc22000"
            new_path = os.path.join(cls.HASHES_DIR, new_filename)
            
            try:
                with open(new_path, 'w') as f:
                    for line in sorted(list(lines)): # Sort for stability
                        f.write(line + '\n')
            except Exception as e:
                log(f"Consolidation write error for {essid}: {e}", "error")

        final_file_count = len([f for f in os.listdir(cls.HASHES_DIR) if f.endswith('.hc22000')])
        cleaned['files_merged'] = initial_file_count - final_file_count
        
        # Trigger inventory sync to update storage with new file names
        cls.sync_inventory()
        return cleaned

    @classmethod
    def get_rules(cls) -> List[Dict[str, Any]]:
        """Get list of available hashcat rule files."""
        rules_dir = 'rules'
        os.makedirs(rules_dir, exist_ok=True)
        rules = []
        
        for filename in sorted(os.listdir(rules_dir)):
            if not filename.endswith('.rule'):
                continue
            
            full_path = os.path.join(rules_dir, filename)
            if not os.path.isfile(full_path):
                continue
            
            # Count non-comment, non-empty lines (approximate rule count)
            rule_count = 0
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            rule_count += 1
            except Exception:
                pass
            
            rules.append({
                'name': filename,
                'path': os.path.relpath(full_path, os.getcwd()),
                'rule_count': rule_count,
                'multiplier': f'{rule_count}x' if rule_count else '',
            })
        
        return rules
    
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
        state = get_state()
        storage = get_storage()
        
        session_start = state.session_start_time.isoformat()
        networks = storage.get_all_networks()
        
        # Enrich with session info
        for net in networks:
            net['discovered_this_session'] = net.get('last_seen', '') >= session_start
        
        return {
            'networks': networks,
            'devices': storage.get_all_devices(),
            'hashes': storage.get_all_hashes(),
            'count': len(networks),
        }
    
    @staticmethod
    def is_cracked(bssid: str) -> bool:
        """Check if a network has been cracked."""
        network = get_storage().get_network(bssid)
        if not network:
            return False
        return network.get('status', {}).get('cracked', False)
