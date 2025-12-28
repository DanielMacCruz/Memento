"""
Rolling Cracker Service.

Continuously cracks hashes using a smart wordlist+rule rotation strategy.
Can run alongside Vigilance mode for passive capture + automatic cracking.

Features:
- ESSID-based wordlist generation (normalize, split, combine words)
- Tracks used wordlist+rule pairs to avoid repetition
- Iterates through available wordlists and rules
- Auto-queues newly captured hashes
"""

from __future__ import annotations
import os
import re
import tempfile
import subprocess
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple

from .storage import get_storage
from .logging import log


def normalize_essid(essid: str) -> List[str]:
    """
    Normalize ESSID and extract words for wordlist generation.
    
    Removes: 2g, 5g, 2.4, 5ghz, 2.4ghz, _2g, _5g, etc.
    Splits on: _, -, space
    Returns: List of normalized words
    """
    if not essid:
        return []
    
    # Work on a copy
    clean = essid.strip()
    
    # Remove common frequency suffixes (case insensitive)
    patterns_to_remove = [
        r'[_\-\s]?5ghz$', r'[_\-\s]?2\.4ghz$', r'[_\-\s]?2\.4g$',
        r'[_\-\s]?5g$', r'[_\-\s]?2g$', r'[_\-\s]?5$', r'[_\-\s]?2\.4$',
        r'^5ghz[_\-\s]?', r'^2\.4ghz[_\-\s]?', r'^2g[_\-\s]?', r'^5g[_\-\s]?',
    ]
    
    for pattern in patterns_to_remove:
        clean = re.sub(pattern, '', clean, flags=re.IGNORECASE)
    
    # Also remove standalone frequency markers
    clean = re.sub(r'\b(2g|5g|2\.4|5ghz|2\.4ghz)\b', '', clean, flags=re.IGNORECASE)
    
    # Split on separators
    parts = re.split(r'[_\-\s]+', clean)
    parts = [p.strip() for p in parts if p.strip()]
    
    return parts


def generate_essid_wordlist(essid: str, output_dir: str = '/tmp') -> Optional[str]:
    """
    Generate a small wordlist based on ESSID words.
    
    Creates combinations:
    - Each word as-is
    - Lowercase + Capitalized + UPPER
    - Concatenations: word1word2, Word1Word2
    - With separators: word1_word2, word1-word2
    - With common suffixes: word123, word1234, word2024
    
    Returns: Path to generated wordlist file, or None if no words extracted
    """
    words = normalize_essid(essid)
    
    if not words:
        return None
    
    candidates: Set[str] = set()
    
    # Add each word with variations
    for word in words:
        if len(word) < 2:
            continue
        candidates.add(word)
        candidates.add(word.lower())
        candidates.add(word.upper())
        candidates.add(word.capitalize())
        
        # With common suffixes
        for suffix in ['123', '1234', '12345', '321', '2024', '2025', '!', '@', '#']:
            candidates.add(f"{word.lower()}{suffix}")
            candidates.add(f"{word.capitalize()}{suffix}")
    
    # Combine pairs of words
    if len(words) >= 2:
        for i, w1 in enumerate(words):
            for w2 in words[i+1:]:
                # Concatenations
                candidates.add(f"{w1.lower()}{w2.lower()}")
                candidates.add(f"{w2.lower()}{w1.lower()}")
                candidates.add(f"{w1.capitalize()}{w2.capitalize()}")
                candidates.add(f"{w2.capitalize()}{w1.capitalize()}")
                
                # With separators
                for sep in ['_', '-', '']:
                    candidates.add(f"{w1.lower()}{sep}{w2.lower()}")
                    candidates.add(f"{w2.lower()}{sep}{w1.lower()}")
                
                # With suffixes
                for suffix in ['123', '1234', '2024']:
                    candidates.add(f"{w1.lower()}{w2.lower()}{suffix}")
                    candidates.add(f"{w1.capitalize()}{w2.capitalize()}{suffix}")
    
    # Filter by WPA length (8-63)
    valid_candidates = [c for c in candidates if 8 <= len(c) <= 63]
    
    if not valid_candidates:
        return None
    
    # Write to temp file
    safe_essid = re.sub(r'[^a-zA-Z0-9]', '_', essid)[:20]
    timestamp = datetime.now().strftime("%H%M%S")
    output_path = os.path.join(output_dir, f"essid_{safe_essid}_{timestamp}.txt")
    
    with open(output_path, 'w') as f:
        for word in sorted(valid_candidates):
            f.write(f"{word}\n")
    
    return output_path


def get_next_crack_job(
    hash_path: str,
    wordlists: List[Dict],
    rules: List[Dict],
    used_attempts: List[Dict]
) -> Optional[Tuple[str, str, str]]:
    """
    Find the next wordlist to try.
    
    NOTE: Rules are currently disabled - using AI-generated passwords only.
    
    Args:
        hash_path: Path to hash file
        wordlists: Available wordlists [{'path': ..., 'name': ...}]
        rules: Available rules (currently ignored)
        used_attempts: Previously tried combinations [{'wordlist': ..., 'rule': ...}]
    
    Returns:
        Tuple of (wordlist_path, rule_path, description) or None if exhausted
    """
    # Build set of used wordlists (no rules = empty string)
    used_wordlists: Set[str] = set()
    for attempt in used_attempts:
        wl = attempt.get('wordlist', '')
        rl = attempt.get('rule', '')
        # Only track no-rule attempts since we're not using rules
        if not rl:
            used_wordlists.add(wl)
    
    # Try each wordlist without rules (AI passwords don't need mutation)
    for wordlist in wordlists:
        wl_path = wordlist.get('path', '')
        wl_name = wordlist.get('name', os.path.basename(wl_path))
        
        # Virtual wordlists use the path as the identifier
        is_virtual = wl_path.startswith('__MASK_')
        identifier = wl_path if is_virtual else wl_name
        
        if identifier not in used_wordlists:
            if is_virtual:
                # Virtual wordlist descriptions
                desc_map = {
                    '__MASK_8DIGIT__': '8-digit numbers (mask attack)',
                }
                desc = desc_map.get(wl_path, wl_path)
                return (wl_path, '', desc)
            else:
                return (wl_path, '', f"{wl_name} (no rules)")
    
    return None  # All wordlists exhausted


class RollingCracker:
    """
    Service that continuously cracks hashes in the background.
    """
    
    def __init__(self):
        self.active = False
        self.current_hash = None
        self.current_job = None
    
    def get_uncracked_hashes(self) -> List[Dict]:
        """Get all uncracked hashes sorted by priority."""
        storage = get_storage()
        hashes = storage.get_all_hashes()
        
        # Filter to uncracked only
        uncracked = [h for h in hashes if not h.get('cracked')]
        
        # Sort by fewer attempts first (try fresh ones)
        uncracked.sort(key=lambda h: len(h.get('cracking_attempts', [])))
        
        return uncracked
    
    def process_next(
        self,
        wordlists: List[Dict],
        rules: List[Dict]
    ) -> Optional[Dict]:
        """
        Process the next available hash.
        
        Returns:
            Job info dict if starting a job, None if nothing to do
        """
        storage = get_storage()
        uncracked = self.get_uncracked_hashes()
        
        if not uncracked:
            return None
        
        # Find a hash with available combinations
        for hash_record in uncracked:
            attempts = hash_record.get('cracking_attempts', [])
            
            # Find next job for this hash
            job = get_next_crack_job(
                hash_record.get('path', ''),
                wordlists,
                rules,
                attempts
            )
            
            if job:
                return {
                    'hash': hash_record,
                    'wordlist_path': job[0],
                    'rule_path': job[1],
                    'description': job[2],
                }
        
        return None  # All hashes exhausted

