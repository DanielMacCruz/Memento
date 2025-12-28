"""
Smart wordlist generator using crunch + Brazilian patterns.

This module generates targeted wordlists for WiFi password cracking using:
- SSID analysis and pattern extraction
- Brazilian cultural patterns (names, teams, locations, slang)
- Crunch for combinatorial generation
- Three modes: Quick (1-5M), Balanced (5-15M), Aggressive (15-50M)
"""

from __future__ import annotations
import os
import re
import subprocess
import tempfile
from datetime import datetime
from typing import List, Set, Dict, Optional, Tuple
from dataclasses import dataclass

from .brazilian_patterns import BrazilianPatterns


@dataclass
class WordlistResult:
    """Result of wordlist generation."""
    success: bool
    file_path: Optional[str] = None
    word_count: int = 0
    recommended_rule: Optional[str] = None
    error: Optional[str] = None


class SSIDAnalyzer:
    """Analyzes SSID to extract patterns and keywords."""
    
    @staticmethod
    def extract_patterns(essid: str) -> Dict[str, List[str]]:
        """
        Extract patterns from SSID.
        
        Returns dict with:
            - base: core SSID variations
            - names: detected names
            - numbers: detected numbers
            - separators: detected separators
            - parts: SSID split by separators
        """
        if not essid:
            return {'base': [], 'names': [], 'numbers': [], 'separators': [], 'parts': []}
        
        # Strip accents and normalize
        clean_essid = BrazilianPatterns.strip_accents(essid)
        
        # Detect separators
        separators = []
        for sep in ['_', '-', '.', '@', '#', ' ']:
            if sep in essid:
                separators.append(sep)
        
        # Split by common separators
        parts = re.split(r'[_\-\.@#\s]+', clean_essid)
        parts = [p for p in parts if p]  # Remove empty
        
        # Extract numbers
        numbers = re.findall(r'\d+', clean_essid)
        
        # Detect names (check against Brazilian name database)
        all_names = [n.lower() for n in BrazilianPatterns.get_all_names()]
        detected_names = []
        for part in parts:
            part_lower = part.lower()
            if part_lower in all_names:
                detected_names.append(part_lower)
        
        # Base variations
        base_variations = [
            essid,
            clean_essid,
            essid.lower(),
            essid.upper(),
            clean_essid.lower(),
            clean_essid.upper(),
        ]
        
        # Add parts
        base_variations.extend(parts)
        
        # Remove duplicates
        base_variations = list(set(base_variations))
        
        return {
            'base': base_variations,
            'names': detected_names,
            'numbers': numbers,
            'separators': separators,
            'parts': parts,
        }


class WordlistGenerator:
    """Generate targeted wordlists using crunch + Brazilian patterns."""
    
    # Mode configurations
    MODES = {
        'quick': {
            'target_size': 3_000_000,  # 3M base words
            'recommended_rule': 'best66.rule',
            'rule_multiplier': 66,
            'description': 'Quick (1-5M words, best66 rule)',
        },
        'balanced': {
            'target_size': 10_000_000,  # 10M base words
            'recommended_rule': 'dive.rule',
            'rule_multiplier': 200,
            'description': 'Balanced (5-15M words, dive rule)',
        },
        'aggressive': {
            'target_size': 30_000_000,  # 30M base words
            'recommended_rule': 'rockyou-30000.rule',
            'rule_multiplier': 30000,
            'description': 'Aggressive (15-50M words, custom rules)',
        },
    }
    
    def __init__(self, output_dir: str = 'wordlists'):
        """Initialize generator."""
        self.output_dir = os.path.abspath(output_dir)
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate(
        self,
        essid: Optional[str] = None,
        keywords: Optional[List[str]] = None,
        mode: str = 'balanced',
        target_size: Optional[int] = None,
        min_length: int = 8,
        max_length: int = 63,
    ) -> WordlistResult:
        """
        Generate a targeted wordlist.
        
        Args:
            essid: Target network SSID
            keywords: Additional keywords
            mode: Generation mode (quick/balanced/aggressive)
            target_size: Override target size
            min_length: Minimum password length
            max_length: Maximum password length
        
        Returns:
            WordlistResult with file path and metadata
        """
        try:
            # Validate mode
            if mode not in self.MODES:
                return WordlistResult(
                    success=False,
                    error=f"Invalid mode: {mode}. Use quick/balanced/aggressive"
                )
            
            mode_config = self.MODES[mode]
            target = target_size or mode_config['target_size']
            
            # Build base wordlist
            base_words = self._build_base_wordlist(essid, keywords, mode)
            
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if essid:
                safe_essid = re.sub(r'[^a-zA-Z0-9_-]', '_', essid)
                filename = f"wordlist_{safe_essid}_{mode}_{timestamp}.txt"
            else:
                filename = f"wordlist_{mode}_{timestamp}.txt"
            
            output_path = os.path.join(self.output_dir, filename)
            
            # Write base words to temp file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
                tmp_path = tmp.name
                for word in base_words:
                    tmp.write(f"{word}\n")
            
            # Deduplicate and filter by length
            final_words = self._deduplicate_and_filter(
                tmp_path,
                min_length,
                max_length,
                target
            )
            
            # Write final wordlist
            with open(output_path, 'w') as f:
                for word in final_words:
                    f.write(f"{word}\n")
            
            # Clean up temp file
            os.unlink(tmp_path)
            
            word_count = len(final_words)
            
            return WordlistResult(
                success=True,
                file_path=output_path,
                word_count=word_count,
                recommended_rule=mode_config['recommended_rule'],
            )
        
        except Exception as e:
            return WordlistResult(
                success=False,
                error=str(e)
            )
    
    def _build_base_wordlist(
        self,
        essid: Optional[str],
        keywords: Optional[List[str]],
        mode: str
    ) -> Set[str]:
        """Build base wordlist from SSID, keywords, and Brazilian patterns."""
        words = set()
        
        # 1. SSID-based patterns (if provided)
        if essid:
            ssid_patterns = SSIDAnalyzer.extract_patterns(essid)
            
            # Add base SSID variations
            words.update(ssid_patterns['base'])
            
            # SSID + common suffixes
            for base in ssid_patterns['base'][:5]:  # Top 5 variations
                for suffix in ['123', '1234', '12345', '@123', '!123', '2024', '2025']:
                    words.add(f"{base}{suffix}")
                for suffix in ['!', '@', '#', '!!', '@@']:
                    words.add(f"{base}{suffix}")
            
            # SSID + years
            for base in ssid_patterns['base'][:3]:
                for year in BrazilianPatterns.RECENT_YEARS:
                    words.add(f"{base}{year}")
            
            # Parts combinations
            if len(ssid_patterns['parts']) >= 2:
                for i, part1 in enumerate(ssid_patterns['parts']):
                    for part2 in ssid_patterns['parts'][i+1:]:
                        words.add(f"{part1}{part2}")
                        words.add(f"{part1}_{part2}")
                        words.add(f"{part1}{part2}123")
        
        # 2. Keywords (if provided)
        if keywords:
            for kw in keywords:
                clean_kw = BrazilianPatterns.strip_accents(kw).lower()
                words.add(clean_kw)
                words.add(clean_kw.capitalize())
                words.add(clean_kw.upper())
                # Keyword + numbers
                for num in ['123', '1234', '12345', '321', '2024']:
                    words.add(f"{clean_kw}{num}")
        
        # 3. Top leaked passwords (always include)
        words.update(BrazilianPatterns.TOP_LEAKED_PASSWORDS)
        
        # 4. Brazilian patterns based on mode
        if mode == 'quick':
            # Quick: Names + top teams + WiFi patterns
            words.update(BrazilianPatterns.NAMES_MALE[:30])
            words.update(BrazilianPatterns.NAMES_FEMALE[:30])
            words.update(BrazilianPatterns.FOOTBALL_TEAMS_MAJOR[:40])
            words.update(BrazilianPatterns.WIFI_SPECIFIC)
            words.update(BrazilianPatterns.get_date_wordlist(2000, 2025, 200))  # Recent dates
            
        elif mode == 'balanced':
            # Balanced: More names, teams, cities, common words
            words.update(BrazilianPatterns.get_all_names()[:150])
            words.update(BrazilianPatterns.FOOTBALL_TEAMS_MAJOR)
            words.update(BrazilianPatterns.CITIES_MAJOR)
            words.update(BrazilianPatterns.WIFI_SPECIFIC)
            words.update(BrazilianPatterns.FAMILY_WORDS)
            words.update(BrazilianPatterns.SLANG_MODERN)
            words.update(BrazilianPatterns.get_date_wordlist(1970, 2025, 1000))  # Common dates
            
        else:  # aggressive
            # Aggressive: Everything
            words.update(BrazilianPatterns.get_all_names())
            words.update(BrazilianPatterns.get_all_football())
            words.update(BrazilianPatterns.get_all_locations())
            words.update(BrazilianPatterns.get_all_common_words())
            words.update(BrazilianPatterns.get_isp_patterns())
        
        # 5. Name + year combinations (very common in Brazil)
        top_names = (
            BrazilianPatterns.NAMES_MALE[:20] +
            BrazilianPatterns.NAMES_FEMALE[:20]
        )
        for name in top_names:
            for year in BrazilianPatterns.ALL_YEARS[::5]:  # Every 5 years
                words.add(f"{name}{year}")
        
        # 6. Football team + numbers
        for team in BrazilianPatterns.FOOTBALL_TEAMS_MAJOR[:30]:
            for num in ['10', '123', '2024', '7', '9']:
                words.add(f"{team}{num}")
        
        # 7. Common patterns
        for word in ['senha', 'wifi', 'internet', 'casa', 'familia']:
            for num in ['123', '1234', '12345', '2024', '2025']:
                words.add(f"{word}{num}")
            for suffix in ['@123', '!123', '#123']:
                words.add(f"{word}{suffix}")
        
        # 8. Date patterns already included via get_date_wordlist above
        # Additional date+year combinations
        for date_ddmm in BrazilianPatterns.SIGNIFICANT_DATES_DDMM[:20]:
            for year in BrazilianPatterns.ALL_YEARS[::10]:  # Every 10 years
                words.add(f"{date_ddmm}{year}")
        
        # 9. Phone patterns (DDD + common sequences)
        for ddd in BrazilianPatterns.PHONE_DDD[:20]:  # Top 20 DDDs
            words.add(f"{ddd}999999999")
            words.add(f"{ddd}99999999")
            words.add(f"{ddd}987654321")
        
        return words
    
    def _deduplicate_and_filter(
        self,
        input_file: str,
        min_length: int,
        max_length: int,
        target_size: int
    ) -> List[str]:
        """Deduplicate and filter wordlist by length."""
        unique_words = set()
        
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip()
                # Filter by length
                if min_length <= len(word) <= max_length:
                    unique_words.add(word)
        
        # Convert to list and limit to target size
        words_list = sorted(list(unique_words))
        
        if len(words_list) > target_size:
            words_list = words_list[:target_size]
        
        return words_list
    
    @staticmethod
    def get_available_rules() -> List[Dict[str, any]]:
        """Get available hashcat rules with metadata."""
        rules_dir = '/usr/share/hashcat/rules'
        
        if not os.path.exists(rules_dir):
            return []
        
        rules = []
        rule_info = {
            'best66.rule': {'multiplier': 66, 'description': 'Best 66 rules (recommended for quick)'},
            'dive.rule': {'multiplier': 200, 'description': 'Dive rules (recommended for balanced)'},
            'rockyou-30000.rule': {'multiplier': 30000, 'description': 'RockYou 30k rules (aggressive)'},
            'leetspeak.rule': {'multiplier': 20, 'description': 'Leet speak transformations'},
            'd3ad0ne.rule': {'multiplier': 150, 'description': 'D3ad0ne rules'},
            'Incisive-leetspeak.rule': {'multiplier': 100, 'description': 'Incisive leet speak'},
            'unix-ninja-leetspeak.rule': {'multiplier': 80, 'description': 'Unix ninja leet'},
        }
        
        for filename in os.listdir(rules_dir):
            if filename.endswith('.rule'):
                path = os.path.join(rules_dir, filename)
                info = rule_info.get(filename, {'multiplier': 50, 'description': 'Custom rules'})
                
                rules.append({
                    'name': filename,
                    'path': path,
                    'multiplier': info['multiplier'],
                    'description': info['description'],
                })
        
        return sorted(rules, key=lambda x: x['multiplier'])
