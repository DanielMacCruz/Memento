"""
Wordlist quality checker.

Analyzes password wordlists for quality metrics:
- Duplicates
- Length distribution
- Character composition
- Pattern detection
- Overlap with training data
"""

import argparse
import re
from pathlib import Path
from collections import Counter
from typing import Dict, List, Optional, Tuple
import math


class WordlistAnalyzer:
    """Analyze wordlist quality."""
    
    # Common keyboard patterns
    KEYBOARD_PATTERNS = [
        'qwerty', 'asdfgh', 'zxcvbn', 'qweasd', '123456', '654321',
        'qazwsx', '1qaz2wsx', 'password', 'letmein', 'abc123'
    ]
    
    def __init__(self, wordlist_path: str, training_data_path: Optional[str] = None):
        """
        Initialize analyzer.
        
        Args:
            wordlist_path: Path to generated wordlist
            training_data_path: Optional path to training data for overlap check
        """
        self.wordlist_path = Path(wordlist_path)
        self.training_data_path = Path(training_data_path) if training_data_path else None
        self.passwords: List[str] = []
        self.training_passwords: set = set()
        
    def load(self):
        """Load wordlist and optional training data."""
        with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            self.passwords = [line.strip() for line in f if line.strip()]
        
        if self.training_data_path and self.training_data_path.exists():
            with open(self.training_data_path, 'r', encoding='utf-8', errors='ignore') as f:
                self.training_passwords = {line.strip() for line in f if line.strip()}
        
        print(f"Loaded {len(self.passwords):,} passwords from {self.wordlist_path}")
        if self.training_passwords:
            print(f"Loaded {len(self.training_passwords):,} training passwords for overlap check")
    
    def check_duplicates(self) -> Tuple[int, float, List[Tuple[str, int]]]:
        """
        Check for duplicate passwords.
        
        Returns:
            (total_dupes, dupe_percentage, top_10_dupes)
        """
        counter = Counter(self.passwords)
        dupes = {k: v for k, v in counter.items() if v > 1}
        total_dupes = sum(v - 1 for v in dupes.values())
        dupe_pct = (total_dupes / len(self.passwords)) * 100 if self.passwords else 0
        top_dupes = counter.most_common(10)
        
        return total_dupes, dupe_pct, top_dupes
    
    def check_length_distribution(self) -> Dict[str, any]:
        """
        Analyze password length distribution.
        
        Returns:
            Dict with min, max, avg, and histogram
        """
        lengths = [len(p) for p in self.passwords]
        if not lengths:
            return {"min": 0, "max": 0, "avg": 0, "histogram": {}}
        
        histogram = Counter(lengths)
        return {
            "min": min(lengths),
            "max": max(lengths),
            "avg": sum(lengths) / len(lengths),
            "histogram": dict(sorted(histogram.items()))
        }
    
    def check_character_composition(self) -> Dict[str, float]:
        """
        Analyze character set usage.
        
        Returns:
            Dict with percentages of each character type
        """
        total_chars = sum(len(p) for p in self.passwords)
        if total_chars == 0:
            return {}
        
        lowercase = sum(1 for p in self.passwords for c in p if c.islower())
        uppercase = sum(1 for p in self.passwords for c in p if c.isupper())
        digits = sum(1 for p in self.passwords for c in p if c.isdigit())
        special = sum(1 for p in self.passwords for c in p if not c.isalnum())
        
        return {
            "lowercase_pct": (lowercase / total_chars) * 100,
            "uppercase_pct": (uppercase / total_chars) * 100,
            "digits_pct": (digits / total_chars) * 100,
            "special_pct": (special / total_chars) * 100,
        }
    
    def check_invalid_lines(self) -> Dict[str, int]:
        """
        Check for invalid or problematic lines.
        
        Returns:
            Dict with counts of different issues
        """
        empty = 0
        whitespace_only = 0
        has_tabs = 0
        has_non_printable = 0
        
        with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                stripped = line.strip()
                if not line.strip('\n'):
                    empty += 1
                elif not stripped:
                    whitespace_only += 1
                if '\t' in line:
                    has_tabs += 1
                if any(ord(c) < 32 and c not in '\n\r\t' for c in line):
                    has_non_printable += 1
        
        return {
            "empty_lines": empty,
            "whitespace_only": whitespace_only,
            "has_tabs": has_tabs,
            "non_printable": has_non_printable
        }
    
    def check_training_overlap(self) -> Tuple[int, float]:
        """
        Check overlap with training data (memorization vs generation).
        
        Returns:
            (overlap_count, overlap_percentage)
        """
        if not self.training_passwords:
            return 0, 0.0
        
        overlap = sum(1 for p in self.passwords if p in self.training_passwords)
        overlap_pct = (overlap / len(self.passwords)) * 100 if self.passwords else 0
        
        return overlap, overlap_pct
    
    def check_patterns(self) -> Dict[str, int]:
        """
        Detect common weak patterns.
        
        Returns:
            Dict with pattern counts
        """
        patterns = {
            "repeated_chars": 0,      # aaa, 111
            "sequential_nums": 0,     # 123, 987
            "keyboard_walks": 0,      # qwerty, asdf
            "all_lowercase": 0,
            "all_uppercase": 0,
            "all_digits": 0,
            "date_patterns": 0,       # DDMMYYYY, etc
        }
        
        for p in self.passwords:
            pl = p.lower()
            
            # Repeated chars (3+ same char in a row)
            if re.search(r'(.)\1{2,}', p):
                patterns["repeated_chars"] += 1
            
            # Sequential numbers
            if re.search(r'(012|123|234|345|456|567|678|789|987|876|765|654|543|432|321|210)', p):
                patterns["sequential_nums"] += 1
            
            # Keyboard walks
            if any(kp in pl for kp in self.KEYBOARD_PATTERNS):
                patterns["keyboard_walks"] += 1
            
            # All same case
            if p.isalpha():
                if p.islower():
                    patterns["all_lowercase"] += 1
                elif p.isupper():
                    patterns["all_uppercase"] += 1
            
            # All digits
            if p.isdigit():
                patterns["all_digits"] += 1
            
            # Date patterns (simple check for DDMMYYYY, MMDDYYYY, etc)
            if re.match(r'^(0[1-9]|[12]\d|3[01])(0[1-9]|1[012])(19|20)\d{2}$', p) or \
               re.match(r'^(19|20)\d{2}(0[1-9]|1[012])(0[1-9]|[12]\d|3[01])$', p) or \
               re.match(r'^(0[1-9]|[12]\d|3[01])(0[1-9]|1[012])\d{2}$', p):
                patterns["date_patterns"] += 1
        
        return patterns
    
    def estimate_entropy(self) -> float:
        """
        Estimate average entropy per password (Shannon entropy approximation).
        
        Returns:
            Average bits of entropy
        """
        if not self.passwords:
            return 0.0
        
        entropies = []
        for p in self.passwords:
            if not p:
                continue
            # Count character classes
            char_space = 0
            if any(c.islower() for c in p):
                char_space += 26
            if any(c.isupper() for c in p):
                char_space += 26
            if any(c.isdigit() for c in p):
                char_space += 10
            if any(not c.isalnum() for c in p):
                char_space += 32  # Approximate special chars
            
            if char_space > 0:
                entropy = len(p) * math.log2(char_space)
                entropies.append(entropy)
        
        return sum(entropies) / len(entropies) if entropies else 0.0
    
    def analyze(self) -> Dict:
        """Run all quality checks and return results."""
        self.load()
        
        dupe_count, dupe_pct, top_dupes = self.check_duplicates()
        length_stats = self.check_length_distribution()
        char_comp = self.check_character_composition()
        invalid = self.check_invalid_lines()
        overlap, overlap_pct = self.check_training_overlap()
        patterns = self.check_patterns()
        entropy = self.estimate_entropy()
        
        return {
            "total_passwords": len(self.passwords),
            "unique_passwords": len(set(self.passwords)),
            "duplicates": {
                "count": dupe_count,
                "percentage": dupe_pct,
                "top_10": top_dupes
            },
            "length": length_stats,
            "character_composition": char_comp,
            "invalid_lines": invalid,
            "training_overlap": {
                "count": overlap,
                "percentage": overlap_pct
            },
            "patterns": patterns,
            "avg_entropy_bits": entropy
        }
    
    def print_report(self):
        """Print a formatted quality report."""
        results = self.analyze()
        
        print("\n" + "="*60)
        print("WORDLIST QUALITY REPORT")
        print("="*60)
        
        print(f"\n📊 SUMMARY")
        print(f"  Total passwords:  {results['total_passwords']:,}")
        print(f"  Unique passwords: {results['unique_passwords']:,}")
        print(f"  Avg entropy:      {results['avg_entropy_bits']:.1f} bits")
        
        print(f"\n🔄 DUPLICATES")
        print(f"  Duplicate count:  {results['duplicates']['count']:,}")
        print(f"  Duplicate %:      {results['duplicates']['percentage']:.2f}%")
        if results['duplicates']['top_10'] and results['duplicates']['count'] > 0:
            print("  Top duplicates:")
            for pwd, count in results['duplicates']['top_10'][:5]:
                if count > 1:
                    print(f"    '{pwd}': {count}x")
        
        print(f"\n📏 LENGTH DISTRIBUTION")
        print(f"  Min length: {results['length']['min']}")
        print(f"  Max length: {results['length']['max']}")
        print(f"  Avg length: {results['length']['avg']:.1f}")
        print("  Histogram:")
        for length, count in sorted(results['length']['histogram'].items()):
            bar = '█' * min(50, int(count / max(results['length']['histogram'].values()) * 50))
            print(f"    {length:2d} chars: {count:>8,} {bar}")
        
        print(f"\n🔤 CHARACTER COMPOSITION")
        for key, val in results['character_composition'].items():
            label = key.replace('_pct', '').replace('_', ' ').title()
            print(f"  {label}: {val:.1f}%")
        
        print(f"\n⚠️  PATTERNS (potential weak passwords)")
        for key, val in results['patterns'].items():
            if val > 0:
                pct = (val / results['total_passwords']) * 100
                label = key.replace('_', ' ').title()
                print(f"  {label}: {val:,} ({pct:.1f}%)")
        
        if results['training_overlap']['count'] > 0:
            print(f"\n📚 TRAINING DATA OVERLAP")
            print(f"  Memorized:  {results['training_overlap']['count']:,}")
            print(f"  Percentage: {results['training_overlap']['percentage']:.1f}%")
            print(f"  Novel:      {results['total_passwords'] - results['training_overlap']['count']:,}")
        
        if any(results['invalid_lines'].values()):
            print(f"\n❌ INVALID LINES")
            for key, val in results['invalid_lines'].items():
                if val > 0:
                    print(f"  {key.replace('_', ' ').title()}: {val}")
        
        print("\n" + "="*60)
        
        # Quality score
        score = 100
        if results['duplicates']['percentage'] > 1:
            score -= min(20, results['duplicates']['percentage'])
        if results['avg_entropy_bits'] < 30:
            score -= 10
        if results['patterns']['all_digits'] / max(1, results['total_passwords']) > 0.3:
            score -= 10
        if results['training_overlap']['percentage'] > 50:
            score -= 20
        
        print(f"🏆 QUALITY SCORE: {max(0, score):.0f}/100")
        print("="*60)


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Analyze wordlist quality")
    parser.add_argument("wordlist", help="Path to wordlist file")
    parser.add_argument("--training-data", "-t", 
                        help="Path to training data for overlap check")
    
    args = parser.parse_args()
    
    analyzer = WordlistAnalyzer(args.wordlist, args.training_data)
    analyzer.print_report()


if __name__ == "__main__":
    main()
