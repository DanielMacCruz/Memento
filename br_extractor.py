#!/usr/bin/env python3
"""
BR Extractor
Extracts Brazilian passwords using AI-generated classification.
Only processes folders marked as PARSE in the classification JSON.
"""

import os
import re
import json
import argparse
from pathlib import Path
from datetime import datetime

# ============================================================================
# CONFIGURATION
# ============================================================================

SOURCE_DIR = "/run/media/kozi/HDD4TB/New folder/Database Leaks/DATABASES/Raidforums"
CLASSIFICATION_FILE = "/run/media/kozi/HDD4TB/New folder/BR_CLASSIFICATION.json"
OUTPUT_FILE = "/run/media/kozi/HDD4TB/New folder/BIG_BR_DUMP.txt"
CHECKPOINT_INTERVAL = 50000

# Brazilian email pattern
BR_EMAIL_RE = re.compile(r'[\w.-]+@[\w.-]+\.br\b', re.IGNORECASE)

# ============================================================================
# VALIDATION
# ============================================================================

def is_valid_password(password: str) -> bool:
    """Strict password validation."""
    if not password or len(password) < 4 or len(password) > 32:
        return False
    
    # Reject common garbage
    if password in ('None', 'xxx', 'null', 'NULL', '', 'N/A', 'n/a', 'first_name', 'last_name'):
        return False
    
    # Reject if contains spaces (names)
    if ' ' in password:
        return False
    
    # Reject dates
    if re.match(r'^\d{4}-\d{2}-\d{2}$', password):
        return False
    
    # Reject hashes (MD5=32, SHA1=40, SHA256=64 hex chars)
    if len(password) in (32, 40, 64) and all(c in '0123456789abcdefABCDEF' for c in password):
        return False
    
    # Reject hex-prefixed hashes
    if password.startswith('0x') and len(password) > 30:
        return False
    
    # Reject bcrypt
    if password.startswith('$2'):
        return False
    
    # Reject full emails
    if '@' in password and re.match(r'^[\w.-]+@[\w.-]+\.\w{2,}$', password):
        return False
    
    # Reject timestamps/JSON
    if password.endswith('}}') or re.search(r'\d+\.\d+Z', password):
        return False
    
    # Reject coordinates
    if re.match(r'^-?\d+\.\d+-?\d*$', password):
        return False
    
    # Reject IP addresses
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', password):
        return False
    
    # Reject JSON/CSV fragments
    if password.startswith('"') or password.endswith('"') or '","' in password:
        return False
    
    # Reject very long pure numbers (phone/IDs)
    if password.isdigit() and len(password) > 12:
        return False
    
    # Must have alphanumeric
    if not any(c.isalnum() for c in password):
        return False
    
    return True


def is_brazilian_line(line: str) -> bool:
    """Check if line contains Brazilian email."""
    return bool(BR_EMAIL_RE.search(line))


# ============================================================================
# EXTRACTION
# ============================================================================

def extract_password(line: str, config: dict) -> str:
    """Extract password from line based on config."""
    delimiter = config.get('delimiter', ':')
    password_field = config.get('password_field', -1)
    
    # Handle different delimiters
    if delimiter == '\\t':
        parts = line.strip().split('\t')
    else:
        parts = line.strip().split(delimiter)
    
    if not parts:
        return None
    
    # Get password field
    try:
        password = parts[password_field].strip()
    except (IndexError, TypeError):
        return None
    
    if is_valid_password(password):
        return password
    
    return None


def process_folder(folder_path: Path, config: dict, output_file, seen: set) -> tuple:
    """Process a folder and extract passwords."""
    folder_name = folder_path.name
    total_found = 0
    
    # Find text files
    txt_files = list(folder_path.rglob('*.txt'))
    
    for txt_file in txt_files:
        try:
            with open(txt_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if not is_brazilian_line(line):
                        continue
                    
                    password = extract_password(line, config)
                    if password and password not in seen:
                        seen.add(password)
                        output_file.write(password + '\n')
                        total_found += 1
                        
                        if total_found % CHECKPOINT_INTERVAL == 0:
                            output_file.flush()
                            print(f"    [CHECKPOINT] {total_found:,} passwords")
        except Exception as e:
            print(f"    Error: {e}")
    
    return total_found


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='Extract Brazilian passwords using AI classification')
    parser.add_argument('--classification', '-c', default=CLASSIFICATION_FILE, help='Path to classification JSON')
    parser.add_argument('--source', '-s', default=SOURCE_DIR, help='Source directory')
    parser.add_argument('--output', '-o', default=OUTPUT_FILE, help='Output file path')
    
    args = parser.parse_args()
    
    # Load classification
    print(f"Loading classification: {args.classification}")
    with open(args.classification, 'r') as f:
        classification = json.load(f)
    
    # Filter to PARSE folders only
    parse_folders = {k: v for k, v in classification.items() if v.get('status') == 'PARSE'}
    print(f"Found {len(parse_folders)} folders to parse\n")
    
    # Prepare output
    seen = set()
    source_path = Path(args.source)
    
    # Load existing if resuming
    output_path = Path(args.output)
    if output_path.exists():
        print(f"Loading existing passwords for deduplication...")
        with open(output_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                seen.add(line.strip())
        print(f"Loaded {len(seen):,} existing passwords\n")
    
    start_time = datetime.now()
    total_passwords = 0
    
    with open(args.output, 'a', encoding='utf-8') as out:
        for folder_name, config in parse_folders.items():
            folder_path = source_path / folder_name
            if not folder_path.exists():
                print(f"[MISSING] {folder_name}")
                continue
            
            print(f"[PARSE] {folder_name}")
            print(f"    Config: {config}")
            
            found = process_folder(folder_path, config, out, seen)
            total_passwords += found
            print(f"    -> {found:,} passwords\n")
    
    elapsed = datetime.now() - start_time
    
    print("=" * 60)
    print("COMPLETE")
    print(f"Total passwords: {total_passwords:,}")
    print(f"Unique passwords: {len(seen):,}")
    print(f"Time: {elapsed}")
    print("=" * 60)


if __name__ == '__main__':
    main()
