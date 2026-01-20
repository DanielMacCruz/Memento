"""Modular cracking helpers (currently hashcat).

This module exists so the web UI can schedule cracking jobs without
baking in a specific tool forever. For now we shell out to hashcat
with sane defaults, but the interface is intentionally generic so we
can swap implementations later without rewriting the web worker.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from datetime import datetime
from typing import Callable, Dict, Optional

DEFAULT_TOOL = os.getenv("SNIFF_CRACKER_TOOL", "hashcat")
DEFAULT_OUTPUT_DIR = os.getenv("SNIFF_CRACKED_DIR", "cracked")
HASH_MODE = os.getenv("SNIFF_HASH_MODE", "22000")  # WPA-PBKDF2-PMKID+EAPOL

LogFn = Optional[Callable[[str], None]]


def _log(message: str, logger: LogFn = None) -> None:
    if logger:
        logger(message)


def ensure_directory(path: str) -> str:
    abs_path = os.path.abspath(path)
    os.makedirs(abs_path, exist_ok=True)
    return abs_path


def human_readable_size(size_bytes: int) -> str:
    if size_bytes <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    value = float(size_bytes)
    while value >= 1024 and idx < len(units) - 1:
        value /= 1024
        idx += 1
    return f"{value:.1f} {units[idx]}"


def build_output_filename(hash_file: str, wordlist_file: str, output_dir: str) -> str:
    hash_base = os.path.splitext(os.path.basename(hash_file))[0]
    wordlist_base = os.path.splitext(os.path.basename(wordlist_file))[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{hash_base}__{wordlist_base}__{timestamp}.cracked"
    return os.path.join(output_dir, filename)


def run_cracker(
    hash_file: str,
    wordlist_file: str,
    *,
    tool: Optional[str] = None,
    output_dir: Optional[str] = None,
    rule_file: Optional[str] = None,
    extra_args: Optional[list[str]] = None,
    log_callback: LogFn = None,
) -> Dict[str, object]:
    """Run the configured cracking tool against a hash + wordlist pair.

    Returns a dict containing exit_code, cracked flag, output_file path,
    and the command invoked. Any stdout is streamed to `log_callback` so
    the caller can push updates to the UI log.
    
    Args:
        hash_file: Path to hash file
        wordlist_file: Path to wordlist file
        tool: Cracking tool to use (default: hashcat)
        output_dir: Output directory for cracked passwords
        rule_file: Optional hashcat rule file for transformations
        extra_args: Additional command-line arguments
        log_callback: Callback function for logging
    """

    if not os.path.exists(hash_file):
        raise FileNotFoundError(f"Hash file not found: {hash_file}")
    if not os.path.exists(wordlist_file):
        raise FileNotFoundError(f"Wordlist not found: {wordlist_file}")

    tool = tool or DEFAULT_TOOL
    output_dir = ensure_directory(output_dir or DEFAULT_OUTPUT_DIR)
    output_file = build_output_filename(hash_file, wordlist_file, output_dir)
    extra_args = extra_args or []

    command = []
    if tool.lower() == "hashcat":
        command = [
            tool,
            "-m",
            HASH_MODE,
            hash_file,
            wordlist_file,
            "--status",
            "--status-timer=10",
            "--force",
            "--potfile-disable",
            "--outfile",
            output_file,
            "--outfile-format=2,3,4",
        ]
        
        # Add rule file if provided
        if rule_file:
            if not os.path.exists(rule_file):
                _log(f"Warning: Rule file not found: {rule_file}", log_callback)
            else:
                command.extend(["-r", rule_file])
                _log(f"Using hashcat rule: {os.path.basename(rule_file)}", log_callback)
        
        command.extend(extra_args)
    else:
        raise ValueError(f"Unsupported cracking tool: {tool}")

    # Log effective wordlist size if using rules
    if rule_file and os.path.exists(rule_file):
        try:
            # Count wordlist lines
            with open(wordlist_file, 'r') as f:
                wordlist_size = sum(1 for _ in f)
            
            # Estimate rule multiplier (rough count of rules)
            with open(rule_file, 'r') as f:
                rule_count = sum(1 for line in f if line.strip() and not line.startswith('#'))
            
            effective_size = wordlist_size * max(1, rule_count)
            _log(
                f"Wordlist: {wordlist_size:,} words × {rule_count} rules = ~{effective_size:,} effective candidates",
                log_callback
            )
        except Exception:
            pass  # Ignore errors in size calculation
    
    _log(
        f"Launching {tool} against {os.path.basename(hash_file)} with {os.path.basename(wordlist_file)}",
        log_callback,
    )

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    try:
        if process.stdout:
            for line in process.stdout:
                line = line.rstrip()
                if line:
                    _log(line, log_callback)
    finally:
        stdout = process.stdout
        if stdout:
            stdout.close()
        exit_code = process.wait()

    cracked = os.path.exists(output_file) and os.path.getsize(output_file) > 0

    status_line = "Cracked" if cracked else "No hits"
    _log(
        f"{status_line} (exit code {exit_code}) - output: {os.path.basename(output_file)}",
        log_callback,
    )

    return {
        "exit_code": exit_code,
        "cracked": cracked,
        "output_file": output_file if os.path.exists(output_file) else None,
        "command": " ".join(shlex.quote(part) for part in command),
    }


# Mask definitions for different attack types
MASK_PATTERNS = {
    '__MASK_8DIGIT__': {
        'mask': '?d?d?d?d?d?d?d?d',
        'description': '8-digit numbers (00000000-99999999)',
        'keyspace': 100_000_000,
    },
}


def run_mask_attack(
    hash_file: str,
    mask_type: str,
    *,
    tool: Optional[str] = None,
    output_dir: Optional[str] = None,
    log_callback: LogFn = None,
) -> Dict[str, object]:
    """Run a hashcat mask/brute-force attack.

    Mask attacks don't use wordlists - they generate candidates directly
    based on a pattern. For example, ?d?d?d?d?d?d?d?d tries all 8-digit numbers.

    Args:
        hash_file: Path to hash file
        mask_type: Mask identifier (e.g., '__MASK_8DIGIT__')
        tool: Cracking tool (default: hashcat)
        output_dir: Output directory for cracked passwords
        log_callback: Callback for logging
    """

    if not os.path.exists(hash_file):
        raise FileNotFoundError(f"Hash file not found: {hash_file}")
    
    if mask_type not in MASK_PATTERNS:
        raise ValueError(f"Unknown mask type: {mask_type}")
    
    mask_info = MASK_PATTERNS[mask_type]
    mask = mask_info['mask']
    desc = mask_info['description']
    keyspace = mask_info.get('keyspace', 0)

    tool = tool or DEFAULT_TOOL
    output_dir = ensure_directory(output_dir or DEFAULT_OUTPUT_DIR)
    
    # Build output filename with mask info
    hash_base = os.path.splitext(os.path.basename(hash_file))[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    mask_short = mask_type.replace('__MASK_', '').replace('__', '').lower()
    output_file = os.path.join(output_dir, f"{hash_base}__mask_{mask_short}__{timestamp}.cracked")

    command = [
        tool,
        "-m", HASH_MODE,
        "-a", "3",  # Brute-force/mask mode
        hash_file,
        mask,
        "--status",
        "--status-timer=10",
        "--force",
        "--potfile-disable",
        "--outfile", output_file,
        "--outfile-format=2,3,4",
    ]

    _log(f"Mask attack: {desc}", log_callback)
    if keyspace:
        _log(f"Keyspace: {keyspace:,} combinations", log_callback)
    _log(f"Launching {tool} -a 3 against {os.path.basename(hash_file)}", log_callback)

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    try:
        if process.stdout:
            for line in process.stdout:
                line = line.rstrip()
                if line:
                    _log(line, log_callback)
    finally:
        stdout = process.stdout
        if stdout:
            stdout.close()
        exit_code = process.wait()

    cracked = os.path.exists(output_file) and os.path.getsize(output_file) > 0

    status_line = "Cracked" if cracked else "No hits"
    _log(
        f"{status_line} (exit code {exit_code}) - output: {os.path.basename(output_file)}",
        log_callback,
    )

    return {
        "exit_code": exit_code,
        "cracked": cracked,
        "output_file": output_file if os.path.exists(output_file) else None,
        "command": " ".join(shlex.quote(part) for part in command),
    }
