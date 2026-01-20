"""
Background worker functions.

Contains all long-running operations that run in separate threads:
scanning, attacking, cracking.
"""

from __future__ import annotations
import os
import time
import subprocess
import builtins
import glob
import re
import select
from datetime import datetime
from typing import List, Dict, Any, Optional

from .state import get_state
from .storage import get_storage
from .services import HashService, NetworkService
from .logging import log, get_logger

# Import core sniff functionality
import memento as sniff
from . import cracking
from .monitor import get_monitor


def cleanup_orphan_captures(essid: str, bssid: str) -> int:
    """
    Clean up capture files that don't have corresponding hash files.
    Called when no handshake is extracted from a capture.
    
    Returns number of files deleted.
    """
    deleted = 0
    # Look for capture files matching this network
    safe_essid = essid.replace(' ', '_')  # Match the sanitization in sniff.py
    patterns = [
        f"captures/*{safe_essid}*.cap",
        f"captures/*{safe_essid}*.pcap",
        f"capture_{safe_essid}*.cap",  # Files in working dir before move
        f"capture_{safe_essid}*.csv",
        f"capture_{safe_essid}*.log",
    ]
    
    for pattern in patterns:
        for cap_file in glob.glob(pattern):
            try:
                os.remove(cap_file)
                deleted += 1
            except Exception:
                pass
    
    return deleted

def run_scan_worker() -> None:
    """Background worker for network scanning using WirelessMonitor."""
    state = get_state()
    storage = get_storage()
    
    sniff.graceful_shutdown = False
    state.scanning = True
    storage.update_stats(
        scan_start_time=datetime.now().isoformat(),
        current_operation='Scanning (Reactive Engine)...',
    )
    
    log('Starting network scan using Reactive Engine...', 'info')
    
    try:
        # Interface discovery
        interface = state.settings.get('interface') or sniff.get_wireless_interface(auto_select=True)
        if not state.monitor_interface:
            log(f'Enabling monitor mode on {interface}...', 'info')
            mon_interface = sniff.start_monitor_mode(interface)
            state.monitor_interface = mon_interface
        else:
            mon_interface = state.monitor_interface
        
        # Start the engine
        monitor = get_monitor(mon_interface)
        monitor.start()
        
        log('Reactive Engine scanning active', 'success')
        
        # Scan for 30s by default if not in vigilance
        scan_duration = 30
        start_time = time.time()
        
        while time.time() - start_time < scan_duration:
            if not state.scanning:
                break
            time.sleep(1)
            
        if not state.vigilant:
            monitor.stop()
            
        log('Scan phase complete', 'success')
        
    except Exception as e:
        log(f'Scan error: {str(e)}', 'error')
    finally:
        state.scanning = False
        storage.update_stats(current_operation='Idle')
        storage.flush()


def run_attack_worker(network: Dict[str, Any]) -> None:
    """Background worker for attacking a single network."""
    state = get_state()
    storage = get_storage()
    
    sniff.graceful_shutdown = False
    state.attacking = True
    state.current_network = network
    storage.update_stats(current_operation=f'Attacking {network["essid"]}...')
    
    log(f'Targeting {network["essid"]} ({network["bssid"]}) on channel {network["channel"]}', 'info')
    
    try:
        if not state.attacking:
            log('Attack cancelled before start', 'warning')
            return
        
        # Ensure monitor mode
        if not state.monitor_interface:
            log('Monitor interface not active, starting monitor mode...', 'warning')
            
            interface = state.settings.get('interface')
            if not interface:
                interfaces = sniff.get_all_wireless_interfaces()
                if not interfaces:
                    log('No wireless interface found', 'error')
                    return
                interface = interfaces[0]
                storage.update_settings(interface=interface)
            
            log('Starting monitor mode...', 'info')
            mon_interface = sniff.start_monitor_mode(interface)
            state.monitor_interface = mon_interface
            log(f'Monitor mode enabled: {mon_interface}', 'success')
        
        target_net = {
            'bssid': network['bssid'],
            'essid': network['essid'],
            'channel': network['channel'],
            'power': network.get('power', '-50'),
            'encryption': network.get('encryption', 'WPA2-PSK'),
            'clients': network.get('clients', 0),
            'has_clients': network.get('has_clients', False),
            'stations': network.get('stations', []),
        }
        
        before_count = len(sniff.captured_handshakes)
        
        log('Starting handshake capture...', 'info')
        
        # Redirect prints to log
        def log_print(*args, **kwargs):
            message = ' '.join(str(arg) for arg in args)
            level = 'info'
            if '[+]' in message:
                level = 'success'
            elif '[!]' in message:
                level = 'warning'
            message = message.replace('[+]', '').replace('[!]', '').replace('[*]', '').strip()
            log(message, level)
        
        old_print = builtins.print
        builtins.print = log_print
        
        try:
            updated_info = sniff.capture_handshake(state.monitor_interface, target_net)
            
            if updated_info and updated_info.get('bssid'):
                stations = [mac.upper() for mac in updated_info.get('stations', [])]
                storage.upsert_network(
                    updated_info['bssid'],
                    essid=updated_info.get('essid'),
                    channel=updated_info.get('channel'),
                    power=updated_info.get('power'),
                    encryption=updated_info.get('encryption'),
                    stations=stations,
                    cached=False,
                )
                log(f'Network info refreshed: {updated_info.get("clients", 0)} clients, {updated_info.get("power", "-50")} dBm', 'info')
        finally:
            builtins.print = old_print
        
        after_count = len(sniff.captured_handshakes)
        if after_count > before_count:
            storage.increment_stat('handshakes_captured')
            log('Handshake captured successfully!', 'success')
            HashService.sync_inventory()
        else:
            log('No handshake detected', 'warning')
            # Clean up orphan capture files
            deleted = cleanup_orphan_captures(network.get('essid', ''), network.get('bssid', ''))
            if deleted > 0:
                log(f'Cleaned up {deleted} orphan capture file(s)', 'info')
        
        storage.increment_stat('networks_attacked')
        
    except Exception as e:
        log(f'Attack error: {str(e)}', 'error')
        import traceback
        traceback.print_exc()
    finally:
        state.attacking = False
        state.current_network = None
        storage.update_stats(current_operation='Idle')
        storage.flush()


def run_batch_attack_worker(network_list: List[Dict[str, Any]]) -> None:
    """Background worker for batch attacking multiple networks."""
    state = get_state()
    storage = get_storage()
    
    sniff.graceful_shutdown = False
    state.attacking = True
    total = len(network_list)
    
    for i, network in enumerate(network_list, 1):
        if not state.attacking:
            log(f'Batch attack cancelled. Processed {i-1}/{total} networks.', 'warning')
            break
        
        state.current_network = network
        storage.update_stats(current_operation=f'Batch [{i}/{total}]: {network["essid"]}')
        
        log(f'[{i}/{total}] Attacking {network["essid"]} ({network["bssid"]})...', 'info')
        
        try:
            # Ensure monitor mode
            if not state.monitor_interface:
                log('Monitor interface not active, starting monitor mode...', 'warning')
                
                interface = state.settings.get('interface')
                if not interface:
                    interfaces = sniff.get_all_wireless_interfaces()
                    if not interfaces:
                        log('No wireless interface found', 'error')
                        break
                    interface = interfaces[0]
                
                mon_interface = sniff.start_monitor_mode(interface)
                state.monitor_interface = mon_interface
                log(f'Monitor mode enabled: {mon_interface}', 'success')
            
            target_net = {
                'bssid': network['bssid'],
                'essid': network['essid'],
                'channel': network['channel'],
                'power': network.get('power', '-50'),
                'encryption': network.get('encryption', 'WPA2-PSK'),
                'clients': network.get('clients', 0),
                'has_clients': network.get('has_clients', False),
                'stations': network.get('stations', []),
            }
            
            before_count = len(sniff.captured_handshakes)
            
            def log_print(*args, **kwargs):
                message = ' '.join(str(arg) for arg in args)
                level = 'info'
                if '[+]' in message:
                    level = 'success'
                elif '[!]' in message:
                    level = 'warning'
                message = message.replace('[+]', '').replace('[!]', '').replace('[*]', '').strip()
                log(message, level)
            
            old_print = builtins.print
            builtins.print = log_print
            
            try:
                updated_info = sniff.capture_handshake(state.monitor_interface, target_net)
                
                if updated_info and updated_info.get('bssid'):
                    stations = [mac.upper() for mac in updated_info.get('stations', [])]
                    storage.upsert_network(
                        updated_info['bssid'],
                        essid=updated_info.get('essid'),
                        channel=updated_info.get('channel'),
                        power=updated_info.get('power'),
                        encryption=updated_info.get('encryption'),
                        stations=stations,
                        cached=False,
                    )
                
                after_count = len(sniff.captured_handshakes)
                if after_count > before_count:
                    storage.increment_stat('handshakes_captured')
                    log(f'[{i}/{total}] Handshake captured for {network["essid"]}!', 'success')
                    HashService.sync_inventory()
                else:
                    log(f'[{i}/{total}] No handshake for {network["essid"]}', 'warning')
            finally:
                builtins.print = old_print
            
            storage.increment_stat('networks_attacked')
            
        except Exception as e:
            log(f'[{i}/{total}] Attack error: {str(e)}', 'error')
            import traceback
            traceback.print_exc()
    
    state.attacking = False
    state.current_network = None
    storage.update_stats(current_operation='Idle')
    storage.flush()
    log(f'Batch attack completed. Processed {total} network(s).', 'success')


def run_crack_worker(task_list: List[Dict[str, Any]]) -> None:
    """Background worker for cracking hash files."""
    if not task_list:
        return
    
    state = get_state()
    storage = get_storage()
    
    state.cracking = True
    state.crack_queue = task_list
    total = len(task_list)
    
    def update_operation(message: str):
        if not state.scanning and not state.attacking:
            storage.update_stats(current_operation=message)
    
    try:
        for idx, task in enumerate(task_list, 1):
            if not state.cracking:
                log('Cracking cancelled by user request', 'warning')
                break
            
            state.current_crack = task
            hash_name = task["hash_name"]
            mask_type = task.get('mask_type')
            
            # Determine attack type
            if mask_type:
                # Mask attack (e.g., 8-digit numbers)
                update_operation(f'Cracking [{idx}/{total}] {hash_name} (mask)')
                mask_desc = '8-digit numbers' if mask_type == '__MASK_8DIGIT__' else mask_type
                log(f'[{idx}/{total}] Cracking {hash_name} with {mask_desc}...', 'info')
                
                def forward_log(message: str, prefix=hash_name):
                    log(f'{prefix}: {message}', 'info')
                
                try:
                    # Check if this mask was already tried
                    if storage.has_attempted(task['hash_rel'], mask_type, None):
                        log(f'[{idx}/{total}] Skipping duplicate mask attempt ({mask_desc})', 'info')
                        continue
                    
                    result = cracking.run_mask_attack(
                        task['hash'],
                        mask_type,
                        log_callback=forward_log,
                    )
                    
                    if result.get('cracked'):
                        storage.increment_stat('hashes_cracked')
                        HashService.mark_cracked(task.get('hash'), result.get('output_file'))
                        log(f'[{idx}/{total}] Case solved! Evidence saved to {result.get("output_file")}', 'success')
                    else:
                        exit_code = result.get('exit_code')
                        log(f'[{idx}/{total}] Finished (exit {exit_code})', 'warning')
                        
                        # Recorded only if fully exhausted or finished naturally
                        # Hashcat: 0 = Finished/Exhausted, 1 = Cracked
                        if exit_code in (0, 1):
                            if storage.add_cracking_attempt(task['hash_rel'], mask_type, None):
                                log(f'[{idx}/{total}] Recorded mask attempt: {mask_desc}', 'info')
                        else:
                            log(f'[{idx}/{total}] Attempt interrupted (code {exit_code}). Not recorded.', 'warning')
                        
                except Exception as e:
                    log(f'[{idx}/{total}] Mask attack error: {e}', 'error')
                    import traceback
                    traceback.print_exc()
            else:
                # Regular wordlist attack
                update_operation(f'Cracking [{idx}/{total}] {hash_name}')
                log(f'[{idx}/{total}] Cracking {hash_name} with {task["wordlist_name"]}...', 'info')
                
                def forward_log(message: str, prefix=hash_name):
                    log(f'{prefix}: {message}', 'info')
                
                try:
                    # Extract rule file if provided
                    rule_file = task.get('rule_file')
                    wordlist_name = task.get('wordlist_name', os.path.basename(task['wordlist']))
                    rule_name = os.path.basename(rule_file) if rule_file else None
                    
                    # Check if this wordlist+rule combo was already tried
                    if storage.has_attempted(task['hash_rel'], wordlist_name, rule_name):
                        log(f'[{idx}/{total}] Skipping duplicate attempt ({wordlist_name} + {rule_name or "no rule"})', 'info')
                        continue
                    
                    result = cracking.run_cracker(
                        task['hash'],
                        task['wordlist'],
                        rule_file=rule_file,
                        log_callback=forward_log,
                    )
                    
                    if result.get('cracked'):
                        storage.increment_stat('hashes_cracked')
                        HashService.mark_cracked(task.get('hash'), result.get('output_file'))
                        log(f'[{idx}/{total}] Case solved! Evidence saved to {result.get("output_file")}', 'success')
                    else:
                        exit_code = result.get('exit_code')
                        log(f'[{idx}/{total}] Finished (exit {exit_code})', 'warning')
                        
                        # Record only if hashcat finished the wordlist (0 or 1)
                        if exit_code in (0, 1):
                            if storage.add_cracking_attempt(task['hash_rel'], wordlist_name, rule_name):
                                log(f'[{idx}/{total}] Recorded attempt: {wordlist_name}' + (f' + {rule_name}' if rule_name else ''), 'info')
                        else:
                            log(f'[{idx}/{total}] Attempt interrupted (code {exit_code}). Not recorded.', 'warning')
                        
                except Exception as e:
                    log(f'[{idx}/{total}] Cracking error: {e}', 'error')
                    import traceback
                    traceback.print_exc()
        
        log('Cracking queue finished.', 'success')
        
    finally:
        state.cracking = False
        state.current_crack = None
        state.crack_queue = []
        if not state.scanning and not state.attacking and not state.vigilant:
            storage.update_stats(current_operation='Idle')
        storage.flush()


def run_vigilance_worker() -> None:
    """
    Vigilance Mode: Constant background monitoring using hcxdumptool.
    """
    state = get_state()
    storage = get_storage()
    
    sniff.graceful_shutdown = False
    state.vigilant = True
    storage.update_stats(
        scan_start_time=datetime.now().isoformat(),
        current_operation='Vigilance: Active',
    )
    
    log('Vigilance Mode activated - The engine is always watching (hcxdumptool).', 'success')
    
    capture_file = 'captures/vigilance.pcapng'
    
    try:
        # Interface discovery
        interface = state.settings.get('interface') or sniff.get_wireless_interface(auto_select=True)
        
        # hcxdumptool v7 prefers the raw interface, not mon interface
        if state.monitor_interface:
            log(f"Stopping monitor mode on {state.monitor_interface} for hcxdumptool...", "info")
            sniff.cleanup_processes()
            state.monitor_interface = None
            time.sleep(2)

        # Ensure directory exists
        os.makedirs('captures', exist_ok=True)
        # Delete old vigilance pcap to start fresh (v7 won't overwrite)
        if os.path.exists(capture_file):
            try:
                os.remove(capture_file)
            except:
                pass

        # Launch hcxdumptool
        # -i: interface, -w: output file, -F: all frequencies, --rds=2: show PMKID/Handshakes
        cmd = [
            'hcxdumptool',
            '-i', interface,
            '-w', capture_file,
            '-F',
            '--rds=2'
        ]
        
        log(f"Starting hcxdumptool on {interface} (v7 BPF Engine)...", "info")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        last_harvest = time.time()
        
        while state.vigilant:
            # Check if user deactivated
            if not state.vigilant:
                break
            
            # Non-blocking read from stdout
            r, _, _ = select.select([proc.stdout], [], [], 0.5)
            if r:
                line = proc.stdout.readline()
                if line:
                    line = line.strip()
                    # hcxdumptool v7 RDS mode 2 output parsing
                    # Example indicators: [P] for PMKID, [2] or [3] for Handshakes
                    if any(indicator in line for indicator in ['[P]', '[1]', '[2]', '[3]']):
                        log(f"Capture Event: {line}", "success")
            
            # Periodic harvesting every 2 minutes
            if time.time() - last_harvest > 120:
                if os.path.exists(capture_file):
                    log("Vigilance: Periodic hash harvest...", "info")
                    harvest_hashes(capture_file)
                    HashService.sync_inventory()
                last_harvest = time.time()

            # Check if process is still running
            if proc.poll() is not None:
                log(f"hcxdumptool exited with code {proc.returncode}", "error")
                break
                
        # Cleanup
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            
        log('Vigilance Mode stopped', 'info')
        
    except Exception as e:
        log(f'Vigilance error: {str(e)}', 'error')
    finally:
        state.vigilant = False
        storage.update_stats(current_operation='Idle')
        storage.flush()


def harvest_hashes(pcap_path: str):
    """Run hcxpcapngtool and split hashes into individual files."""
    tmp_hash = "/tmp/memento_harvest.hc22000"
    if os.path.exists(tmp_hash):
        try:
            os.remove(tmp_hash)
        except:
            pass
        
    try:
        subprocess.run(['hcxpcapngtool', '-o', tmp_hash, pcap_path],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        if os.path.exists(tmp_hash) and os.path.getsize(tmp_hash) > 0:
            split_hc22000_file(tmp_hash, 'hashes')
    except Exception as e:
        log(f"Harvest error: {e}", "error")


def split_hc22000_file(input_file: str, output_dir: str):
    """Split a bulk .hc22000 file into individual files based on ESSID."""
    os.makedirs(output_dir, exist_ok=True)
    
    with open(input_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            parts = line.split('*')
            if len(parts) >= 6:
                essid_hex = parts[5]
                try:
                    essid = bytes.fromhex(essid_hex).decode('utf-8', 'ignore')
                    safe_essid = re.sub(r'[^a-zA-Z0-9_-]', '_', essid)
                    if not safe_essid:
                        safe_essid = f"unknown_{essid_hex[:8]}"
                    
                    out_file = os.path.join(output_dir, f"{safe_essid}_vigilance.hc22000")
                    
                    # Deduplicate: Only append if hash not already in file
                    existing_hashes = set()
                    if os.path.exists(out_file):
                        with open(out_file, 'r') as of:
                            for l in of:
                                existing_hashes.add(l.strip())
                    
                    if line not in existing_hashes:
                        with open(out_file, 'a') as of:
                            of.write(line + '\n')
                except Exception:
                    pass


def run_rolling_cracker_worker() -> None:
    """
    Rolling Cracker: Continuous background hash cracking.
    
    Iterates through uncracked hashes, trying each wordlist.
    - Uses user-specified wordlist order if provided
    - Skips already-attempted combinations
    - Can run alongside Vigilance mode
    - Rules are currently disabled (AI passwords only)
    """
    from .rolling_cracker import RollingCracker
    
    state = get_state()
    storage = get_storage()
    
    state.rolling_cracking = True
    storage.update_stats(current_operation='Anterograde Amnesia...')
    
    log('Anterograde Amnesia activated - solving cases in a loop...', 'success')
    
    try:
        cracker = RollingCracker()
        
        # Get available wordlists
        wordlists = storage.stats.get('wordlists', [])
        if not wordlists:
            # Fallback: scan wordlists directory
            wl_dir = 'wordlists'
            if os.path.exists(wl_dir):
                wordlists = [
                    {'path': os.path.join(wl_dir, f), 'name': f}
                    for f in os.listdir(wl_dir)
                    if f.endswith('.txt')
                ]
        
        # Add virtual wordlists (mask attacks treated as wordlists)
        virtual_wordlists = [
            {'path': '__MASK_8DIGIT__', 'name': '8-digit numbers (bruteforce)'},
        ]
        wordlists = virtual_wordlists + wordlists
        
        # Apply user-specified wordlist order if provided
        if state.wordlist_order:
            order_map = {name: idx for idx, name in enumerate(state.wordlist_order)}
            # Sort wordlists by user order, unordered ones go to the end
            wordlists.sort(key=lambda w: order_map.get(w.get('name', ''), 999))
            log(f'Using custom wordlist order ({len(state.wordlist_order)} items)', 'info')
        
        # Rules are disabled - using AI-generated passwords only
        rules = []
        
        jobs_completed = 0
        
        while state.rolling_cracking:
            # Get next job
            job = cracker.process_next(wordlists, rules)
            
            if not job:
                log('All combinations exhausted, waiting for new hashes...', 'info')
                # Wait and check again
                for _ in range(30):  # 30 seconds
                    if not state.rolling_cracking:
                        break
                    time.sleep(1)
                continue
            
            hash_record = job['hash']
            essid = hash_record.get('essid', 'Unknown')
            hash_path = hash_record.get('path', '')
            
            log(f'Cracking {essid}: {job["description"]}', 'info')
            storage.update_stats(current_operation=f'Solving: {essid}')
            
            # Generate output file path for cracked password
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"cracked/{essid}_{timestamp}_rolling.cracked"
            os.makedirs('cracked', exist_ok=True)
            
            # Build hashcat command with --outfile to capture password
            wordlist_path = job['wordlist_path']
            is_mask_attack = wordlist_path.startswith('__MASK_')
            
            # Map virtual wordlist to mask pattern
            mask_patterns = {
                '__MASK_8DIGIT__': '?d?d?d?d?d?d?d?d',
            }
            
            if is_mask_attack:
                # Mask attack (brute-force)
                mask = mask_patterns.get(wordlist_path, '?d?d?d?d?d?d?d?d')
                cmd = [
                    'hashcat',
                    '-m', '22000',
                    '-a', '3',  # Mask/brute-force mode
                    hash_path,
                    mask,
                    '--potfile-disable',
                    '-O',
                    '--outfile', output_file,
                    '--outfile-format', '2',  # Plain password only
                ]
            else:
                # Regular wordlist attack
                cmd = [
                    'hashcat',
                    '-m', '22000',
                    '-a', '0',  # Wordlist mode
                    hash_path,
                    wordlist_path,
                    '--potfile-disable',
                    '-O',
                    '--outfile', output_file,
                    '--outfile-format', '2',  # Plain password only
                ]
            
            if job['rule_path']:
                cmd.extend(['-r', job['rule_path']])
            
            # Run hashcat with progress monitoring (no timeout)
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,  # Line buffered
                )
                
                last_progress_time = time.time()
                last_progress_line = ""
                
                # Monitor process output
                while proc.poll() is None:
                    # Check if user stopped
                    if not state.rolling_cracking:
                        log(f'{essid}: User cancelled, terminating...', 'warning')
                        proc.terminate()
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                        break
                    
                    # Read available output (non-blocking via select)
                    import select
                    readable, _, _ = select.select([proc.stdout], [], [], 0.5)
                    if readable:
                        line = proc.stdout.readline()
                        if line:
                            # Capture progress lines for status updates
                            if 'Progress' in line or 'Speed' in line or 'Recovered' in line:
                                last_progress_line = line.strip()
                    
                    # Log progress every 15 minutes
                    elapsed = time.time() - last_progress_time
                    if elapsed >= 900:  # 15 minutes
                        if last_progress_line:
                            log(f'{essid}: {last_progress_line}', 'info')
                        else:
                            log(f'{essid}: Still running...', 'info')
                        last_progress_time = time.time()
                
                # Get final exit code
                exit_code = proc.returncode if proc.returncode is not None else proc.wait()
                
                # Record attempt ONLY if naturally finished or cracked
                # Hashcat: 0 = Finished/Exhausted, 1 = Cracked
                if exit_code in (0, 1):
                    if is_mask_attack:
                        wordlist_name = wordlist_path  # e.g., '__MASK_8DIGIT__'
                    else:
                        wordlist_name = os.path.basename(wordlist_path)
                    rule_name = os.path.basename(job['rule_path']) if job['rule_path'] else ''
                    
                    if storage.add_cracking_attempt(hash_path, wordlist_name, rule_name):
                        if exit_code == 0:
                            log(f'{essid}: no match with {job["description"]}', 'info')
                else:
                    log(f'{essid}: Attempt interrupted (code {exit_code}). Not recording.', 'warning')
                
                if exit_code == 1:
                    # Cracked! Check output file for password
                    log(f'CRACKED {essid}!', 'success')
                    storage.increment_stat('hashes_cracked')
                    
                    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                        HashService.mark_cracked(hash_path, output_file)
                        # Read password for logging (first line only)
                        try:
                            with open(output_file, 'r') as f:
                                password = f.readline().strip()
                            log(f'Password: {password}', 'success')
                        except:
                            pass
                    else:
                        log(f'Warning: Output file empty for {essid}', 'warning')
                        HashService.mark_cracked(hash_path, None)
                else:
                    log(f'{essid}: no match with {job["description"]}', 'info')
                
                jobs_completed += 1
                
            except Exception as e:
                log(f'Error: {e}', 'error')
            
            # Clean up ESSID wordlist if generated
            if job.get('essid_wordlist') and os.path.exists(job['essid_wordlist']):
                try:
                    os.remove(job['essid_wordlist'])
                except:
                    pass
            
            storage.flush()
            
            # Brief pause between jobs
            if state.rolling_cracking:
                time.sleep(2)
        
        log(f'Anterograde Amnesia stopped ({jobs_completed} jobs completed)', 'info')
        
    except Exception as e:
        log(f'Rolling Cracker error: {str(e)}', 'error')
        import traceback
        traceback.print_exc()
    finally:
        state.rolling_cracking = False
        if not state.scanning and not state.attacking and not state.vigilant:
            storage.update_stats(current_operation='Idle')
        storage.flush()

