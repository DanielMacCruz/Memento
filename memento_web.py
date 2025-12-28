#!/usr/bin/env python3
"""
WiFi Handshake Capture Tool - Web Interface
Flask-based web GUI for monitoring and controlling handshake captures
"""

from flask import Flask, render_template, jsonify, request, Response
import threading
import time
import os
import sys
import json
from datetime import datetime
from queue import Queue
import subprocess
import re

# Import core functionality from sniff.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import memento as sniff
import cracking

app = Flask(__name__)

# Global state
class AppState:
    def __init__(self):
        self.scanning = False
        self.attacking = False
        self.cracking = False
        self.monitor_interface = None
        self.network_index = {}
        self.networks = []
        self.devices = {}
        self.hash_index = {}
        self.captured_handshakes = []
        self.current_network = None
        self.current_crack = None
        self.log_queue = Queue()
        self.stats = {
            'networks_scanned': 0,
            'networks_attacked': 0,
            'handshakes_captured': 0,
            'hashes_cracked': 0,
            'scan_start_time': None,
            'current_operation': 'Idle'
        }
        self.crack_queue = []
        self.settings = {
            'band': 'abg',
            'interface': None
        }

state = AppState()


def sync_network_snapshot():
    """Refresh derived network list after mutating network_index."""
    state.networks = list(state.network_index.values())


def get_devices_payload():
    """Return device objects as a list for API responses."""
    return list(state.devices.values())


def get_hashes_payload():
    """Return hash inventory for API responses."""
    return list(state.hash_index.values())


def find_network_record(bssid):
    """Fetch a normalized network record by BSSID (case-insensitive)."""
    if not bssid:
        return None
    return state.network_index.get(bssid.upper())


def upsert_network_record(bssid, sync_after=True, **updates):
    """Create or update a network record in the normalized store."""
    if not bssid:
        return None

    key = bssid.upper()
    now_iso = datetime.now().isoformat()
    record = state.network_index.get(key, {
        'bssid': key,
        'essid': 'Unknown',
        'channel': '',
        'power': '-100',
        'encryption': 'WPA2-PSK',
        'has_clients': False,
        'clients': 0,
        'stations': [],
        'device_ids': [],
        'cached': True,
        'hash_ids': [],
        'status': {
            'has_hash': False,
            'cracked': False
        },
        'cracked_password': None,
        'cracked_hex': None,
        'cracked_salt': None,
        'cracked_hash_path': None,
        'last_seen': now_iso,
        'first_seen': now_iso
    })

    for field, value in updates.items():
        if value is None:
            continue
        if field == 'stations':
            record['stations'] = value
            record['device_ids'] = value
            record['has_clients'] = len(value) > 0
            record['clients'] = len(value)
        elif field == 'hash_ids':
            record['hash_ids'] = value
            record['status']['has_hash'] = len(value) > 0
        elif field == 'cached':
            record['cached'] = value
        elif field == 'status':
            record['status'].update(value)
        else:
            record[field] = value

    record['last_seen'] = updates.get('last_seen', now_iso)
    state.network_index[key] = record
    if sync_after:
        sync_network_snapshot()
    return record


def mark_networks_cached(current_ids):
    """Set cached flag on networks that were not seen in the latest scan."""
    current_ids = {bssid.upper() for bssid in current_ids}
    for key, record in state.network_index.items():
        record['cached'] = key not in current_ids
    sync_network_snapshot()


def upsert_device_record(mac, network_bssid=None):
    """Track device metadata and relationships to networks."""
    if not mac:
        return None
    key = mac.upper()
    now_iso = datetime.now().isoformat()
    device = state.devices.get(key, {
        'mac': key,
        'networks': [],
        'first_seen': now_iso
    })
    device['last_seen'] = now_iso
    if network_bssid:
        network_bssid = network_bssid.upper()
        if network_bssid not in device['networks']:
            device['networks'].append(network_bssid)
    state.devices[key] = device
    return device


def reset_network_cache():
    """Clear cached network/device/hash data (used when interface changes)."""
    state.network_index = {}
    state.devices = {}
    state.hash_index = {}
    sync_network_snapshot()


def merge_network_payload(networks_payload):
    """Merge live scan payloads into the cached network/device graph."""
    if not networks_payload:
        return

    current_ids = set()
    now_iso = datetime.now().isoformat()

    for net in networks_payload:
        bssid = (net.get('bssid') or '').upper()
        if not bssid:
            continue
        current_ids.add(bssid)
        stations = [mac.upper() for mac in net.get('stations', [])]
        upsert_network_record(
            bssid,
            sync_after=False,
            essid=net.get('essid'),
            channel=net.get('channel'),
            power=net.get('power'),
            encryption=net.get('encryption', 'WPA2-PSK'),
            stations=stations,
            cached=False,
            last_seen=now_iso
        )

        for mac in stations:
            upsert_device_record(mac, bssid)

    mark_networks_cached(current_ids)


def find_bssid_by_essid(essid):
    """Best-effort lookup for a network BSSID via ESSID match."""
    if not essid:
        return None
    target = essid.lower()
    for record in state.network_index.values():
        if record.get('essid', '').lower() == target:
            return record['bssid']
    return None


def link_hash_to_network(hash_path, bssid, *, sync_after=True):
    """Associate a hash file with a known network."""
    if not bssid or not hash_path:
        return
    key = bssid.upper()
    record = state.network_index.get(key)
    if not record:
        record = upsert_network_record(bssid, sync_after=False)

    hash_ids = record.get('hash_ids', [])
    if hash_path not in hash_ids:
        hash_ids.append(hash_path)
        record['hash_ids'] = hash_ids
    status = record.setdefault('status', {'has_hash': False, 'cracked': False})
    status['has_hash'] = len(record['hash_ids']) > 0
    state.network_index[key] = record
    if sync_after:
        sync_network_snapshot()


def sync_hash_inventory():
    """Scan hashes/ directory and refresh the in-memory hash index."""
    hashes_dir = 'hashes'
    wordlists_dir = 'wordlists'
    os.makedirs(hashes_dir, exist_ok=True)
    os.makedirs(wordlists_dir, exist_ok=True)

    cwd = os.path.abspath(os.getcwd())
    active_hash_ids = set()

    for file_name in sorted(os.listdir(hashes_dir)):
        if not file_name.endswith('.hc22000'):
            continue
        full_path = os.path.join(hashes_dir, file_name)
        if not os.path.isfile(full_path):
            continue
        rel_path = os.path.relpath(full_path, cwd)
        active_hash_ids.add(rel_path)

        essid = extract_essid_from_filename(file_name)
        candidate_bssid = find_bssid_by_essid(essid)
        size_bytes = os.path.getsize(full_path)
        timestamp = datetime.fromtimestamp(os.path.getmtime(full_path)).isoformat()

        record = state.hash_index.get(rel_path, {
            'path': rel_path,
            'name': file_name,
            'essid': essid,
            'network_bssid': candidate_bssid,
            'hash_mode': '22000',
            'cracked': False,
            'cracked_password': None,
            'cracked_hex': None,
            'cracked_salt': None,
            'cracked_output': None,
            'cracked_at': None
        })

        record.update({
            'name': file_name,
            'essid': essid,
            'network_bssid': candidate_bssid,
            'size': size_bytes,
            'size_human': cracking.human_readable_size(size_bytes),
            'timestamp': timestamp
        })

        state.hash_index[rel_path] = record
        if candidate_bssid:
            link_hash_to_network(rel_path, candidate_bssid, sync_after=False)

    stale_ids = [hid for hid in state.hash_index.keys() if hid not in active_hash_ids]
    for hid in stale_ids:
        state.hash_index.pop(hid, None)
        for record in state.network_index.values():
            if hid in record.get('hash_ids', []):
                record['hash_ids'] = [existing for existing in record['hash_ids'] if existing != hid]
                record.setdefault('status', {'has_hash': False, 'cracked': False})
                record['status']['has_hash'] = len(record['hash_ids']) > 0

    sync_network_snapshot()
    return get_hashes_payload()


def parse_cracked_line(line):
    """Parse hashcat outfile line into components."""
    if not line:
        return None, None, None
    parts = line.strip().split(':')
    plain = parts[0] if parts else None
    hex_repr = parts[1] if len(parts) > 1 else None
    salt = parts[2] if len(parts) > 2 else None
    return plain, hex_repr, salt


def mark_hash_cracked(hash_path, output_file):
    """Update hash/device graph when a password is recovered."""
    if not hash_path:
        return

    rel_path = os.path.relpath(hash_path, os.getcwd()) if os.path.isabs(hash_path) else hash_path
    record = state.hash_index.get(rel_path)
    if not record:
        record = {
            'path': rel_path,
            'name': os.path.basename(rel_path),
            'hash_mode': '22000',
            'cracked': False
        }

    plain = hex_repr = salt = None
    if output_file and os.path.exists(output_file):
        try:
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as outfile:
                first_line = outfile.readline().strip()
                plain, hex_repr, salt = parse_cracked_line(first_line)
        except Exception as exc:
            log(f'Error reading cracked output {output_file}: {exc}', 'error')

    record.update({
        'cracked': True,
        'cracked_password': plain,
        'cracked_hex': hex_repr,
        'cracked_salt': salt,
        'cracked_output': output_file,
        'cracked_at': datetime.now().isoformat()
    })
    state.hash_index[rel_path] = record

    bssid = record.get('network_bssid')
    if bssid:
        key = bssid.upper()
        network = state.network_index.get(key)
        if network:
            status = network.setdefault('status', {'has_hash': True, 'cracked': False})
            status['cracked'] = True
            network['cracked_password'] = plain
            network['cracked_hex'] = hex_repr
            network['cracked_salt'] = salt
            network['cracked_hash_path'] = rel_path
            state.network_index[key] = network

    sync_network_snapshot()

# Logging function that sends to both console and web clients
_original_print = print  # Save original print at module level

def log(message, level='info'):
    """Send log message to web clients via SSE"""
    timestamp = datetime.now().strftime('%H:%M:%S')
    log_entry = {
        'timestamp': timestamp,
        'message': message,
        'level': level
    }
    state.log_queue.put(log_entry)
    _original_print(f"[{timestamp}] {message}")  # Use saved original print


def extract_essid_from_filename(file_name):
    """Best-effort ESSID extraction from capture/hash filenames."""
    essid = 'Unknown'
    try:
        base = file_name
        for suffix in ('.cap', '.hc22000', '-01'):
            base = base.replace(suffix, '')
        parts = base.split('_')
        if len(parts) >= 4 and parts[-2].isdigit() and parts[-1].isdigit():
            essid = '_'.join(parts[1:-2]) or 'Unknown'
        elif len(parts) >= 2:
            essid = parts[1] or 'Unknown'
    except Exception:
        pass
    return essid


def resolve_user_path(candidate_path, base_dir):
    """Resolve a relative path and verify it stays within base_dir."""
    base_abs = os.path.abspath(base_dir)
    target_abs = os.path.abspath(os.path.join(os.getcwd(), candidate_path))
    if not target_abs.startswith(base_abs):
        raise ValueError('Invalid path outside allowed directory')
    return target_abs

# Routes
@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/api/status')
def get_status():
    """Get current status and stats"""
    return jsonify({
        'scanning': state.scanning,
        'attacking': state.attacking,
        'cracking': state.cracking,
        'monitor_interface': state.monitor_interface,
        'stats': state.stats,
        'settings': state.settings,
        'current_network': state.current_network
    })

@app.route('/api/networks')
def get_networks():
    """Get list of discovered networks"""
    sync_hash_inventory()
    return jsonify({
        'networks': state.networks,
        'devices': get_devices_payload(),
        'hashes': get_hashes_payload(),
        'count': len(state.networks)
    })

@app.route('/api/captures')
def get_captures():
    """Get list of captured handshakes grouped by BSSID/ESSID"""
    captures = []
    
    try:
        sync_hash_inventory()
        # Ensure directories exist
        captures_dir = 'captures'
        hashes_dir = 'hashes'
        
        if not os.path.exists(captures_dir):
            os.makedirs(captures_dir)
        if not os.path.exists(hashes_dir):
            os.makedirs(hashes_dir)
        
        # Read all .cap files from captures directory
        cap_files = [f for f in os.listdir(captures_dir) if f.endswith('.cap')]
        
        # Group captures by ESSID (network)
        network_captures = {}
        
        for cap_file in cap_files:
            cap_path = os.path.join(captures_dir, cap_file)
            essid = extract_essid_from_filename(cap_file)
            
            # Look for corresponding hash file
            hash_file = None
            base_name = cap_file.replace('.cap', '').replace('capture_', '').replace('-01', '')
            possible_hash = f"{base_name}.hc22000"
            hash_path = os.path.join(hashes_dir, possible_hash)
            
            if os.path.exists(hash_path):
                hash_file = hash_path
            else:
                # Try to find any hash file with matching ESSID
                for hf in os.listdir(hashes_dir):
                    if hf.endswith('.hc22000') and essid in hf:
                        hash_file = os.path.join(hashes_dir, hf)
                        break
            
            # Get file timestamp
            timestamp = os.path.getmtime(cap_path)
            
            # Group by ESSID
            if essid not in network_captures:
                network_captures[essid] = []
            
            network_captures[essid].append({
                'file': cap_path,
                'hash': hash_file,
                'timestamp': timestamp,
                'timestamp_iso': datetime.fromtimestamp(timestamp).isoformat()
            })
        
        # Create consolidated list - one entry per network with all captures
        for essid, caps in network_captures.items():
            # Sort by timestamp (most recent first)
            caps.sort(key=lambda x: x['timestamp'], reverse=True)
            
            # Get most recent capture
            latest = caps[0]
            
            # Collect all file paths
            all_files = [c['file'] for c in caps]
            all_hashes = list(set([c['hash'] for c in caps if c['hash']]))  # Unique hashes
            
            captures.append({
                'essid': essid,
                'file': latest['file'],  # Most recent .cap file
                'hash': all_hashes[0] if all_hashes else None,  # First hash found
                'timestamp': latest['timestamp_iso'],
                'capture_count': len(caps),  # How many captures for this network
                'all_files': all_files,  # All capture files
                'all_hashes': all_hashes  # All hash files
            })
        
        # Sort by most recent capture
        captures.sort(key=lambda x: x['timestamp'], reverse=True)
        
    except Exception as e:
        _original_print(f"[!] Error reading captures: {e}")
    
    return jsonify({
        'captures': captures,
        'count': len(captures)
    })


@app.route('/api/cracking_assets')
def get_cracking_assets():
    """List available hash files and wordlists for cracking UI."""
    hashes = []
    wordlists = []
    try:
        hashes_dir = 'hashes'
        wordlists_dir = 'wordlists'
        os.makedirs(hashes_dir, exist_ok=True)
        os.makedirs(wordlists_dir, exist_ok=True)

        hashes = sorted(sync_hash_inventory(), key=lambda item: item.get('timestamp', ''), reverse=True)

        for file_name in sorted(os.listdir(wordlists_dir)):
            full_path = os.path.join(wordlists_dir, file_name)
            if not os.path.isfile(full_path):
                continue
            wordlists.append({
                'name': file_name,
                'path': os.path.relpath(full_path, os.path.abspath(os.getcwd())),
                'size': os.path.getsize(full_path),
                'size_human': cracking.human_readable_size(os.path.getsize(full_path))
            })
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500

    return jsonify({'hashes': hashes, 'wordlists': wordlists})

@app.route('/api/interfaces')
def get_interfaces():
    """Get list of available wireless interfaces"""
    try:
        interfaces = sniff.get_all_wireless_interfaces()
        return jsonify({
            'interfaces': interfaces,
            'count': len(interfaces)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings', methods=['GET', 'POST'])
def handle_settings():
    """Get or update settings"""
    if request.method == 'POST':
        data = request.json
        old_interface = state.settings.get('interface')
        
        if 'band' in data:
            state.settings['band'] = data['band']
        if 'interface' in data:
            new_interface = data['interface']
            
            # If interface changed and we have an active monitor interface, clean it up
            if new_interface != old_interface and state.monitor_interface:
                log(f'Interface changed from {old_interface} to {new_interface}, cleaning up...', 'warning')
                try:
                    # Stop any active operations
                    state.scanning = False
                    state.attacking = False
                    
                    # Clean up old monitor interface
                    subprocess.run("pkill -9 airodump-ng", shell=True, stderr=subprocess.DEVNULL)
                    subprocess.run("pkill -9 aireplay-ng", shell=True, stderr=subprocess.DEVNULL)
                    sniff.cleanup_processes()
                    
                    state.monitor_interface = None
                    reset_network_cache()
                    state.stats['networks_scanned'] = 0
                    state.stats['networks_attacked'] = 0
                    
                    log('Previous interface cleaned up, ready for new scan', 'success')
                except Exception as e:
                    log(f'Cleanup error: {e}', 'error')
            
            state.settings['interface'] = new_interface
        
        return jsonify({'success': True, 'settings': state.settings})
    return jsonify(state.settings)

@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    """Start network scanning"""
    if state.scanning:
        return jsonify({'error': 'Already scanning'}), 400
    
    if state.attacking:
        return jsonify({'error': 'Cannot scan while attacking. Stop current operation first.'}), 400
    
    # Start scan in background thread
    thread = threading.Thread(target=run_scan_worker)
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': 'Scan started'})

@app.route('/api/stop_scan', methods=['POST'])
def stop_scan():
    """Stop current operation immediately"""
    log('STOP requested - terminating all operations', 'warning')
    
    # Set flags immediately
    state.scanning = False
    state.attacking = False
    state.cracking = False
    sniff.graceful_shutdown = True
    
    # Kill all processes immediately
    try:
        subprocess.run("pkill -9 airodump-ng", shell=True, stderr=subprocess.DEVNULL)
        subprocess.run("pkill -9 aireplay-ng", shell=True, stderr=subprocess.DEVNULL)
        subprocess.run("pkill -9 hashcat", shell=True, stderr=subprocess.DEVNULL)
        log('All capture/attack processes terminated', 'info')
    except Exception as e:
        log(f'Error killing processes: {e}', 'error')
    
    # Reset operation status
    state.stats['current_operation'] = 'Idle'
    
    return jsonify({'success': True, 'message': 'Operations stopped'})

@app.route('/api/attack_network', methods=['POST'])
def attack_network():
    """Attack a specific network"""
    data = request.json
    bssid = data.get('bssid')
    
    if not bssid:
        return jsonify({'error': 'BSSID required'}), 400
    
    if state.attacking:
        return jsonify({'error': 'Already attacking a network'}), 400
    
    if state.scanning:
        return jsonify({'error': 'Cannot attack while scanning. Stop scan first.'}), 400
    
    # Try to find network in normalized cache first
    network = find_network_record(bssid)
    
    # If not found, accept network data from client (cached network)
    if not network:
        # Client should send full network data for cached networks
        if 'network' in data:
            network = data['network']
            log(f'Using cached network data for {network.get("essid", "Unknown")}', 'info')
            upsert_network_record(
                network.get('bssid'),
                essid=network.get('essid'),
                channel=network.get('channel'),
                power=network.get('power'),
                encryption=network.get('encryption', 'WPA2-PSK'),
                cached=True
            )
        else:
            return jsonify({'error': 'Network not found in current scan. Please provide network details.'}), 404
    else:
        status = network.get('status', {})
        if status.get('cracked'):
            return jsonify({'error': 'This network password is already cracked. Skipping attack.'}), 400
    
    # Validate required fields
    if not network.get('channel'):
        return jsonify({'error': 'Network channel required'}), 400
    
    # Start attack in background
    thread = threading.Thread(target=run_attack_worker, args=(network,))
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': f'Attacking {network["essid"]}'})

@app.route('/api/batch_attack', methods=['POST'])
def batch_attack():
    """Start batch attack on multiple networks"""
    data = request.get_json()
    network_list = data.get('networks', [])
    
    if not network_list:
        return jsonify({'error': 'No networks provided'}), 400
    
    if state.scanning:
        return jsonify({'error': 'Cannot attack while scanning. Stop scan first.'}), 400
    
    if state.attacking:
        return jsonify({'error': 'Already attacking. Stop current attack first.'}), 400
    
    skipped = []
    filtered_list = []
    for item in network_list:
        record = find_network_record(item.get('bssid')) if item else None
        if record and record.get('status', {}).get('cracked'):
            skipped.append(record.get('essid') or record.get('bssid'))
            continue
        filtered_list.append(item)

    if not filtered_list:
        return jsonify({'error': 'All selected networks already have cracked passwords'}), 400

    if skipped:
        log(f'Skipping cracked networks: {", ".join(skipped)}', 'warning')

    log(f'Starting batch attack on {len(filtered_list)} network(s)...', 'success')
    
    # Start batch attack in background
    thread = threading.Thread(target=run_batch_attack_worker, args=(filtered_list,))
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': f'Batch attacking {len(filtered_list)} networks', 'skipped': skipped})


@app.route('/api/crack_hashes', methods=['POST'])
def crack_hashes():
    """Start sequential cracking of selected hash files."""
    data = request.get_json() or {}
    task_items = data.get('tasks', [])

    if not task_items:
        return jsonify({'error': 'No tasks provided'}), 400

    if state.cracking:
        return jsonify({'error': 'Cracking already in progress'}), 400

    normalized_tasks = []
    try:
        for task in task_items:
            hash_path = task.get('hash')
            wordlist_path = task.get('wordlist')
            if not hash_path or not wordlist_path:
                raise ValueError('Task missing hash or wordlist path')
            resolved_hash = resolve_user_path(hash_path, 'hashes')
            resolved_wordlist = resolve_user_path(wordlist_path, 'wordlists')
            rel_hash = os.path.relpath(resolved_hash, os.getcwd())
            hash_record = state.hash_index.get(rel_hash)
            if hash_record and hash_record.get('cracked'):
                raise ValueError(f"Hash already cracked: {hash_record.get('name', rel_hash)}")
            normalized_tasks.append({
                'hash': resolved_hash,
                'hash_rel': rel_hash,
                'wordlist': resolved_wordlist,
                'hash_name': os.path.basename(resolved_hash),
                'wordlist_name': os.path.basename(resolved_wordlist)
            })
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    log(f'Starting cracking queue for {len(normalized_tasks)} hash file(s)...', 'success')
    thread = threading.Thread(target=run_crack_worker, args=(normalized_tasks,))
    thread.daemon = True
    thread.start()

    return jsonify({'success': True, 'message': f'Cracking {len(normalized_tasks)} hash file(s)'})

@app.route('/api/stream')
def stream():
    """Server-Sent Events stream for real-time updates"""
    def event_stream():
        while True:
            try:
                # Send log messages
                if not state.log_queue.empty():
                    log_entry = state.log_queue.get()
                    yield f"data: {json.dumps({'type': 'log', 'data': log_entry})}\n\n"
                
                # Send periodic status updates
                yield f"data: {json.dumps({'type': 'status', 'data': state.stats})}\n\n"
                time.sleep(0.5)
            except GeneratorExit:
                break
    
    return Response(event_stream(), mimetype='text/event-stream')

@app.route('/api/cleanup', methods=['POST'])
def cleanup():
    """Clean up monitor mode and restore network"""
    try:
        log('Cleaning up and restoring network...', 'info')
        sniff.cleanup_processes()
        subprocess.run("pkill -9 hashcat", shell=True, stderr=subprocess.DEVNULL)
        state.monitor_interface = None
        log('Cleanup complete', 'success')
        return jsonify({'success': True})
    except Exception as e:
        log(f'Cleanup error: {str(e)}', 'error')
        return jsonify({'error': str(e)}), 500

# Worker functions (these will call the actual sniff.py functions)
def run_crack_worker(task_list):
    """Background worker for cracking hash files sequentially."""
    if not task_list:
        return

    state.cracking = True
    state.crack_queue = task_list
    total = len(task_list)

    def update_operation(message):
        if not state.scanning and not state.attacking:
            state.stats['current_operation'] = message

    try:
        for idx, task in enumerate(task_list, 1):
            if not state.cracking:
                log('Cracking cancelled by user request', 'warning')
                break

            state.current_crack = task
            update_operation(f'Cracking [{idx}/{total}] {task["hash_name"]}')
            log(f'[{idx}/{total}] Cracking {task["hash_name"]} with {task["wordlist_name"]}...', 'info')

            def forward_log(message, prefix=task['hash_name']):
                log(f'{prefix}: {message}', 'info')

            try:
                result = cracking.run_cracker(
                    task['hash'],
                    task['wordlist'],
                    log_callback=forward_log,
                )
                if result.get('cracked'):
                    state.stats['hashes_cracked'] += 1
                    mark_hash_cracked(task.get('hash'), result.get('output_file'))
                    log(
                        f'[{idx}/{total}] Hash cracked! Saved to {result.get("output_file")}',
                        'success'
                    )
                else:
                    log(
                        f'[{idx}/{total}] No hits (exit {result.get("exit_code")})',
                        'warning'
                    )
            except Exception as exc:
                log(f'[{idx}/{total}] Cracking error: {exc}', 'error')
                import traceback
                traceback.print_exc()

        log('Cracking queue finished.', 'success')
    finally:
        state.cracking = False
        state.current_crack = None
        state.crack_queue = []
        if not state.scanning and not state.attacking:
            state.stats['current_operation'] = 'Idle'

def run_scan_worker():
    """Background worker for scanning"""
    # Reset graceful_shutdown flag for new operation
    sniff.graceful_shutdown = False
    
    state.scanning = True
    state.stats['scan_start_time'] = datetime.now().isoformat()
    state.stats['current_operation'] = 'Scanning for networks...'
    csv_file = None
    scan_proc = None
    
    log('Starting network scan...', 'info')
    log(f'Band: {state.settings["band"]}', 'info')
    
    def publish_networks(parsed_networks, elapsed=None):
        """Update shared state with parsed networks and station counts."""
        if not parsed_networks:
            mark_networks_cached(set())
            state.stats['networks_scanned'] = 0
            return
        
        station_counts = sniff.get_station_counts(csv_file) if csv_file and os.path.exists(csv_file) else {}
        
        # Get all stations mapped by BSSID
        stations_by_bssid = sniff.get_all_stations_by_bssid(csv_file) if csv_file and os.path.exists(csv_file) else {}
        
        networks_payload = []
        for net in parsed_networks:
            bssid_upper = net['bssid'].upper()
            clients = station_counts.get(bssid_upper, 0)
            stations = stations_by_bssid.get(bssid_upper, [])
            
            networks_payload.append({
                'bssid': net['bssid'],
                'essid': net['essid'],
                'channel': net['channel'],
                'power': net.get('power', '-50'),
                'encryption': 'WPA2-PSK',
                'has_clients': len(stations) > 0,
                'clients': len(stations),
                'stations': stations  # Include actual station MAC addresses
            })
        merge_network_payload(networks_payload)
        state.stats['networks_scanned'] = len(networks_payload)
        if elapsed is not None:
            log(f'Found {len(networks_payload)} networks ({elapsed}s elapsed)...', 'info')
        else:
            log(f'Found {len(networks_payload)} networks total', 'info')
    
    try:
        # Set global settings from web UI
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
            state.settings['interface'] = interface
            if len(interfaces) > 1:
                log(f'Multiple interfaces found, using {interface}. Change in settings if needed.', 'warning')
        
        log(f'Using interface: {interface}', 'info')
        
        # Start monitor mode
        log('Starting monitor mode...', 'info')
        log('Stopping NetworkManager and wpa_supplicant...', 'info')
        mon_interface = sniff.start_monitor_mode(interface)
        state.monitor_interface = mon_interface
        log(f'Monitor mode enabled: {mon_interface}', 'success')
        
        # Scan for networks
        scan_duration = 120  # 2 minutes for deep scan
        log(f'Scanning for {scan_duration}s to detect networks and clients...', 'info')
        
        # Start ONE continuous scan process
        csv_file, scan_proc = sniff.scan_networks(mon_interface, duration=scan_duration, background=True)
        
        if not csv_file:
            log('Failed to start scan', 'error')
            return
        
        # Monitor the scan and update periodically
        scan_start = time.time()
        last_update = 0
        
        while time.time() - scan_start < scan_duration:
            # Check if user stopped scanning - check frequently
            if not state.scanning:
                log('Scan stopped by user', 'warning')
                if scan_proc:
                    sniff.terminate_process(scan_proc, name='airodump-ng scan', force=True)
                    scan_proc = None
                # Kill the scan process immediately as a fallback
                subprocess.run("pkill -9 airodump-ng", shell=True, stderr=subprocess.DEVNULL)
                break
            
            elapsed = int(time.time() - scan_start)
            
            # Update every 15 seconds
            if elapsed - last_update >= 15:
                last_update = elapsed
                
                if os.path.exists(csv_file):
                    # Parse and update networks in real-time
                    networks = sniff.parse_networks(csv_file)
                    publish_networks(networks, elapsed=elapsed)
            
            time.sleep(1)  # Check every second
        
        # Stop background scan now that duration elapsed
        if scan_proc:
            sniff.terminate_process(scan_proc, name='airodump-ng scan')
            scan_proc = None
        
        if not csv_file or not os.path.exists(csv_file):
            log('Failed to create scan file', 'error')
            return
        
        # Parse networks
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
        csv_file = None
        state.scanning = False
        state.stats['current_operation'] = 'Idle'

def run_attack_worker(network):
    """Background worker for attacking a network"""
    # Reset graceful_shutdown flag for new operation
    sniff.graceful_shutdown = False
    
    state.attacking = True
    state.current_network = network
    state.stats['current_operation'] = f'Attacking {network["essid"]}...'
    
    log(f'Targeting {network["essid"]} ({network["bssid"]}) on channel {network["channel"]}', 'info')
    
    try:
        # Check if already stopped before starting
        if not state.attacking:
            log('Attack cancelled before start', 'warning')
            return
        
        # Ensure monitor mode is active
        if not state.monitor_interface:
            log('Monitor interface not active, starting monitor mode...', 'warning')
            
            # Get interface from settings or auto-detect
            if state.settings['interface']:
                interface = state.settings['interface']
                log(f'Using configured interface: {interface}', 'info')
            else:
                log('Auto-detecting wireless interface...', 'info')
                interfaces = sniff.get_all_wireless_interfaces()
                if not interfaces:
                    log('No wireless interface found', 'error')
                    return
                interface = interfaces[0]
                state.settings['interface'] = interface
            
            # Start monitor mode
            log('Starting monitor mode...', 'info')
            log('Stopping NetworkManager and wpa_supplicant...', 'info')
            mon_interface = sniff.start_monitor_mode(interface)
            state.monitor_interface = mon_interface
            log(f'Monitor mode enabled: {mon_interface}', 'success')
        
        # Prepare network dict in format expected by capture_handshake
        target_net = {
            'bssid': network['bssid'],
            'essid': network['essid'],
            'channel': network['channel'],
            'power': network.get('power', '-50'),
            'encryption': network.get('encryption', 'WPA2-PSK'),
            'clients': network.get('clients', 0),
            'has_clients': network.get('has_clients', False),
            'stations': network.get('stations', [])  # CRITICAL: Include station MAC addresses from scan
        }
        
        # Track captured handshakes before attack
        before_count = len(sniff.captured_handshakes)
        
        # Call the actual capture function from sniff.py
        log('Starting handshake capture...', 'info')
        
        # Temporarily redirect prints to log function
        def log_print(*args, **kwargs):
            message = ' '.join(str(arg) for arg in args)
            # Parse log level from message
            if '[+]' in message:
                level = 'success'
            elif '[!]' in message:
                level = 'warning'
            elif '[*]' in message:
                level = 'info'
            else:
                level = 'info'
            # Clean up message
            message = message.replace('[+]', '').replace('[!]', '').replace('[*]', '').strip()
            
            # Send to log queue without calling log() to avoid recursion
            timestamp = datetime.now().strftime('%H:%M:%S')
            log_entry = {
                'timestamp': timestamp,
                'message': message,
                'level': level
            }
            state.log_queue.put(log_entry)
            _original_print(f"[{timestamp}] {message}")
        
        import builtins
        old_print = builtins.print
        builtins.print = log_print
        
        try:
            updated_network_info = sniff.capture_handshake(state.monitor_interface, target_net)
            
            # Update cached network metadata with the fresh capture info
            if updated_network_info and updated_network_info.get('bssid'):
                stations = [mac.upper() for mac in updated_network_info.get('stations', [])]
                upsert_network_record(
                    updated_network_info['bssid'],
                    essid=updated_network_info.get('essid'),
                    channel=updated_network_info.get('channel'),
                    power=updated_network_info.get('power'),
                    encryption=updated_network_info.get('encryption'),
                    stations=stations,
                    cached=False
                )
                log(f'Network info refreshed: {updated_network_info.get("clients", 0)} clients, {updated_network_info.get("power", "-50")} dBm', 'info')
        finally:
            builtins.print = old_print
        
        # Check if handshake was captured
        after_count = len(sniff.captured_handshakes)
        if after_count > before_count:
            # Update stats counter
            state.stats['handshakes_captured'] += 1
            log(f'Handshake captured successfully!', 'success')
            sync_hash_inventory()
        else:
            log('No handshake detected', 'warning')
        
        state.stats['networks_attacked'] += 1
        
    except Exception as e:
        log(f'Attack error: {str(e)}', 'error')
        import traceback
        traceback.print_exc()
    finally:
        state.attacking = False
        state.current_network = None
        state.stats['current_operation'] = 'Idle'

def run_batch_attack_worker(network_list):
    """Background worker for batch attacking multiple networks"""
    sniff.graceful_shutdown = False
    state.attacking = True
    
    total = len(network_list)
    
    for i, network in enumerate(network_list, 1):
        # Check if user stopped the batch
        if not state.attacking:
            log(f'Batch attack cancelled. Processed {i-1}/{total} networks.', 'warning')
            break
        
        state.current_network = network
        state.stats['current_operation'] = f'Batch [{i}/{total}]: {network["essid"]}'
        
        log(f'[{i}/{total}] Attacking {network["essid"]} ({network["bssid"]})...', 'info')
        
        try:
            # Ensure monitor mode is active
            if not state.monitor_interface:
                log('Monitor interface not active, starting monitor mode...', 'warning')
                
                if state.settings['interface']:
                    interface = state.settings['interface']
                else:
                    interfaces = sniff.get_all_wireless_interfaces()
                    if not interfaces:
                        log('No wireless interface found', 'error')
                        break
                    interface = interfaces[0]
                
                mon_interface = sniff.start_monitor_mode(interface)
                state.monitor_interface = mon_interface
                log(f'Monitor mode enabled: {mon_interface}', 'success')
            
            # Prepare network
            target_net = {
                'bssid': network['bssid'],
                'essid': network['essid'],
                'channel': network['channel'],
                'power': network.get('power', '-50'),
                'encryption': network.get('encryption', 'WPA2-PSK'),
                'clients': network.get('clients', 0),
                'has_clients': network.get('has_clients', False),
                'stations': network.get('stations', [])
            }
            
            before_count = len(sniff.captured_handshakes)
            
            # Redirect prints
            def log_print(*args, **kwargs):
                message = ' '.join(str(arg) for arg in args)
                if '[+]' in message:
                    level = 'success'
                elif '[!]' in message:
                    level = 'warning'
                else:
                    level = 'info'
                message = message.replace('[+]', '').replace('[!]', '').replace('[*]', '').strip()
                
                timestamp = datetime.now().strftime('%H:%M:%S')
                log_entry = {
                    'timestamp': timestamp,
                    'message': message,
                    'level': level
                }
                state.log_queue.put(log_entry)
                _original_print(f"[{timestamp}] {message}")
            
            import builtins
            old_print = builtins.print
            builtins.print = log_print
            
            try:
                updated_network_info = sniff.capture_handshake(state.monitor_interface, target_net)
                
                if updated_network_info and updated_network_info.get('bssid'):
                    stations = [mac.upper() for mac in updated_network_info.get('stations', [])]
                    upsert_network_record(
                        updated_network_info['bssid'],
                        essid=updated_network_info.get('essid'),
                        channel=updated_network_info.get('channel'),
                        power=updated_network_info.get('power'),
                        encryption=updated_network_info.get('encryption'),
                        stations=stations,
                        cached=False
                    )
                
                after_count = len(sniff.captured_handshakes)
                if after_count > before_count:
                    state.stats['handshakes_captured'] += 1
                    log(f'[{i}/{total}] Handshake captured for {network["essid"]}!', 'success')
                    sync_hash_inventory()
                else:
                    log(f'[{i}/{total}] No handshake for {network["essid"]}', 'warning')
            finally:
                builtins.print = old_print
            
            state.stats['networks_attacked'] += 1
            
        except Exception as e:
            log(f'[{i}/{total}] Attack error: {str(e)}', 'error')
            import traceback
            traceback.print_exc()
    
    # Batch complete
    state.attacking = False
    state.current_network = None
    state.stats['current_operation'] = 'Idle'
    log(f'Batch attack completed. Processed {total} network(s).', 'success')

if __name__ == '__main__':
    if os.geteuid() != 0:
        _original_print("[!] This application must be run as root")
        _original_print("Usage: sudo python3 sniff_web.py")
        sys.exit(1)
    
    # Handle cleanup on exit
    import signal
    
    def handle_exit(signum=None, frame=None):
        _original_print("\n[*] Shutting down web server...")
        _original_print("[*] Cleaning up monitor mode and processes...")
        
        # Stop any active operations
        state.scanning = False
        state.attacking = False
        
        # Clean up wireless processes
        try:
            subprocess.run("pkill -9 airodump-ng", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run("pkill -9 aireplay-ng", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run("pkill -9 hashcat", shell=True, stderr=subprocess.DEVNULL)
            sniff.cleanup_processes()
            _original_print("[+] Cleanup complete")
        except Exception as e:
            _original_print(f"[!] Cleanup error: {e}")
        
        _original_print("[*] Goodbye!")
        sys.exit(0)
    
    # Register signal handlers
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)
    
    _original_print("="*60)
    _original_print("Memento - WiFi Handshake Capture Tool")
    _original_print("="*60)
    _original_print("Starting web server...")
    _original_print()
    _original_print("  Local:    http://localhost:5000")
    _original_print("  Network:  http://<your-ip>:5000")
    _original_print()
    _original_print("Press CTRL+C to stop")
    _original_print("="*60)
    _original_print()
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        handle_exit()
    except Exception as e:
        _original_print(f"[!] Server error: {e}")
        handle_exit()
