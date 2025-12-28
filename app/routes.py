"""
HTTP API routes.

Clean RESTful endpoints with consistent error handling.
Separated from business logic and state management.
"""

from __future__ import annotations
import json
import os
import subprocess
import threading
import time
from datetime import datetime
from typing import Tuple, Any

from flask import Blueprint, jsonify, request, Response

from .state import get_state
from .storage import get_storage
from .services import HashService, CaptureService, NetworkService
from .logging import log, set_log_queue
from .workers import run_scan_worker, run_attack_worker, run_batch_attack_worker, run_crack_worker, run_vigilance_worker

import memento as sniff


# Create blueprint
api = Blueprint('api', __name__, url_prefix='/api')


def error_response(message: str, status: int = 400) -> Tuple[Any, int]:
    """Create a consistent error response."""
    return jsonify({'error': message, 'success': False}), status


def success_response(message: str = None, **data) -> Any:
    """Create a consistent success response."""
    response = {'success': True}
    if message:
        response['message'] = message
    response.update(data)
    return jsonify(response)


# ─────────────────────────────────────────────────────────────
# Status & Info
# ─────────────────────────────────────────────────────────────

@api.route('/status')
def get_status():
    """Get current application status."""
    state = get_state()
    return jsonify(state.get_status_dict())


@api.route('/networks')
def get_networks():
    """Get discovered networks with devices and hashes."""
    return jsonify(NetworkService.get_networks_response())


@api.route('/captures')
def get_captures():
    """Get captured handshakes grouped by network."""
    try:
        captures = CaptureService.get_captures()
        return jsonify({
            'captures': captures,
            'count': len(captures),
        })
    except Exception as e:
        return error_response(str(e), 500)


@api.route('/cracking_assets')
def get_cracking_assets():
    """Get available hashes and wordlists for cracking."""
    try:
        hashes = sorted(
            HashService.sync_inventory(),
            key=lambda h: h.get('timestamp', ''),
            reverse=True
        )
        wordlists = HashService.get_wordlists()
        return jsonify({
            'hashes': hashes,
            'wordlists': wordlists,
        })
    except Exception as e:
        return error_response(str(e), 500)


@api.route('/interfaces')
def get_interfaces():
    """Get available wireless interfaces."""
    try:
        interfaces = sniff.get_all_wireless_interfaces()
        return jsonify({
            'interfaces': interfaces,
            'count': len(interfaces),
        })
    except Exception as e:
        return error_response(str(e), 500)


# ─────────────────────────────────────────────────────────────
# Settings
# ─────────────────────────────────────────────────────────────

@api.route('/settings', methods=['GET', 'POST'])
def handle_settings():
    """Get or update settings."""
    state = get_state()
    storage = get_storage()
    
    if request.method == 'POST':
        data = request.json or {}
        old_interface = state.settings.get('interface')
        
        if 'band' in data:
            storage.update_settings(band=data['band'])
        
        if 'deauth_count' in data:
            count = int(data['deauth_count'])
            if count in [8, 16, 32, 64]:
                storage.update_settings(deauth_count=count)
                # Update sniff module directly
                sniff.PYTHON_DEAUTH_COUNT = count
                pressure_names = {8: 'Gentle', 16: 'Firm', 32: 'Heavy', 64: 'Brutal'}
                log(f'Pressure set to {pressure_names.get(count, count)} ({count} packets)', 'info')
        
        if 'interface' in data:
            new_interface = data['interface']
            
            # Clean up if interface changed
            if new_interface != old_interface and state.monitor_interface:
                log(f'Interface changed from {old_interface} to {new_interface}, cleaning up...', 'warning')
                try:
                    state.scanning = False
                    state.attacking = False
                    subprocess.run("pkill -9 airodump-ng", shell=True, stderr=subprocess.DEVNULL)
                    subprocess.run("pkill -9 aireplay-ng", shell=True, stderr=subprocess.DEVNULL)
                    sniff.cleanup_processes()
                    state.monitor_interface = None
                    state.reset_cache()
                    log('Previous interface cleaned up, ready for new scan', 'success')
                except Exception as e:
                    log(f'Cleanup error: {e}', 'error')
            
            storage.update_settings(interface=new_interface)
        
        storage.flush()
        return success_response(settings=dict(state.settings))
    
    return jsonify(dict(state.settings))


# ─────────────────────────────────────────────────────────────
# Scanning
# ─────────────────────────────────────────────────────────────

@api.route('/start_scan', methods=['POST'])
def start_scan():
    """Start network scanning."""
    state = get_state()
    
    if state.scanning:
        return error_response('Already scanning')
    
    if state.attacking:
        return error_response('Cannot scan while attacking. Stop current operation first.')
    
    thread = threading.Thread(target=run_scan_worker)
    thread.daemon = True
    thread.start()
    
    return success_response('Scan started')


@api.route('/stop_scan', methods=['POST'])
def stop_scan():
    """Stop all operations."""
    state = get_state()
    storage = get_storage()
    
    log('STOP requested - terminating all operations', 'warning')
    
    state.scanning = False
    state.attacking = False
    state.cracking = False
    state.vigilant = False
    sniff.graceful_shutdown = True
    
    try:
        subprocess.run("pkill -9 airodump-ng", shell=True, stderr=subprocess.DEVNULL)
        subprocess.run("pkill -9 aireplay-ng", shell=True, stderr=subprocess.DEVNULL)
        subprocess.run("pkill -9 hashcat", shell=True, stderr=subprocess.DEVNULL)
        log('All processes terminated', 'info')
    except Exception as e:
        log(f'Error killing processes: {e}', 'error')
    
    storage.update_stats(current_operation='Idle')
    
    return success_response('Operations stopped')


@api.route('/vigilance', methods=['POST'])
def toggle_vigilance():
    """Start or stop Vigilance Mode (constant passive scanning)."""
    state = get_state()
    data = request.json or {}
    
    action = data.get('action', 'toggle')
    
    if action == 'start' or (action == 'toggle' and not state.vigilant):
        if state.vigilant:
            return error_response('Vigilance already active')
        if state.scanning:
            return error_response('Cannot start vigilance while scanning')
        if state.attacking:
            return error_response('Cannot start vigilance while attacking')
        
        thread = threading.Thread(target=run_vigilance_worker)
        thread.daemon = True
        thread.start()
        
        return success_response('Vigilance Mode activated')
    else:
        if not state.vigilant:
            return error_response('Vigilance not active')
        state.vigilant = False
        return success_response('Vigilance Mode stopping...')


@api.route('/rolling', methods=['POST'])
def toggle_rolling():
    """Toggle rolling cracker (auto-solve mode)."""
    from .workers import run_rolling_cracker_worker
    
    state = get_state()
    data = request.json or {}
    
    action = data.get('action', 'toggle')
    wordlist_order = data.get('wordlist_order', [])  # Optional ordered wordlist names
    
    if action == 'start' or (action == 'toggle' and not state.rolling_cracking):
        if state.rolling_cracking:
            return error_response('Rolling Cracker already active')
        if state.cracking:
            return error_response('Cannot start auto-solve while manual cracking')
        
        # Store wordlist order in state for the worker to use
        state.wordlist_order = wordlist_order
        
        thread = threading.Thread(target=run_rolling_cracker_worker)
        thread.daemon = True
        thread.start()
        
        return success_response('Rolling Cracker activated')
    else:
        if not state.rolling_cracking:
            return error_response('Rolling Cracker not active')
        state.rolling_cracking = False
        return success_response('Rolling Cracker stopping...')


@api.route('/network/<bssid>/cracked', methods=['POST'])
def set_network_cracked(bssid):
    """Toggle manual cracked status for a network."""
    storage = get_storage()
    data = request.json or {}
    
    cracked = data.get('cracked', False)
    
    network = storage.get_network(bssid)
    if not network:
        return error_response('Network not found', 404)
    
    storage.upsert_network(bssid, manual_cracked=cracked)
    storage.flush()
    
    status = 'marked as solved' if cracked else 'reopened'
    log(f'{network.get("essid", bssid)} {status}', 'info')
    
    return success_response(f'Network {status}')


# ─────────────────────────────────────────────────────────────
# Attacking
# ─────────────────────────────────────────────────────────────

@api.route('/attack_network', methods=['POST'])
def attack_network():
    """Attack a specific network."""
    state = get_state()
    storage = get_storage()
    data = request.json or {}
    
    bssid = data.get('bssid')
    if not bssid:
        return error_response('BSSID required')
    
    if state.attacking:
        return error_response('Already attacking a network')
    
    if state.scanning:
        return error_response('Cannot attack while scanning. Stop scan first.')
    
    # Find network
    network = storage.get_network(bssid)
    
    if not network:
        if 'network' in data:
            network = data['network']
            log(f'Using cached network data for {network.get("essid", "Unknown")}', 'info')
            storage.upsert_network(
                network.get('bssid'),
                essid=network.get('essid'),
                channel=network.get('channel'),
                power=network.get('power'),
                encryption=network.get('encryption', 'WPA2-PSK'),
                cached=True,
            )
            network = storage.get_network(bssid)
        else:
            return error_response('Network not found. Please provide network details.', 404)
    
    # Check if already cracked
    if network.get('status', {}).get('cracked'):
        return error_response('This network is already cracked. Skipping attack.')
    
    if not network.get('channel'):
        return error_response('Network channel required')
    
    thread = threading.Thread(target=run_attack_worker, args=(dict(network),))
    thread.daemon = True
    thread.start()
    
    return success_response(f'Attacking {network["essid"]}')


@api.route('/batch_attack', methods=['POST'])
def batch_attack():
    """Start batch attack on multiple networks."""
    state = get_state()
    storage = get_storage()
    data = request.json or {}
    
    network_list = data.get('networks', [])
    if not network_list:
        return error_response('No networks provided')
    
    if state.scanning:
        return error_response('Cannot attack while scanning. Stop scan first.')
    
    if state.attacking:
        return error_response('Already attacking. Stop current attack first.')
    
    # Filter out cracked networks
    skipped = []
    filtered = []
    for item in network_list:
        record = storage.get_network(item.get('bssid')) if item else None
        if record and record.get('status', {}).get('cracked'):
            skipped.append(record.get('essid') or record.get('bssid'))
            continue
        filtered.append(item)
    
    if not filtered:
        return error_response('All selected networks already have cracked passwords')
    
    if skipped:
        log(f'Skipping cracked networks: {", ".join(skipped)}', 'warning')
    
    log(f'Starting batch attack on {len(filtered)} network(s)...', 'success')
    
    thread = threading.Thread(target=run_batch_attack_worker, args=(filtered,))
    thread.daemon = True
    thread.start()
    
    return success_response(f'Batch attacking {len(filtered)} networks', skipped=skipped)


# ─────────────────────────────────────────────────────────────
# Cracking
# ─────────────────────────────────────────────────────────────

@api.route('/crack_hashes', methods=['POST'])
def crack_hashes():
    """Start cracking selected hashes."""
    state = get_state()
    storage = get_storage()
    data = request.json or {}
    
    task_items = data.get('tasks', [])
    if not task_items:
        return error_response('No tasks provided')
    
    if state.cracking:
        return error_response('Cracking already in progress')
    
    normalized_tasks = []
    try:
        for task in task_items:
            hash_path = task.get('hash')
            mask_type = task.get('mask_type')  # e.g., '__MASK_8DIGIT__'
            wordlist_path = task.get('wordlist')
            
            if not hash_path:
                raise ValueError('Task missing hash path')
            
            # Either mask_type OR wordlist, but at least one
            if not mask_type and not wordlist_path:
                raise ValueError('Task missing wordlist or mask type')
            
            resolved_hash = HashService.resolve_path(hash_path, 'hashes')
            rel_hash = os.path.relpath(resolved_hash, os.getcwd())
            
            # Check if already cracked
            hash_record = storage.get_hash(rel_hash)
            if hash_record and hash_record.get('cracked'):
                raise ValueError(f"Hash already cracked: {hash_record.get('name', rel_hash)}")
            
            if mask_type:
                # Mask attack - no wordlist needed
                normalized_tasks.append({
                    'hash': resolved_hash,
                    'hash_rel': rel_hash,
                    'hash_name': os.path.basename(resolved_hash),
                    'mask_type': mask_type,  # e.g., '__MASK_8DIGIT__'
                })
            else:
                # Regular wordlist attack
                resolved_wordlist = HashService.resolve_path(wordlist_path, 'wordlists')
                normalized_tasks.append({
                    'hash': resolved_hash,
                    'hash_rel': rel_hash,
                    'wordlist': resolved_wordlist,
                    'hash_name': os.path.basename(resolved_hash),
                    'wordlist_name': os.path.basename(resolved_wordlist),
                    'rule_file': task.get('rule_file'),
                })
    except ValueError as e:
        return error_response(str(e))
    
    log(f'Starting cracking queue for {len(normalized_tasks)} hash file(s)...', 'success')
    
    thread = threading.Thread(target=run_crack_worker, args=(normalized_tasks,))
    thread.daemon = True
    thread.start()
    
    return success_response(f'Cracking {len(normalized_tasks)} hash file(s)')


@api.route('/delete_hash', methods=['POST'])
def delete_hash():
    """Delete a hash file."""
    storage = get_storage()
    data = request.json or {}
    
    hash_path = data.get('hash_path')
    if not hash_path:
        return error_response('Hash path required')
    
    try:
        # Resolve to absolute path
        resolved = HashService.resolve_path(hash_path, 'hashes')
        rel_path = os.path.relpath(resolved, os.getcwd())
        
        # Check it exists
        if not os.path.exists(resolved):
            return error_response(f'Hash file not found: {hash_path}', 404)
        
        # Get hash info before deletion
        hash_record = storage.get_hash(rel_path)
        hash_name = hash_record.get('name', os.path.basename(resolved)) if hash_record else os.path.basename(resolved)
        
        # Delete the file
        os.remove(resolved)
        
        # Remove from storage
        storage.remove_hash(rel_path)
        storage.flush()
        
        log(f'Deleted hash file: {hash_name}', 'info')
        return success_response(f'Deleted {hash_name}')
        
    except Exception as e:
        log(f'Error deleting hash: {e}', 'error')
        return error_response(str(e), 500)


# ─────────────────────────────────────────────────────────────
# SSE Stream
# ─────────────────────────────────────────────────────────────

@api.route('/stream')
def stream():
    """Server-Sent Events stream for real-time updates."""
    state = get_state()
    storage = get_storage()
    
    # Ensure logger has the queue
    set_log_queue(state.log_queue)
    
    def event_stream():
        while True:
            try:
                if not state.log_queue.empty():
                    log_entry = state.log_queue.get()
                    yield f"data: {json.dumps({'type': 'log', 'data': log_entry})}\n\n"
                
                yield f"data: {json.dumps({'type': 'status', 'data': dict(storage.stats)})}\n\n"
                time.sleep(0.5)
            except GeneratorExit:
                break
    
    return Response(event_stream(), mimetype='text/event-stream')


# ─────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────

@api.route('/cleanup', methods=['POST'])
def cleanup():
    """Clean up monitor mode and restore network."""
    state = get_state()
    
    try:
        log('Cleaning up and restoring network...', 'info')
        sniff.cleanup_processes()
        subprocess.run("pkill -9 hashcat", shell=True, stderr=subprocess.DEVNULL)
        state.monitor_interface = None
        log('Cleanup complete', 'success')
        return success_response()
    except Exception as e:
        log(f'Cleanup error: {str(e)}', 'error')
        return error_response(str(e), 500)


# ─────────────────────────────────────────────────────────────
# Smart Wordlist Generator Integration
# ─────────────────────────────────────────────────────────────

@api.route('/wordlist/generate', methods=['POST'])
def wordlist_generate():
    """Generate passwords using brgen (PassGPT neural network)."""
    try:
        from brgen import PassGPTGenerator
        from datetime import datetime
        
        data = request.json or {}
        count = data.get('count', 10000)
        temperature = data.get('temperature', 1.0)
        ordered = data.get('ordered', True)  # SOPG by default - probability ordered
        beam_width = data.get('beam_width', 50)
        model = data.get('model')  # None = default, or path to fine-tuned
        
        # Validate count - allow up to 1M
        count = max(100, min(count, 1_000_000))
        
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        mode_str = "ordered" if ordered else "random"
        filename = f"brgen_{count}_{mode_str}_{timestamp}.txt"
        output_path = os.path.join('wordlists', filename)
        
        generator = PassGPTGenerator(model_path=model)
        
        if ordered:
            log(f'Generating {count} passwords with SOPG beam search (width={beam_width})', 'info')
            generated = generator.generate_ordered_to_file(
                output_path,
                count=count,
                beam_width=beam_width,
                verbose=False,
            )
        else:
            log(f'Generating {count} passwords with brgen (temp={temperature})', 'info')
            generated = generator.generate_to_file(
                output_path,
                count=count,
                temperature=temperature,
                verbose=False,
            )
        
        log(f'Generated {generated:,} passwords → {filename}', 'success')
        
        return success_response(
            file_path=output_path,
            word_count=generated,
            filename=filename,
            mode='ordered' if ordered else 'random',
        )
            
    except ImportError as e:
        return error_response(f'Brgen module error: {str(e)}', 500)
    except Exception as e:
        log(f'Generation error: {str(e)}', 'error')
        return error_response(str(e), 500)



@api.route('/wordlist/rules', methods=['GET'])
def wordlist_rules():
    """Get available hashcat rules."""
    try:
        from app.wordlist_generator import WordlistGenerator
        
        rules = WordlistGenerator.get_available_rules()
        
        return jsonify({
            'rules': rules,
            'count': len(rules),
        })
    except Exception as e:
        return error_response(str(e), 500)


@api.route('/wordlist/status', methods=['GET'])
def wordlist_status():
    """Check wordlist generator availability and modes."""
    try:
        from app.wordlist_generator import WordlistGenerator
        from app.brazilian_patterns import BrazilianPatterns
        
        return jsonify({
            'available': True,
            'modes': WordlistGenerator.MODES,
            'patterns': {
                'names': len(BrazilianPatterns.get_all_names()),
                'football': len(BrazilianPatterns.get_all_football()),
                'locations': len(BrazilianPatterns.get_all_locations()),
                'common_words': len(BrazilianPatterns.get_all_common_words()),
                'leaked_passwords': len(BrazilianPatterns.TOP_LEAKED_PASSWORDS),
            },
        })
    except ImportError:
        return jsonify({
            'available': False,
            'modes': {},
            'patterns': {},
        })

