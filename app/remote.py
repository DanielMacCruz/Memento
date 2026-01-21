"""
Remote Operations API (Base Station Mode).

Endpoints for:
- Uploading hashes from field laptops
- Checking cracking status
- Fetching connection info (Public IP)
"""

from flask import Blueprint, jsonify, request
from .services import RemoteService, HashService
from .tunnel import get_public_ip, get_local_ip
from .workers import run_crack_worker
import threading
import os

remote_bp = Blueprint('remote', __name__, url_prefix='/api/remote')

@remote_bp.route('/info', methods=['GET'])
def get_connection_info():
    """Get public IP and port for display."""
    return jsonify({
        'public_ip': get_public_ip(),
        'local_ip': get_local_ip(),
        'port': 5000,
        'protocol': 'https'
    })

@remote_bp.route('/upload', methods=['POST'])
def upload_hash():
    """
    Accepts .hc22000 file upload.
    Automatically starts cracking if 'auto_crack' is True (default).
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    success, result = RemoteService.handle_upload(file, file.filename)
    
    if not success:
        return jsonify({'error': result}), 500
        
    job_id = result
    
    # Auto-start cracking logic (Simple default: Mask Attack then Wordlist)
    # We create a task list to run immediately
    if request.form.get('auto_crack', 'true') == 'true':
        hash_path = os.path.join("hashes", job_id)
        
        # Standard "Anterograde Amnesia" style queue:
        # 1. 8-Digit Mask
        # 2. rockyou.txt (if available)
        
        tasks = [
            {
                'hash': os.path.abspath(hash_path),
                'hash_rel': hash_path,
                'hash_name': job_id,
                'mask_type': '__MASK_8DIGIT__',
            }
        ]
        
        # Add rockyou if exists
        rockyou = os.path.abspath("wordlists/rockyou.txt")
        if os.path.exists(rockyou):
            tasks.append({
                'hash': os.path.abspath(hash_path),
                'hash_rel': hash_path,
                'hash_name': job_id,
                'wordlist': rockyou,
                'wordlist_name': 'rockyou.txt',
                'rule_file': None
            })
            
        # Start worker
        thread = threading.Thread(target=run_crack_worker, args=(tasks,))
        thread.daemon = True
        thread.start()

    return jsonify({
        'success': True, 
        'job_id': job_id,
        'message': 'File uploaded and queued for cracking.'
    })

@remote_bp.route('/status/<filename>', methods=['GET'])
def check_status(filename):
    """Check status of a specific hash file."""
    status = RemoteService.get_job_status(filename)
    return jsonify(status)
