#!/usr/bin/env python3
"""
Base Station Server
===================
Standalone HTTPS server for receiving hash uploads from field laptops.
Authenticated via simple hardcoded password.

Features:
- Upload .hc22000 hash files from field laptops
- Auto-crack on upload with 8-digit mask then rockyou
- Real-time status updates via SSE
- Download cracked results

Run with: sudo python3 base_station.py
"""

import os
import sys
import json
import time
import queue
import socket
import logging
import threading
import subprocess
from datetime import datetime
from functools import wraps
from collections import OrderedDict

# Ensure app package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, render_template_string, send_file, Response

# Helper to check permissions
if os.geteuid() != 0:
    print("[!] This server must be run as root (for port 8443 binding)")
    sys.exit(1)

# Configuration
PORT = 8443
PASSWORD = 'memento'
cert_path = 'data/base_station.crt'
key_path = 'data/base_station.key'
UPLOAD_DIR = 'hashes'
CRACKED_DIR = 'cracked'
WORDLIST_DIR = 'wordlists'

# Ensure directories exist
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(CRACKED_DIR, exist_ok=True)

app = Flask(__name__)

# ═══════════════════════════════════════════════════════════════
# JOB TRACKING
# ═══════════════════════════════════════════════════════════════

# Job states: pending, cracking, cracked, failed, exhausted
jobs = OrderedDict()  # job_id -> job info
job_lock = threading.Lock()
event_queues = []  # SSE subscribers

def create_job(filename: str) -> dict:
    """Create a new job entry."""
    job = {
        'id': filename,
        'filename': filename,
        'status': 'pending',
        'progress': 0,
        'speed': '',
        'eta': '',
        'password': None,
        'created_at': datetime.now().isoformat(),
        'updated_at': datetime.now().isoformat(),
        'log': [],
    }
    with job_lock:
        jobs[filename] = job
    broadcast_event('job_created', job)
    return job

def update_job(job_id: str, **updates):
    """Update job and broadcast to SSE subscribers."""
    with job_lock:
        if job_id in jobs:
            jobs[job_id].update(updates)
            jobs[job_id]['updated_at'] = datetime.now().isoformat()
            broadcast_event('job_updated', jobs[job_id])

def job_log(job_id: str, message: str):
    """Add log message to job."""
    with job_lock:
        if job_id in jobs:
            jobs[job_id]['log'].append({
                'time': datetime.now().strftime('%H:%M:%S'),
                'msg': message
            })
            # Keep only last 50 log entries
            jobs[job_id]['log'] = jobs[job_id]['log'][-50:]
    broadcast_event('job_log', {'job_id': job_id, 'message': message})

def broadcast_event(event_type: str, data: dict):
    """Send event to all SSE subscribers."""
    msg = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    dead_queues = []
    for q in event_queues:
        try:
            q.put_nowait(msg)
        except:
            dead_queues.append(q)
    for q in dead_queues:
        try:
            event_queues.remove(q)
        except:
            pass


# ═══════════════════════════════════════════════════════════════
# AUTHENTICATION
# ═══════════════════════════════════════════════════════════════

def check_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        password = request.headers.get('X-Base-Password')
        
        # Check Basic Auth (browser) or custom header (API)
        if auth and auth.password == PASSWORD:
            return f(*args, **kwargs)
        if password == PASSWORD:
            return f(*args, **kwargs)
            
        return Response(
            'Authentication required.\n'
            'Use password: memento', 401,
            {'WWW-Authenticate': 'Basic realm="Memento Base Station"'})
    return decorated


# ═══════════════════════════════════════════════════════════════
# CRACKING WORKER
# ═══════════════════════════════════════════════════════════════

def crack_job(job_id: str, hash_path: str):
    """Background worker to crack a hash file."""
    from app.cracking import run_mask_attack, run_cracker
    
    def log_cb(msg):
        job_log(job_id, msg)
        # Parse hashcat status for progress
        if 'Progress' in msg:
            try:
                # Parse "Progress.........: 12345/100000000 (0.01%)"
                percent_match = msg.split('(')[1].split('%')[0] if '(' in msg else None
                if percent_match:
                    update_job(job_id, progress=float(percent_match))
            except:
                pass
        if 'Speed' in msg:
            update_job(job_id, speed=msg.split(':')[-1].strip())
        if 'Time.Estimated' in msg:
            update_job(job_id, eta=msg.split(':')[-1].strip())
    
    update_job(job_id, status='cracking')
    
    # Stage 1: 8-digit mask attack
    job_log(job_id, "Starting 8-digit mask attack...")
    try:
        result = run_mask_attack(hash_path, '__MASK_8DIGIT__', log_callback=log_cb)
        if result.get('cracked'):
            password = read_cracked_password(result.get('output_file'))
            update_job(job_id, status='cracked', password=password, progress=100)
            job_log(job_id, f"✓ PASSWORD FOUND: {password}")
            return
    except Exception as e:
        job_log(job_id, f"Mask attack error: {e}")
    
    # Stage 2: rockyou wordlist if available
    rockyou_path = os.path.join(WORDLIST_DIR, 'rockyou.txt')
    if os.path.exists(rockyou_path):
        job_log(job_id, "Starting rockyou.txt wordlist attack...")
        update_job(job_id, progress=0)
        try:
            result = run_cracker(hash_path, rockyou_path, log_callback=log_cb)
            if result.get('cracked'):
                password = read_cracked_password(result.get('output_file'))
                update_job(job_id, status='cracked', password=password, progress=100)
                job_log(job_id, f"✓ PASSWORD FOUND: {password}")
                return
        except Exception as e:
            job_log(job_id, f"Wordlist attack error: {e}")
    else:
        job_log(job_id, "rockyou.txt not found, skipping wordlist attack")
    
    # No password found
    update_job(job_id, status='exhausted', progress=100)
    job_log(job_id, "All attack methods exhausted. No password found.")

def read_cracked_password(output_file: str) -> str:
    """Read password from cracked output file."""
    if not output_file or not os.path.exists(output_file):
        return None
    try:
        with open(output_file, 'r') as f:
            # Format is usually: hash:password or just password
            line = f.readline().strip()
            if ':' in line:
                return line.split(':')[-1]
            return line
    except:
        return None


# ═══════════════════════════════════════════════════════════════
# ROUTES - WEB UI
# ═══════════════════════════════════════════════════════════════

@app.route('/')
@check_auth
def index():
    hash_files = []
    if os.path.exists(UPLOAD_DIR):
        for f in os.listdir(UPLOAD_DIR):
            path = os.path.join(UPLOAD_DIR, f)
            if os.path.isfile(path):
                hash_files.append({
                    'name': f,
                    'size': os.path.getsize(path),
                    'job': jobs.get(f, {})
                })
    
    cracked_files = []
    if os.path.exists(CRACKED_DIR):
        for f in os.listdir(CRACKED_DIR):
            path = os.path.join(CRACKED_DIR, f)
            if os.path.isfile(path):
                try:
                    with open(path, 'r') as fp:
                        content = fp.read().strip()
                except:
                    content = '(unreadable)'
                cracked_files.append({'name': f, 'content': content})
    
    return render_template_string(BASE_STATION_HTML, 
        public_ip=get_public_ip(), 
        port=PORT, 
        hashes=hash_files, 
        results=cracked_files,
        jobs=list(jobs.values()))


# ═══════════════════════════════════════════════════════════════
# ROUTES - API
# ═══════════════════════════════════════════════════════════════

@app.route('/api/info', methods=['GET'])
def info():
    """Public info endpoint (no auth needed to check reachability)."""
    return jsonify({
        'status': 'online',
        'public_ip': get_public_ip(),
        'port': PORT,
        'protocol': 'https',
        'version': '2.0'
    })

@app.route('/api/upload', methods=['POST'])
@check_auth
def upload():
    """Upload hash file and auto-start cracking."""
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'No file provided'}), 400
        
    filename = file.filename
    if not filename:
        return jsonify({'error': 'Empty filename'}), 400
    
    # Secure filename
    from werkzeug.utils import secure_filename
    filename = secure_filename(filename)
    
    save_path = os.path.join(UPLOAD_DIR, filename)
    file.save(save_path)
    
    print(f"[+] Received upload: {filename}")
    
    # Create job and start cracking in background
    job = create_job(filename)
    
    auto_crack = request.form.get('auto_crack', 'true').lower() == 'true'
    if auto_crack:
        thread = threading.Thread(target=crack_job, args=(filename, save_path))
        thread.daemon = True
        thread.start()
    
    return jsonify({
        'success': True, 
        'job_id': filename,
        'message': f'Received {filename}' + (' - cracking started' if auto_crack else '')
    })

@app.route('/api/jobs', methods=['GET'])
@check_auth
def list_jobs():
    """List all jobs with their status."""
    with job_lock:
        return jsonify({'jobs': list(jobs.values())})

@app.route('/api/jobs/<job_id>', methods=['GET'])
@check_auth
def get_job(job_id):
    """Get detailed status of a specific job."""
    with job_lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    return jsonify(job)

@app.route('/api/results', methods=['GET'])
@check_auth
def list_results():
    """List cracked password files."""
    files = []
    if os.path.exists(CRACKED_DIR):
        for f in os.listdir(CRACKED_DIR):
            path = os.path.join(CRACKED_DIR, f)
            if os.path.isfile(path):
                try:
                    with open(path, 'r') as fp:
                        content = fp.read().strip()
                except:
                    content = None
                files.append({'filename': f, 'password': content})
    return jsonify({'files': files})

@app.route('/api/download/<filename>', methods=['GET'])
@check_auth
def download_result(filename):
    """Download a specific cracked result."""
    from werkzeug.utils import secure_filename
    filename = secure_filename(filename)
    path = os.path.join(CRACKED_DIR, filename)
    
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    else:
        return jsonify({'error': 'File not found'}), 404

@app.route('/api/stream')
@check_auth
def stream():
    """SSE endpoint for real-time job updates."""
    def event_stream():
        q = queue.Queue()
        event_queues.append(q)
        try:
            # Send initial state
            with job_lock:
                for job in jobs.values():
                    yield f"event: job_updated\ndata: {json.dumps(job)}\n\n"
            
            # Stream updates
            while True:
                try:
                    msg = q.get(timeout=30)
                    yield msg
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            try:
                event_queues.remove(q)
            except:
                pass
    
    return Response(event_stream(), mimetype='text/event-stream',
                   headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


# ═══════════════════════════════════════════════════════════════
# UTILS
# ═══════════════════════════════════════════════════════════════

def get_public_ip():
    try:
        from app.tunnel import get_public_ip as fetch_ip
        return fetch_ip()
    except:
        return 'Unknown'

def generate_certs():
    os.makedirs('data', exist_ok=True)
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print("[*] Generating Base Station SSL certificates...")
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096', 
            '-keyout', key_path, '-out', cert_path, 
            '-days', '3650', '-nodes', 
            '-subj', '/CN=MementoBaseStation'
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ═══════════════════════════════════════════════════════════════
# HTML TEMPLATE
# ═══════════════════════════════════════════════════════════════

BASE_STATION_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Memento Base Station</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', system-ui, sans-serif; 
            background: #0a0a0c; 
            color: #e0e0e0; 
            padding: 1rem; 
            margin: 0;
            min-height: 100vh;
        }
        .container { 
            max-width: 1000px; 
            margin: 0 auto; 
            background: #121216;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.6);
            overflow: hidden;
        }
        header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 1.5rem 2rem;
            border-bottom: 2px solid #00ff00;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        h1 { margin: 0; color: #00ff00; font-weight: 300; letter-spacing: 2px; font-size: 1.5rem; }
        .status-badge {
            background: rgba(0,255,0,0.15);
            color: #00ff00;
            padding: 0.4rem 1rem;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
        }
        .content { padding: 1.5rem 2rem; }
        
        .info-bar {
            background: #1c1c24;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            font-family: monospace;
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 1rem;
        }
        .info-item { color: #888; }
        .info-item strong { color: #00ff00; }
        
        .section { margin-bottom: 2rem; }
        .section h2 { 
            font-size: 1rem; 
            color: #888;
            text-transform: uppercase;
            letter-spacing: 1px;
            border-bottom: 1px solid #333; 
            padding-bottom: 0.5rem; 
            margin-bottom: 1rem;
        }
        
        .upload-form {
            background: #1c1c24;
            padding: 1.5rem;
            border-radius: 8px;
            border: 2px dashed #333;
            text-align: center;
            margin-bottom: 1.5rem;
        }
        .upload-form input[type="file"] { display: none; }
        .upload-label {
            display: inline-block;
            background: linear-gradient(135deg, #00aa00, #008800);
            color: white;
            padding: 0.75rem 2rem;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.2s;
        }
        .upload-label:hover { transform: translateY(-2px); box-shadow: 0 4px 15px rgba(0,255,0,0.3); }
        
        .job-list { display: flex; flex-direction: column; gap: 0.5rem; }
        .job-item { 
            background: #1c1c24; 
            padding: 1rem;
            border-radius: 6px;
            border-left: 3px solid #333;
        }
        .job-item.pending { border-left-color: #888; }
        .job-item.cracking { border-left-color: #ffcc00; animation: pulse 1.5s infinite; }
        .job-item.cracked { border-left-color: #00ff00; }
        .job-item.exhausted { border-left-color: #ff4444; }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        .job-header { display: flex; justify-content: space-between; align-items: center; }
        .job-name { font-family: monospace; font-weight: 500; }
        .job-status { 
            font-size: 0.75rem; 
            padding: 0.25rem 0.75rem; 
            border-radius: 12px;
            text-transform: uppercase;
        }
        .job-status.pending { background: #333; color: #888; }
        .job-status.cracking { background: rgba(255,204,0,0.2); color: #ffcc00; }
        .job-status.cracked { background: rgba(0,255,0,0.2); color: #00ff00; }
        .job-status.exhausted { background: rgba(255,68,68,0.2); color: #ff4444; }
        
        .job-progress {
            margin-top: 0.75rem;
            height: 4px;
            background: #333;
            border-radius: 2px;
            overflow: hidden;
        }
        .job-progress-bar {
            height: 100%;
            background: linear-gradient(90deg, #00ff00, #00cc00);
            transition: width 0.3s;
        }
        
        .job-password {
            margin-top: 0.75rem;
            padding: 0.5rem;
            background: rgba(0,255,0,0.1);
            border-radius: 4px;
            font-family: monospace;
            color: #00ff00;
            font-size: 1.1rem;
        }
        
        .result-list { display: flex; flex-direction: column; gap: 0.5rem; }
        .result-item {
            background: #1c1c24;
            padding: 1rem;
            border-radius: 6px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-family: monospace;
        }
        .result-password { color: #00ff00; font-weight: 500; }
        .download-btn {
            background: transparent;
            border: 1px solid #00ff00;
            color: #00ff00;
            padding: 0.4rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.85rem;
            transition: all 0.2s;
        }
        .download-btn:hover { background: #00ff00; color: #000; }
        
        .empty { color: #555; font-style: italic; padding: 1rem; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📡 MEMENTO · BASE STATION</h1>
            <span class="status-badge">● ONLINE</span>
        </header>
        <div class="content">
            <div class="info-bar">
                <div class="info-item">Public IP: <strong>{{ public_ip }}</strong></div>
                <div class="info-item">Port: <strong>{{ port }}</strong></div>
                <div class="info-item">URL: <strong>https://{{ public_ip }}:{{ port }}</strong></div>
            </div>
            
            <div class="section">
                <h2>Upload Hash File</h2>
                <form class="upload-form" action="/api/upload" method="POST" enctype="multipart/form-data">
                    <input type="file" name="file" id="file-input" accept=".hc22000,.hash">
                    <label class="upload-label" for="file-input">📁 Choose .hc22000 File</label>
                    <p style="margin: 1rem 0 0; color: #666;">Drop hash files to start cracking</p>
                </form>
            </div>
            
            <div class="section">
                <h2>Active Jobs</h2>
                <div class="job-list" id="job-list">
                    {% if jobs %}
                        {% for job in jobs %}
                        <div class="job-item {{ job.status }}">
                            <div class="job-header">
                                <span class="job-name">{{ job.filename }}</span>
                                <span class="job-status {{ job.status }}">{{ job.status }}</span>
                            </div>
                            {% if job.status == 'cracking' %}
                            <div class="job-progress">
                                <div class="job-progress-bar" style="width: {{ job.progress }}%"></div>
                            </div>
                            {% endif %}
                            {% if job.password %}
                            <div class="job-password">🔑 {{ job.password }}</div>
                            {% endif %}
                        </div>
                        {% endfor %}
                    {% else %}
                        <p class="empty">No jobs yet. Upload a hash file to start.</p>
                    {% endif %}
                </div>
            </div>
            
            <div class="section">
                <h2>Cracked Results</h2>
                <div class="result-list">
                    {% if results %}
                        {% for r in results %}
                        <div class="result-item">
                            <div>
                                <span style="color:#888">{{ r.name }}</span>
                                <span class="result-password">→ {{ r.content }}</span>
                            </div>
                            <a href="/api/download/{{ r.name }}" class="download-btn">Download</a>
                        </div>
                        {% endfor %}
                    {% else %}
                        <p class="empty">No passwords recovered yet.</p>
                    {% endif %}
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Auto-submit on file selection
        document.getElementById('file-input').addEventListener('change', function() {
            if (this.files.length > 0) {
                this.form.submit();
            }
        });
        
        // SSE for live updates
        const evtSource = new EventSource('/api/stream');
        evtSource.addEventListener('job_updated', function(e) {
            const job = JSON.parse(e.data);
            updateJobUI(job);
        });
        
        function updateJobUI(job) {
            // Simple refresh for now - could be made smarter
            location.reload();
        }
    </script>
</body>
</html>
"""


if __name__ == '__main__':
    generate_certs()
    public_ip = get_public_ip()
    print("=" * 60)
    print("📡 MEMENTO BASE STATION")
    print("=" * 60)
    print(f"   URL: https://{public_ip}:{PORT}")
    print(f"   Local: https://0.0.0.0:{PORT}")
    print(f"   Password: {PASSWORD}")
    print()
    print("   Field laptops connect here to upload hashes.")
    print("   Auto-cracks with 8-digit mask + rockyou.")
    print("=" * 60)
    
    # Silence Flask logs
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    # Use Werkzeug's serving to run SSL
    app.run(host='0.0.0.0', port=PORT, ssl_context=(cert_path, key_path), threaded=True)
