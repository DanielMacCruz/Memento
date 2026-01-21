#!/usr/bin/env python3
"""
Base Station Server
===================
Standalone HTTPS server for receiving hash uploads from field laptops.
Authenticated via simple hardcoded password.
"""

import os
import sys
import json
import socket
import logging
import subprocess
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, render_template_string, send_file, Response

# Helper to check permissions
if os.geteuid() != 0:
    print("[!] This server must be run as root (for port 443/8443 binding)")
    sys.exit(1)

# Configuration
PORT = 8443
cert_path = 'data/base_station.crt'
key_path = 'data/base_station.key'
UPLOAD_DIR = 'hashes'
CRACKED_DIR = 'cracked'

# Ensure directories exist
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(CRACKED_DIR, exist_ok=True)

app = Flask(__name__)

# ═══════════════════════════════════════════════════════════════
# AUTHENTICATION
# ═══════════════════════════════════════════════════════════════

def check_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        password = request.headers.get('X-Base-Password')
        
        # Check Basic Auth (Browser) or Custom Header (API)
        # For simplicity, we just check against a hardcoded "password" 
        # But wait, user said "hardcoded password field".
        # Let's say the password is 'hunter2' for now, or read from env/file?
        # User said "No user, it is always me".
        # Let's use a default strict password or ask user?
        # I'll default to 'memento' and print it on startup.
        
        valid_pass = 'memento' # keeping it simple as requested
        
        if auth and auth.password == valid_pass:
            return f(*args, **kwargs)
        
        if password == valid_pass:
            return f(*args, **kwargs)
            
        return Response(
            'Could not verify your access level for that URL.\n'
            'You have to login with proper credentials', 401,
            {'WWW-Authenticate': 'Basic realm="Login Required"'})
    return decorated

# ═══════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route('/')
@check_auth
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Memento Base Station</title>
        <style>
            body { font-family: monospace; background: #0f0f0f; color: #00ff00; padding: 2rem; }
            .container { max-width: 800px; margin: 0 auto; border: 1px solid #333; padding: 2rem; }
            h1 { border-bottom: 1px solid #333; padding-bottom: 1rem; }
            .status { background: #1a1a1a; padding: 1rem; margin: 1rem 0; }
            .upload-zone { border: 2px dashed #333; padding: 2rem; text-align: center; margin: 2rem 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>📡 Base Station Uplink</h1>
            <div class="status">
                <p>Status: ONLINE</p>
                <p>Public IP: {{ public_ip }}</p>
                <p>Port: {{ port }} (HTTPS)</p>
            </div>
            
            <div class="upload-zone">
                <p>Ready to receive evidence packets.</p>
                <small>Use Field Laptop "Upload" button.</small>
            </div>
        </div>
    </body>
    </html>
    """, public_ip=get_public_ip(), port=PORT)

@app.route('/api/remote/info', methods=['GET'])
def info():
    """Public info endpoint (no auth needed to check reachability)."""
    return jsonify({
        'status': 'online',
        'public_ip': get_public_ip(),
        'port': PORT,
        'protocol': 'https'
    })

@app.route('/api/remote/upload', methods=['POST'])
@check_auth
def upload():
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'No file'}), 400
        
    filename = file.filename
    if not filename:
        return jsonify({'error': 'Empty filename'}), 400
    
    # Secure filename
    from werkzeug.utils import secure_filename
    filename = secure_filename(filename)
    
    save_path = os.path.join(UPLOAD_DIR, filename)
    file.save(save_path)
    
    print(f"[+] Received upload: {filename}")
    return jsonify({'success': True, 'message': f'Received {filename}'})

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
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print("[*] Generating Base Station SSL certificates...")
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096', 
            '-keyout', key_path, '-out', cert_path, 
            '-days', '3650', '-nodes', 
            '-subj', '/CN=MementoBaseStation'
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == '__main__':
    generate_certs()
    print("="*60)
    print(f"📡 BASE STATION ONLINE")
    print(f"   URL: https://0.0.0.0:{PORT}")
    print(f"   Password: memento")
    print("="*60)
    
    # Use Werkzeug's serving to run SSL
    app.run(host='0.0.0.0', port=PORT, ssl_context=(cert_path, key_path))
