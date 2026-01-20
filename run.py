#!/usr/bin/env python3
"""
WiFi Handshake Capture Tool - Web Interface (Refactored)

Clean architecture with proper separation of concerns:
- app/models.py   : Data structures
- app/storage.py  : Persistent JSON-backed storage
- app/state.py    : Runtime state management
- app/services.py : Business logic
- app/routes.py   : HTTP API endpoints
- app/workers.py  : Background tasks
- app/logging.py  : Unified logging
"""

import os
import sys
import signal
import subprocess

from flask import Flask, render_template

# Ensure app package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.routes import api
from app.state import get_state
from app.storage import get_storage
from app.logging import set_log_queue, log

import memento as sniff

# Store original print
_original_print = print


def create_app() -> Flask:
    """Application factory."""
    app = Flask(__name__)
    
    # Register blueprints
    app.register_blueprint(api)
    
    # Main route
    @app.route('/')
    def index():
        return render_template('index.html')
    
    return app


def handle_exit(signum=None, frame=None):
    """Graceful shutdown handler."""
    _original_print("\n[*] Shutting down web server...")
    _original_print("[*] Cleaning up monitor mode and processes...")
    
    state = get_state()
    storage = get_storage()
    
    state.scanning = False
    state.attacking = False
    state.cracking = False
    
    try:
        subprocess.run("pkill -9 airodump-ng", shell=True, stderr=subprocess.DEVNULL)
        subprocess.run("pkill -9 aireplay-ng", shell=True, stderr=subprocess.DEVNULL)
        subprocess.run("pkill -9 hashcat", shell=True, stderr=subprocess.DEVNULL)
        sniff.cleanup_processes()
        storage.save_all()
        _original_print("[+] Cleanup complete")
    except Exception as e:
        _original_print(f"[!] Cleanup error: {e}")
    
    _original_print("[*] Goodbye!")
    sys.exit(0)


def check_dependencies():
    """Check for required external tools and warn about missing ones."""
    deps = {
        'airmon-ng': 'aircrack-ng',
        'airodump-ng': 'aircrack-ng', 
        'aireplay-ng': 'aircrack-ng',
        'hashcat': 'hashcat',
        'hcxpcapngtool': 'hcxtools',
    }
    
    missing = []
    for cmd, package in deps.items():
        result = subprocess.run(
            f"which {cmd}", 
            shell=True, 
            capture_output=True
        )
        if result.returncode != 0:
            missing.append((cmd, package))
    
    if missing:
        _original_print("[!] WARNING: Missing dependencies detected")
        _original_print("    Some features may not work correctly.")
        _original_print("")
        for cmd, package in missing:
            _original_print(f"    - {cmd} (install package: {package})")
        _original_print("")
        _original_print("    On Debian/Ubuntu: sudo apt install aircrack-ng hashcat hcxtools")
        _original_print("    On Arch: sudo pacman -S aircrack-ng hashcat hcxtools")
        _original_print("")
        return False
    
    return True

def main():
    """Main entry point."""
    if os.geteuid() != 0:
        _original_print("[!] This application must be run as root")
        _original_print("Usage: sudo python3 run.py")
        sys.exit(1)
    
    # Check for required tools
    check_dependencies()
    
    # Initialize state and wire up logging
    state = get_state()
    set_log_queue(state.log_queue)
    
    # Register signal handlers
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)
    
    _original_print("=" * 60)
    _original_print("Memento - WiFi Handshake Capture Tool v2.0")
    _original_print("=" * 60)
    _original_print("Starting web server...")
    _original_print()
    _original_print("  Local:    http://localhost:5000")
    _original_print("  Network:  http://<your-ip>:5000")
    _original_print()
    _original_print("Press CTRL+C to stop")
    _original_print("=" * 60)
    _original_print()
    
    app = create_app()
    
    # Silence noisy Flask logs
    import logging
    log_wrk = logging.getLogger('werkzeug')
    log_wrk.setLevel(logging.ERROR)
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        handle_exit()
    except Exception as e:
        _original_print(f"[!] Server error: {e}")
        handle_exit()


if __name__ == '__main__':
    main()
