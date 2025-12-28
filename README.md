# Memento

A WiFi handshake capture and cracking tool with a web interface.

Memento scans for WPA/WPA2 networks, captures authentication handshakes, and cracks passwords using hashcat. The web UI provides real-time monitoring of network discovery, attack progress, and cracking status.

## Requirements

### System Dependencies

```bash
# Debian/Ubuntu
sudo apt install aircrack-ng hashcat hcxtools python3-pip python3-scapy

# Arch Linux
sudo pacman -S aircrack-ng hashcat hcxtools python-pip python-scapy
```

### Hardware

- A WiFi adapter that supports **monitor mode** and **packet injection**
- Recommended: ALFA AWUS036ACH, AWUS036ACHM, or similar Realtek/Atheros chipset adapters
- Most built-in laptop WiFi cards do **not** support monitor mode

### Python Dependencies

```bash
pip3 install flask scapy
```

## Installation

```bash
git clone https://github.com/yourusername/memento.git
```

## Usage

```bash
cd memento
sudo python3 run.py
```

Then open http://localhost:5000 in your browser.

### Interface Overview

| Panel | Purpose |
|-------|---------|
| **Suspects** | Discovered networks with signal strength, channel, and client count |
| **Field Notes** | Real-time activity log |
| **Evidence Locker** | Captured handshakes ready for cracking |

### Main Functions

- **Remember** - Start scanning for networks
- **Forget** - Stop all operations
- **Interrogate** - Deauth attack to capture handshakes
- **Vigilance** - Passive mode (no deauth, just listens)
- **Anterograde Amnesia** - Automatic cracking loop using all available wordlists
- **Fabricate** - Generate passwords using AI (PassGPT)
- **Solve Cases** - Manual cracking with selected wordlist

### Pressure Levels

Controls deauth packet count for handshake capture:

| Level | Packets | Use Case |
|-------|---------|----------|
| Gentle | 8 | Minimal disruption |
| Firm | 16 | Default, balanced |
| Heavy | 32 | Stubborn clients |
| Brutal | 64 | Last resort |

## How It Works

1. **Scanning**: Uses `airodump-ng` to discover WPA/WPA2 networks and connected clients
2. **Deauthentication**: Sends deauth packets to force clients to reconnect
3. **Capture**: Records the 4-way handshake during reconnection
4. **Conversion**: Uses `hcxpcapngtool` to convert captures to hashcat format
5. **Cracking**: Uses `hashcat` with wordlists to recover passwords

## The 8-Digit Attack

Many WiFi passwords are 8 digits (phone numbers, birthdates, default passwords). Memento includes a built-in mask attack that tries all 100 million combinations:

```
00000000 → 99999999
```

On a modern GPU, this completes in 5-10 minutes.

## File Structure

```
memento/
├── run.py              # Main entry point (Flask app)
├── sniff.py            # Core capture logic (to be renamed memento.py)
├── cracking.py         # Hashcat wrapper
├── deauth.py           # Scapy-based deauth implementation
├── app/
│   ├── routes.py       # HTTP API endpoints
│   ├── workers.py      # Background tasks
│   ├── storage.py      # JSON-based state persistence
│   └── ...
├── templates/
│   └── index.html      # Web UI
├── static/
│   ├── style.css
│   └── app.js
├── captures/           # Raw .cap files (gitignored)
├── hashes/             # Converted .hc22000 files (gitignored)
├── cracked/            # Recovered passwords (gitignored)
└── wordlists/          # Password lists (gitignored except samples)
```

## Legal Notice

**This tool is for authorized security testing only.**

Capturing handshakes from networks you don't own or have permission to test is illegal in most jurisdictions. Use responsibly.

## Troubleshooting

### "No wireless interface found"

Your adapter doesn't support monitor mode or isn't recognized. Try:
- `iwconfig` to list wireless interfaces
- `airmon-ng` to check monitor mode support
- Different USB port or adapter

### Handshake not captured

- Ensure clients are connected to the target network
- Try higher pressure level
- Move closer to the access point
- Some networks have client isolation or other protections

### Cracking is slow

- Use GPU if available (`hashcat` auto-detects)
- Use smaller, targeted wordlists
- Try the 8-digit mask attack first
- WPA cracking is intentionally slow (4096 PBKDF2 iterations)

## License

MIT
