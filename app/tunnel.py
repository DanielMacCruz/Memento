"""
Tunnel/Connectivity helpers.

Fetches public IP for display in the Base Station UI.
"""
import requests
import socket

def get_public_ip() -> str:
    """Fetch public IP address from external service."""
    try:
        # Try a few reliable services
        services = [
            'https://api.ipify.org',
            'https://ifconfig.me/ip',
            'https://icanhazip.com'
        ]
        
        for url in services:
            try:
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    return response.text.strip()
            except:
                continue
                
    except Exception:
        pass
    return "Unknown"

def get_local_ip() -> str:
    """Get local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't actually connect, just finding the route
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"
