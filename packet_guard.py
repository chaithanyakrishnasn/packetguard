from scapy.all import sniff, IP, TCP, UDP, Raw
import matplotlib.pyplot as plt
from datetime import datetime
import sys

# Global variables to track statistics
packet_counts = {'TCP': 0, 'UDP': 0, 'Other': 0}
KEYWORDS = ["password", "user", "username", "login", "admin", "pass"]
LOG_FILE = "alerts.log"

def log_alert(message):
    """Writes alerts to a file with a timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_msg = f"[{timestamp}] {message}\n"
    
    # Write to file
    with open(LOG_FILE, "a") as f:
        f.write(formatted_msg)
    
    # Also print to console
    print(formatted_msg)

def packet_callback(packet):
    # Only process packets that have an IP layer
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    
    # 1. Update Statistics
    if packet.haslayer(TCP):
        packet_counts['TCP'] += 1
    elif packet.haslayer(UDP):
        packet_counts['UDP'] += 1
    else:
        packet_counts['Other'] += 1

    # 2. Watchdog Logic (The IDS)
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            for keyword in KEYWORDS:
                if keyword in payload.lower():
                    alert_msg = (
                        f"ALERT: Suspicious keyword '{keyword}' found! "
                        f"Src: {src_ip} -> Dst: {dst_ip}"
                    )
                    log_alert(alert_msg)
                    break
        except Exception:
            pass

def visualize_results():
    """Generates a pie chart of the traffic captured."""
    print("\n[*] Generating Traffic Report...")
    labels = list(packet_counts.keys())
    values = list(packet_counts.values())

    # Only show plot if we actually captured data
    if sum(values) > 0:
        plt.figure(figsize=(8, 6))
        plt.pie(values, labels=labels, autopct='%1.1f%%', startangle=140, colors=['#ff9999','#66b3ff','#99ff99'])
        plt.title('Network Traffic Distribution')
        plt.show()
    else:
        print("[!] No packets captured to visualize.")

def start_sniffing():
    print(f"[*] PacketGuard Running... Logs saving to {LOG_FILE}")
    print("[*] Press Ctrl+C to stop and generate report.")
    
    try:
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping Sniffer...")
        visualize_results()
        print("[*] Done. Goodbye!")

if __name__ == "__main__":
    start_sniffing()