import time
from scapy.all import sniff, IP, TCP, ICMP
from collections import defaultdict
import threading
import csv
import os

# Constants for DDoS detection
THRESHOLD = 10  # Packet count threshold to trigger warning
INTERVAL = 1    # Time interval for monitoring
LOG_DURATION = 10  # Duration for logging (not actively used)
SESSION_TIMEOUT = 2  # Timeout for counting packets from the same IP

# Data structures to store packet information and detection status
packet_info = defaultdict(lambda: {'count': 0, 'last_time': time.time(), 'bytes': 0})
attack_started = False
attack_details = []
total_packets = 0

# Function to log attack details to a CSV file
def log_to_csv(data):
    with open('ddos_attack_log.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(data)

# Function to detect potential DDoS attacks based on incoming packets
def detect_ddos(packet):
    global attack_started, total_packets

    # Check if the packet is an IP packet
    if IP in packet:
        src_ip = packet[IP].src  # Extract source IP
        current_time = time.time()  # Get current time
        packet_size = len(packet)  # Calculate packet size in bytes

        # Update packet information for the source IP
        if current_time - packet_info[src_ip]['last_time'] < SESSION_TIMEOUT:
            packet_info[src_ip]['count'] += 1
            packet_info[src_ip]['bytes'] += packet_size  # Update total bytes
        else:
            packet_info[src_ip]['count'] = 1  # Reset count for new session
            packet_info[src_ip]['bytes'] = packet_size

        packet_info[src_ip]['last_time'] = current_time  # Update last seen time
        total_packets += 1  # Increment total packet count

        # Check if packet count exceeds threshold
        if packet_info[src_ip]['count'] > THRESHOLD:
            print(f"[WARNING] Possible DDoS attack from IP {src_ip}: {packet_info[src_ip]['count']} packets received. "
                  f"Total bytes: {packet_info[src_ip]['bytes']}.")

        # Identify attack type based on packet characteristics
        if TCP in packet and packet[TCP].flags == "S":
            attack_type = "SYN flood"
        elif ICMP in packet and len(packet[ICMP].load) >= 100:
            attack_type = "Ping of Death"
        elif TCP in packet and packet[TCP].flags == "SA":
            attack_type = "SYN-ACK flood"
        elif ICMP in packet and packet[IP].src == packet[IP].dst:
            attack_type = "Smurf"
        else:
            attack_type = None

        # Log attack details if an attack is detected
        if attack_type:
            attack_started = True
            print(f"[INFO] {attack_type} detected from {src_ip}.")
            attack_details.append(
                [time.strftime("%Y-%m-%d %H:%M:%S"), src_ip, attack_type, total_packets, packet_info[src_ip]['bytes']])

# Function to continuously monitor network traffic
def monitor_traffic(interface):
    global attack_started, total_packets

    print(f"Monitoring traffic on {interface}...")
    while True:
        time.sleep(INTERVAL)  # Wait for the specified interval
        current_counts = {ip: info['count'] for ip, info in packet_info.items()}  # Get current packet counts
        current_bytes = {ip: info['bytes'] for ip, info in packet_info.items()}  # Get current byte counts
        packet_info.clear()  # Clear packet info for the next interval

        # Check for possible DDoS attacks
        if any(count > THRESHOLD for count in current_counts.values()):
            for ip, count in current_counts.items():
                if count > THRESHOLD:
                    print(f"[WARNING] Possible DDoS attack from IP {ip}: {count} packets in {INTERVAL} seconds. "
                          f"Total bytes: {current_bytes[ip]}.")
        else:
            # Log end of attack if previously detected
            if attack_started:
                print("[INFO] DDoS attack has ended.")
                for detail in attack_details:
                    log_to_csv(detail)  # Log attack details to CSV
                attack_details.clear()  # Clear attack details
                attack_started = False  # Reset attack status
                total_packets = 0  # Reset total packet count

# Main execution block
if __name__ == "__main__":
    INTERFACE = "ens33"  # Specify network interface for monitoring

    # Initialize the CSV log file with headers if it doesn't exist
    if not os.path.exists('ddos_attack_log.csv'):
        with open('ddos_attack_log.csv', mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Timestamp", "Source IP", "Attack Type", "Total Packets", "Total Bytes"])

    # Start monitoring traffic in a separate thread
    threading.Thread(target=monitor_traffic, args=(INTERFACE,), daemon=True).start()
    # Start sniffing packets on the specified interface
    sniff(iface=INTERFACE, prn=detect_ddos, store=0)
