import os
import json
import time
import datetime
import scapy.all as scapy
import socket

# Directory to store captured packets
PACKETS_DIR = "logs/packets"

# Ensure directory exists
os.makedirs(PACKETS_DIR, exist_ok=True)

def is_wifi_connected():
    """Check if the system is connected to a WiFi network."""
    try:
        hostname = socket.gethostbyname("www.google.com")
        return hostname != "127.0.0.1"
    except:
        return False

def packet_callback(packet):
    """Process each captured packet and extract details."""
    packet_info = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "protocol": packet.proto if hasattr(packet, "proto") else "Unknown",
        "source_ip": packet[scapy.IP].src if packet.haslayer(scapy.IP) else "Unknown",
        "destination_ip": packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "Unknown",
        "source_port": packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else (packet[scapy.UDP].sport if packet.haslayer(scapy.UDP) else "Unknown"),
        "destination_port": packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else (packet[scapy.UDP].dport if packet.haslayer(scapy.UDP) else "Unknown"),
        "payload": str(packet.payload) if packet.payload else "No Payload"
    }
    return packet_info

def capture_packets(duration=20):
    """Capture WiFi packets for a given duration."""
    if not is_wifi_connected():
        print("Please connect to your WiFi network first.")
        return
    
    print(f"Capturing packets for {duration} seconds...")
    packets = scapy.sniff(timeout=duration, prn=packet_callback)

    # Process packets into a list
    packet_data = [packet_callback(pkt) for pkt in packets]

    # Save to JSON file
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = os.path.join(PACKETS_DIR, f"packets_{timestamp}.json")
    
    with open(file_path, "w") as f:
        json.dump(packet_data, f, indent=4)
    
    print(f"Packet capture complete. Data saved in {file_path}")

if __name__ == "__main__":
    capture_packets()
