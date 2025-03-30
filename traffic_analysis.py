import os
import json
import datetime

# ✅ Corrected log directory path
PACKET_LOG_DIR = "logs/packets"
REPORT_DIR = "logs/traffic_analysis_reports"

# Ensure report directory exists
os.makedirs(REPORT_DIR, exist_ok=True)

# Example suspicious ports & IPs for basic threat detection
SUSPICIOUS_PORTS = {23, 445, 3389}  # Telnet, SMB, RDP (common attack vectors)
MALICIOUS_IPS = {"192.168.1.100"}  # Replace with known bad IPs

def get_latest_packet_file():
    """Find the latest packet capture file."""
    if not os.path.exists(PACKET_LOG_DIR):
        print(f"❌ Packet log directory '{PACKET_LOG_DIR}' not found.")
        return None

    files = [f for f in os.listdir(PACKET_LOG_DIR) if f.endswith(".json")]
    if not files:
        print(f"❌ No packet capture files found in '{PACKET_LOG_DIR}'.")
        return None
    
    # Get the most recent file based on timestamp in filename
    files.sort(reverse=True)
    return os.path.join(PACKET_LOG_DIR, files[0])

def analyze_packets():
    """Analyze latest captured packets for threats."""
    file_path = get_latest_packet_file()
    
    if not file_path:
        print("❌ No captured packets found. Please run 'capture_packets.py' first.")
        return
    
    print(f"🔍 Analyzing packet data from: {file_path}")

    try:
        with open(file_path, "r") as f:
            packets = json.load(f)
    except Exception as e:
        print(f"❌ Error reading packet log: {e}")
        return

    threat_results = []

    for pkt in packets:
        src_ip = pkt.get("src_ip", "Unknown")
        dst_ip = pkt.get("dst_ip", "Unknown")
        protocol = pkt.get("protocol", "Unknown")
        port = pkt.get("dst_port", 0)  # Ensure a default numeric value

        threat_level = "Safe"
        threat_reason = ""

        if src_ip in MALICIOUS_IPS or dst_ip in MALICIOUS_IPS:
            threat_level = "⚠️ Critical"
            threat_reason = "Connection with a known malicious IP."
        
        elif isinstance(port, int) and port in SUSPICIOUS_PORTS:
            threat_level = "⚠️ High"
            threat_reason = f"Unusual port detected ({port}). Possible attack vector."
        
        elif protocol == "Unknown":
            threat_level = "⚠️ Medium"
            threat_reason = "Unrecognized network protocol."

        if threat_level != "Safe":
            threat_results.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "port": port,
                "threat_level": threat_level,
                "reason": threat_reason
            })

    # Save report
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(REPORT_DIR, f"traffic_analysis_{timestamp}.json")

    report_data = {
        "timestamp": timestamp,
        "file_analyzed": file_path,
        "threats_found": threat_results if threat_results else ["✅ No threats detected."]
    }

    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=4)

    print(f"✅ Analysis complete. Report saved: {report_path}")

if __name__ == "__main__":
    analyze_packets()
