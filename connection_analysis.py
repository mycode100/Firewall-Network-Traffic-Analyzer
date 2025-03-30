import os
import json
import datetime

# Directories
PACKET_LOG_DIR = "logs/packets"
CONN_REPORT_DIR = "logs/connection_reports"

# Ensure report directory exists
os.makedirs(CONN_REPORT_DIR, exist_ok=True)

# Common port security classification
PORT_SECURITY_LEVELS = {
    80: "❌ Not Secure (Unencrypted HTTP)",
    443: "✅ Secure (HTTPS)",
    22: "❌ Not Secure (SSH Exposed)",
    445: "❌ Not Secure (SMB - High Risk)",
    3389: "❌ Not Secure (RDP - High Risk)",
    53: "⚠️ Caution (DNS - Potential Data Leakage)",
    25: "⚠️ Caution (SMTP - Spam/Phishing Risk)"
}

def get_latest_packet_file():
    """Find the latest captured packet file."""
    if not os.path.exists(PACKET_LOG_DIR):
        print(f"❌ Packet log directory '{PACKET_LOG_DIR}' not found.")
        return None

    files = [f for f in os.listdir(PACKET_LOG_DIR) if f.endswith(".json")]
    if not files:
        print(f"❌ No packet capture files found in '{PACKET_LOG_DIR}'.")
        return None
    
    files.sort(reverse=True)
    return os.path.join(PACKET_LOG_DIR, files[0])

def analyze_connections():
    """Analyze network connections and determine security status."""
    file_path = get_latest_packet_file()
    
    if not file_path:
        print("❌ No captured packets found. Please run 'capture_packets.py' first.")
        return
    
    print(f"🔍 Analyzing network connections from: {file_path}")

    try:
        with open(file_path, "r") as f:
            packets = json.load(f)
    except Exception as e:
        print(f"❌ Error reading packet log: {e}")
        return

    secure_connections = 0
    insecure_connections = 0

    for pkt in packets:
        port = pkt.get("dst_port", 0)
        security_status = PORT_SECURITY_LEVELS.get(port, "✅ Secure (Unknown Risk Level)")

        if "Not Secure" in security_status or "Caution" in security_status:
            insecure_connections += 1
        else:
            secure_connections += 1

    # Determine overall connection security
    overall_security = "✅ Secure" if insecure_connections == 0 else "❌ Not Secure"

    # Save connection analysis report
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(CONN_REPORT_DIR, f"conn_analysis_{timestamp}.json")

    report_data = {
        "timestamp": timestamp,
        "file_analyzed": file_path,
        "overall_security": overall_security
    }

    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=4)

    print(f"✅ Connection analysis complete. Overall Security: {overall_security}")
    print(f"📄 Report saved: {report_path}")

if __name__ == "__main__":
    analyze_connections()
