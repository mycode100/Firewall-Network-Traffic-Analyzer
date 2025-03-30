import os
import json
import joblib  # For loading trained ML models
import datetime
import numpy as np

# ✅ Corrected log directory path
PACKET_LOG_DIR = "logs/packets"
AI_REPORT_DIR = "logs/ai_analysis_reports"
MODEL_PATH = "models/ai_threat_model.pkl"

# Ensure AI report directory exists
os.makedirs(AI_REPORT_DIR, exist_ok=True)

# Load trained AI model
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        expected_features = model.n_features_in_  # Get the number of features the model expects
    except Exception as e:
        print(f"❌ Error loading AI model: {e}")
        exit()
else:
    print("⚠️ AI Model not found. Train and save a model first.")
    exit()

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

def extract_features(packet):
    """Extract numerical features for AI analysis."""
    features = [
        int(packet.get("dst_port", 0)),  # Destination port
        1 if packet.get("protocol") == "TCP" else 0,  # Protocol (TCP = 1, UDP = 0)
        1 if packet.get("src_ip") in ["192.168.1.100"] else 0,  # Known malicious IP (example)
    ]

    # ✅ Add a missing feature (Example: Packet size)
    features.append(int(packet.get("packet_size", 0)))  # Example: Packet size

    return features

def ai_threat_analysis():
    """Perform AI-based threat analysis on captured packets."""
    file_path = get_latest_packet_file()
    
    if not file_path:
        print("❌ No captured packets found. Please run 'capture_packets.py' first.")
        return
    
    print(f"🔍 Analyzing packets with AI from: {file_path}")

    try:
        with open(file_path, "r") as f:
            packets = json.load(f)
    except Exception as e:
        print(f"❌ Error reading packet log: {e}")
        return

    threat_results = []

    for pkt in packets:
        try:
            features = np.array(extract_features(pkt)).reshape(1, -1)

            # ✅ Check feature length before prediction
            if features.shape[1] != expected_features:
                print(f"❌ Error: Model expects {expected_features} features, but got {features.shape[1]}")
                continue

            risk_score = model.predict_proba(features)[0][1]  # Probability of being a threat
        except Exception as e:
            print(f"❌ Error processing packet: {e}")
            continue

        if risk_score > 0.75:
            threat_level = "⚠️ Critical"
        elif risk_score > 0.4:
            threat_level = "⚠️ High"
        else:
            threat_level = "✅ Safe"

        threat_results.append({
            "src_ip": pkt.get("src_ip", "Unknown"),
            "dst_ip": pkt.get("dst_ip", "Unknown"),
            "protocol": pkt.get("protocol", "Unknown"),
            "port": pkt.get("dst_port", 0),
            "packet_size": pkt.get("packet_size", "Unknown"),  # ✅ Include packet size
            "risk_score": round(risk_score, 2),
            "threat_level": threat_level
        })

    # Save AI threat analysis report
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(AI_REPORT_DIR, f"ai_analysis_{timestamp}.json")

    report_data = {
        "timestamp": timestamp,
        "file_analyzed": file_path,
        "ai_threats_found": threat_results if threat_results else ["✅ No threats detected."]
    }

    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=4)

    print(f"✅ AI-based analysis complete. Report saved: {report_path}")

if __name__ == "__main__":
    ai_threat_analysis()
