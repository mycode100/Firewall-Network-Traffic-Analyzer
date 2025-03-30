# **🔹 Firewall & Network Traffic Analyzer**  

🚀 **Firewall & Network Traffic Analyzer** is a Python-based security tool that captures network traffic, analyzes firewall rules, and performs AI-driven threat detection to ensure system security.

---

## **📌 Features**
✅ **Packet Capture & Logging** – Captures network packets for analysis.  
✅ **Firewall Rule Analysis** – Checks Windows Firewall rules for threats.  
✅ **Traffic Threat Analysis** – Identifies suspicious network activity.  
✅ **AI-Based Threat Detection** – Uses a trained model to detect potential attacks.  
✅ **Connection Security Analysis** – Determines whether network connections are secure.  
✅ **Firewall Backup & Restore** – Saves and restores firewall settings.  

---

## **📁 Directory Structure**
```
FirewallAnalyzer/
│── logs/
│   ├── packets/                # Captured network traffic logs
│   ├── firewall_rules/         # Firewall rules logs
│   ├── ai_analysis_reports/    # AI-based threat analysis reports
│   ├── connection_reports/     # Secure vs. insecure connections reports
│── models/
│   ├── ai_threat_model.pkl     # Pre-trained AI model for threat detection
│── scripts/
│   ├── capture_packets.py      # Captures network packets and saves them
│   ├── analyze_rules.py        # Analyzes firewall rules for threats
│   ├── traffic_analysis.py     # Detects suspicious network activity
│   ├── ai_threat_analysis.py   # AI-based threat detection
│   ├── connection_analysis.py  # Determines secure vs. insecure connections
│── README.md                   # Documentation
│── requirements.txt             # Required dependencies
```

---

## **📦 Installation & Setup**
### **1️⃣ Install Python & Dependencies**
Ensure you have **Python 3.8+** installed.  
Then, install the required packages:
```bash
pip install -r requirements.txt
```

### **2️⃣ Run Scripts**
#### **🔍 1. Capture Network Packets**
Start capturing network traffic:
```bash
python scripts/capture_packets.py
```
- This script saves packets in `logs/packets/packet_log_<timestamp>.json`.

#### **🔥 2. Analyze Firewall Rules**
Check your Windows Firewall for risks:
```bash
python scripts/analyze_rules.py
```
- Saves results in `logs/firewall_rules/firewall_rules_<timestamp>.json`.

#### **🛡️ 3. Traffic Threat Analysis**
Analyze network packets for suspicious activity:
```bash
python scripts/traffic_analysis.py
```
- Identifies attacks based on destination ports & known malicious IPs.

#### **🤖 4. AI-Based Threat Detection**
Uses a pre-trained AI model to classify network threats:
```bash
python scripts/ai_threat_analysis.py
```
- Requires `models/ai_threat_model.pkl` (train if missing).
- Saves AI analysis reports in `logs/ai_analysis_reports/`.

#### **🔐 5. Secure vs. Insecure Connection Analysis**
Classifies connections as **secure** or **not secure**:
```bash
python scripts/connection_analysis.py
```
- Saves a **single security status** (`"Secure"` or `"Not Secure"`) in `logs/connection_reports/`.

#### **💾 6. Backup & Restore Firewall Rules**
Backup current firewall rules:
```bash
python scripts/firewall_backup.py
```
Restore saved rules:
```bash
python scripts/firewall_restore.py
```

---

## **⚙️ How It Works**
### **🔍 Packet Capture**
- Captures live network packets using `scapy`.
- Logs **IP addresses, ports, protocols**, and **timestamps**.

### **🔥 Firewall Rule Analysis**
- Extracts Windows Firewall rules using PowerShell.
- Checks for **dangerous inbound/outbound rules**.

### **🚨 Threat Detection**
- Detects suspicious activities like:
  - **Access to insecure ports (HTTP, RDP, SMB, etc.).**
  - **Connections to known malicious IPs.**
  - **Unusual traffic behavior.**

### **🤖 AI Threat Detection**
- Uses **Random Forest Classifier** to predict if a connection is dangerous.
- Features used:
  - **Destination Port**
  - **Protocol Type (TCP/UDP)**
  - **Known Malicious IP Flag**
  - **Packet Size (if available)**

### **🔐 Secure Connection Analysis**
- Compares destination ports with known risk levels.
- Reports **"Secure"** or **"Not Secure"** based on threats detected.

---

## **🔴 Considerations**
⚠️ **Run scripts as Administrator** (some firewall functions require admin access).  
⚠️ **Ensure an AI model is trained** (`ai_threat_model.pkl`) before using AI detection.  
⚠️ **Data stored locally** – No external communication happens.  

---

## **📌 To-Do & Future Updates**
✅ Improve **AI threat detection model** with more training data.  
✅ Add **real-time alert system** for detected threats.  
✅ Integrate with **network visualization tools**.  

---

## **🙌 Contributors**
- 🔹  MOPURU VENKATA SRIKANTH REDDY {DEVELOPER}   
- 💡  SURYA VARDHAN {TEAM MEMBER}

🚀 **Enjoy Secure Network Analysis!** Let me know if you need enhancements! 😊
