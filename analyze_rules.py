import os
import json
import datetime

# Directory where firewall rules are saved
FIREWALL_DIR = "logs/firewall_rules"
REPORT_DIR = "logs/analysis_reports"

# Ensure report directory exists
os.makedirs(REPORT_DIR, exist_ok=True)

def get_latest_firewall_file():
    """Find the latest firewall rules JSON file."""
    files = [f for f in os.listdir(FIREWALL_DIR) if f.endswith(".json")]
    if not files:
        return None
    
    # Get the most recent file based on timestamp in filename
    files.sort(reverse=True)
    return os.path.join(FIREWALL_DIR, files[0])

def analyze_firewall_rules():
    """Analyze latest firewall rules for potential threats."""
    file_path = get_latest_firewall_file()
    
    if not file_path:
        print("❌ No firewall rules found. Please run 'get_firewall_rules.py' first.")
        return
    
    print(f"🔍 Analyzing firewall rules from: {file_path}")
    
    try:
        with open(file_path, "r") as f:
            firewall_rules = json.load(f)
    except Exception as e:
        print(f"❌ Error reading firewall rules: {e}")
        return
    
    threats = []
    
    for rule in firewall_rules:
        action = str(rule.get("Action", "")).lower()  # Convert to string safely
        enabled = bool(rule.get("Enabled", False))  # Ensure boolean value

        if action == "allow" and enabled:  
            if str(rule.get("Direction", "")).lower() == "inbound" and str(rule.get("Profile", "")).lower() == "public":
                threats.append(f"⚠️ Rule '{rule.get('DisplayName', 'Unknown')}' allows inbound traffic on a public network.")

    # Save report
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(REPORT_DIR, f"firewall_analysis_{timestamp}.json")
    
    report_data = {
        "timestamp": timestamp,
        "file_analyzed": file_path,
        "threats_found": threats if threats else ["✅ No major threats detected."]
    }
    
    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=4)
    
    print(f"✅ Analysis complete. Report saved: {report_path}")

if __name__ == "__main__":
    analyze_firewall_rules()
