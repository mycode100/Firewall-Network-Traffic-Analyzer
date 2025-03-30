import os
import json
import datetime
import subprocess

# Directory to store firewall rules
FIREWALL_DIR = "logs/firewall_rules"
os.makedirs(FIREWALL_DIR, exist_ok=True)

def get_firewall_rules():
    """Extract Windows Firewall rules and save them as JSON."""
    try:
        print("Fetching Windows Firewall rules...")
        
        # Run PowerShell command to get firewall rules in JSON format
        command = 'powershell -Command "Get-NetFirewallRule | Select-Object DisplayName, Direction, Action, Enabled, Profile | ConvertTo-Json"'
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        
        # Parse JSON output
        firewall_rules = json.loads(result.stdout) if result.stdout else []
        
        if not firewall_rules:
            print("No firewall rules found.")
            return
        
        # Save the rules to a JSON file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = os.path.join(FIREWALL_DIR, f"firewall_rules_{timestamp}.json")
        
        with open(file_path, "w") as f:
            json.dump(firewall_rules, f, indent=4)
        
        print(f"Firewall rules saved successfully: {file_path}")
    
    except Exception as e:
        print(f"Error fetching firewall rules: {e}")

if __name__ == "__main__":
    get_firewall_rules()
