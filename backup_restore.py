import os
import shutil
import json
import subprocess

# Define directories
FIREWALL_DIR = "logs/firewall_rules"
BACKUP_DIR = "logs/firewall_backups"
os.makedirs(BACKUP_DIR, exist_ok=True)

def list_firewall_logs():
    """List all saved firewall rule logs."""
    files = [f for f in os.listdir(FIREWALL_DIR) if f.endswith(".json")]
    return files

def backup_firewall_rules():
    """Backup a selected firewall rules file."""
    files = list_firewall_logs()
    if not files:
        print("No firewall rule logs found.")
        return
    
    # Show available firewall logs
    print("\nAvailable firewall rule logs:")
    for i, file in enumerate(files, 1):
        print(f"{i}. {file}")

    # User selects a file to backup
    choice = int(input("\nEnter the number of the file to backup: ")) - 1
    if 0 <= choice < len(files):
        src_path = os.path.join(FIREWALL_DIR, files[choice])
        dest_path = os.path.join(BACKUP_DIR, files[choice])

        # Copy the file
        shutil.copy(src_path, dest_path)
        print(f"✅ Backup successful: {dest_path}")
    else:
        print("❌ Invalid selection.")

def restore_firewall_rules():
    """Restore a firewall rules backup."""
    files = [f for f in os.listdir(BACKUP_DIR) if f.endswith(".json")]
    if not files:
        print("No backup files found.")
        return

    # Show available backups
    print("\nAvailable backups:")
    for i, file in enumerate(files, 1):
        print(f"{i}. {file}")

    # User selects a file to restore
    choice = int(input("\nEnter the number of the backup to restore: ")) - 1
    if 0 <= choice < len(files):
        backup_file = os.path.join(BACKUP_DIR, files[choice])

        # Load the backup rules
        with open(backup_file, "r") as f:
            firewall_rules = json.load(f)

        # Apply firewall rules using PowerShell
        for rule in firewall_rules:
            cmd = f'powershell -Command "New-NetFirewallRule -DisplayName \'{rule["DisplayName"]}\' -Direction {rule["Direction"]} -Action {rule["Action"]} -Profile {rule["Profile"]}"'
            subprocess.run(cmd, shell=True)

        print(f"✅ Firewall rules restored from {backup_file}")
    else:
        print("❌ Invalid selection.")

if __name__ == "__main__":
    print("1. Backup Firewall Rules")
    print("2. Restore Firewall Rules")
    choice = input("Choose an option (1 or 2): ")

    if choice == "1":
        backup_firewall_rules()
    elif choice == "2":
        restore_firewall_rules()
    else:
        print("❌ Invalid choice.")
