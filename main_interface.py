import os
import subprocess
import tkinter as tk
from tkinter import messagebox

# Define the script directory
SCRIPT_DIR = "scripts"

# Function to run a script
def run_script(script_name):
    script_path = os.path.join(SCRIPT_DIR, script_name)
    if os.path.exists(script_path):
        try:
            subprocess.run(["python", script_path], check=True)
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to run {script_name}\n{e}")
    else:
        messagebox.showerror("Error", f"Script not found: {script_name}")

# Initialize the main window
root = tk.Tk()
root.title("Firewall Analyzer")
root.geometry("600x500")
root.configure(bg="#2C3E50")

# UI Header
header = tk.Label(root, text="Select an Option:", font=("Arial", 16, "bold"), bg="#2C3E50", fg="white")
header.pack(pady=20)

# Button Configurations
BUTTON_CONFIG = {
    "Scan WiFi & Capture Packets": "capture_packets.py",
    "Get Firewall Rules": "get_firewall_rules.py",
    "Analyze Firewall Rules": "analyze_rules.py",
    "Backup Firewall Rules": "backup_restore.py",
    "Traffic Threat Analysis": "traffic_analysis.py",
    "AI Threat Analysis": "ai_threat_analysis.py",
    "Connection Analysis": "connection_analysis.py",
}

# Generate buttons dynamically
for text, script in BUTTON_CONFIG.items():
    btn = tk.Button(root, text=text, command=lambda s=script: run_script(s),
                    font=("Arial", 12), bg="#3498DB", fg="white",
                    activebackground="#2980B9", width=40, height=2)
    btn.pack(pady=5)

# Run the main loop
root.mainloop()
