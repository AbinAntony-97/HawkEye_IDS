import time
import re
import subprocess
import tkinter as tk
from tkinter import messagebox

# Global list for whitelist and dictionary to track SYN scans
whitelist = ["192.168.1.1", "10.0.0.1"]  # Initial whitelist (editable by user)
syn_scan_counts = {}
SCAN_THRESHOLD = 5
LOG_FILE = "/var/log/syslog"  # Change based on your system

# Function to block an IP using IPTables
def block_ip(ip_address):
    if ip_address in whitelist:
        log_message(f"IP {ip_address} is whitelisted. Skipping block.")
    else:
        log_message(f"Blocking IP: {ip_address}")
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"])

# Function to process SYN scans from logs
def process_syn_scan(line):
    match = re.search(r"SRC=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
    if match:
        ip_address = match.group(1)
        log_message(f"Detected SYN scan from {ip_address}")

        # Track SYN scans from this IP
        if ip_address in syn_scan_counts:
            syn_scan_counts[ip_address] += 1
        else:
            syn_scan_counts[ip_address] = 1

        # Block IP if it exceeds the scan threshold
        if syn_scan_counts[ip_address] >= SCAN_THRESHOLD:
            block_ip(ip_address)

# Function to monitor log file in real-time
def monitor_logs():
    with open(LOG_FILE, "r") as log:
        log.seek(0, 2)
        while True:
            line = log.readline()
            if line and "SYN_SCAN:" in line:
                process_syn_scan(line)
            else:
                time.sleep(1)

# Function to add IP to whitelist
def add_to_whitelist():
    new_ip = entry_ip.get()
    if re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", new_ip):
        if new_ip not in whitelist:
            whitelist.append(new_ip)
            log_message(f"Added IP {new_ip} to whitelist.")
        else:
            messagebox.showinfo("Info", f"IP {new_ip} is already whitelisted.")
    else:
        messagebox.showerror("Error", "Invalid IP address format.")

# Function to display log messages in the GUI
def log_message(message):
    text_log.insert(tk.END, message + "\n")
    text_log.see(tk.END)

# GUI Setup
def start_gui():
    global entry_ip, text_log

    # Create the main window
    root = tk.Tk()
    root.title("Intrusion Detection System GUI")
    root.geometry("500x400")

    # IP Entry Label and Field
    label_ip = tk.Label(root, text="Enter IP to Whitelist:")
    label_ip.pack(pady=5)

    entry_ip = tk.Entry(root, width=30)
    entry_ip.pack(pady=5)

    # Add to Whitelist Button
    btn_add = tk.Button(root, text="Add to Whitelist", command=add_to_whitelist)
    btn_add.pack(pady=5)

    # Start Monitoring Button
    btn_start_monitor = tk.Button(root, text="Start Monitoring", command=lambda: subprocess.Popen(monitor_logs))
    btn_start_monitor.pack(pady=10)

    # Log Display Area (Scrolled Text)
    text_log = tk.Text(root, height=10, width=50)
    text_log.pack(pady=10)

    # Start the GUI loop
    root.mainloop()

# Start the GUI
start_gui()
