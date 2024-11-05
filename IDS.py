import os
import subprocess
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import threading
import re
from datetime import datetime, timedelta
import matplotlib.pyplot as plt

class IntrusionDetector:
    def __init__(self, root):
        self.root = root
        self.root.title("HAWK EYE")
        
        # Styling options
        button_style = {"font": ("Helvetica", 12), "bg": "#4CAF50", "fg": "white", "padx": 10, "pady": 5, "width": 19}
        label_style = {"font": ("Helvetica", 14, "bold"), "bg": "#282828", "fg": "white"}
        log_style = {"font": ("Courier", 10), "bg": "#333333", "fg": "lightgray"}
        self.root.configure(bg="#282828")  # Set background color
        
        # Header Label
        tk.Label(self.root, text="Network Intrusion Detector", **label_style).pack(pady=10)
        
        # Log output box
        self.log_output = scrolledtext.ScrolledText(root, height=15, width=80, **log_style)
        self.log_output.pack(pady=10)

        # Frame for buttons
        button_frame = tk.Frame(self.root, bg="#282828")
        button_frame.pack(pady=10)

        # Buttons for managing IP lists
        tk.Button(button_frame, text="Block IP", command=self.add_to_blacklist, **button_style).grid(row=0, column=0, padx=10, pady=5)
        tk.Button(button_frame, text="Allow IP", command=self.add_to_whitelist, **button_style).grid(row=0, column=1, padx=10, pady=5)
        tk.Button(button_frame, text="Unblock IP", command=self.remove_from_blacklist, **button_style).grid(row=0, column=2, padx=10, pady=5)
        tk.Button(button_frame, text="Show Blacklist", command=self.show_blacklist, **button_style).grid(row=1, column=0, padx=10, pady=5)
        tk.Button(button_frame, text="Show Whitelist", command=self.show_whitelist, **button_style).grid(row=1, column=1, padx=10, pady=5)
        tk.Button(button_frame, text="Remove from Whitelist", command=self.remove_from_whitelist, **button_style).grid(row=1, column=2, padx=10, pady=5)
        tk.Button(button_frame, text="Refresh Logs", command=self.refresh_logs, **button_style).grid(row=2, column=0, padx=10, pady=5)
        tk.Button(button_frame, text="Show Stats", command=self.show_stats, **button_style).grid(row=2, column=1, padx=10, pady=5)
        tk.Button(button_frame, text="Show Visualization", command=self.show_visualization, **button_style).grid(row=2, column=2, padx=10, pady=5)
        tk.Button(button_frame, text="Open Manual", command=self.open_manual_html, **button_style).grid(row=3, column=1, padx=10, pady=5)

        # Keep track of seen IPs and last scan time to consolidate scans
        self.last_scan_time_by_ip = {}
        self.last_notification_time_by_ip = {}
        self.scan_threshold = timedelta(seconds=60)  # 1 minute threshold for consolidating scans
        self.scan_count = 0
        self.blocked_ips = set()
        self.scan_data_by_ip_and_time = {}

        # Start the log monitoring thread
        thread = threading.Thread(target=self.log_monitor)
        thread.daemon = True
        thread.start()

    def update_text(self, text):
        """Helper function to update GUI in a thread-safe manner."""
        self.log_output.insert(tk.END, text + '\n')
        self.log_output.see(tk.END)

    def log_monitor(self):
        """Monitor the log file for new entries and extract IP addresses."""
        # Clear the previous logs first to prevent old detections
        with open('/var/log/syn_scan.log', 'w') as f:
            f.write('')

        cmd = ['sudo', 'tail', '-f', '/var/log/syn_scan.log']
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True) as proc:
            for line in proc.stdout:
                ip = self.extract_ip(line)
                if ip:
                    now = datetime.now()
                    if ip in self.last_scan_time_by_ip:
                        # Check if the new scan is within the threshold
                        last_scan_time = self.last_scan_time_by_ip[ip]
                        if now - last_scan_time > self.scan_threshold:
                            # If outside the threshold, consider it a new scan
                            self.scan_count += 1
                            self.root.after(0, self.update_text, f"Detected SYN scan from {ip} at {now.strftime('%Y-%m-%d %H:%M:%S')}")
                            self.last_scan_time_by_ip[ip] = now
                            self.log_scan(ip, now)

                            # Send notification if 60 seconds have passed since the last one
                            if ip not in self.last_notification_time_by_ip or now - self.last_notification_time_by_ip[ip] > self.scan_threshold:
                                self.root.after(0, messagebox.showinfo, "SYN Scan Detected", f"SYN scan detected from IP: {ip} at {now.strftime('%Y-%m-%d %H:%M:%S')}")
                                self.last_notification_time_by_ip[ip] = now
                    else:
                        # First time seeing this IP
                        self.scan_count += 1
                        self.root.after(0, self.update_text, f"Detected SYN scan from {ip} at {now.strftime('%Y-%m-%d %H:%M:%S')}")
                        self.last_scan_time_by_ip[ip] = now
                        self.log_scan(ip, now)
                        self.root.after(0, messagebox.showinfo, "SYN Scan Detected", f"SYN scan detected from IP: {ip} at {now.strftime('%Y-%m-%d %H:%M:%S')}")
                        self.last_notification_time_by_ip[ip] = now

    def log_scan(self, ip, timestamp):
        """Log scan data for visualization."""
        if ip not in self.scan_data_by_ip_and_time:
            self.scan_data_by_ip_and_time[ip] = []
        self.scan_data_by_ip_and_time[ip].append(timestamp.strftime('%Y-%m-%d %H:%M:%S'))

    def extract_ip(self, log_entry):
        """Extract IP from log entry."""
        match = re.search(r"SRC=(\d+\.\d+\.\d+\.\d+)", log_entry)
        return match.group(1) if match else None

    def add_to_blacklist(self):
        """Add an IP to the blacklist and remove it from whitelist (if present)."""
        ip = simpledialog.askstring("Block IP", "Enter IP to block:")
        if ip:
            if self.is_ip_in_whitelist(ip):
                self.update_nftables(ip, block=False, remove=True, whitelist=True)  # Remove from whitelist
            if not self.is_ip_in_blacklist(ip):
                self.update_nftables(ip, block=True)
                self.blocked_ips.add(ip)  # Add to blocked IPs set

    def add_to_whitelist(self):
        """Add an IP to the whitelist with password protection and remove it from blacklist (if present)."""
        ip = simpledialog.askstring("Allow IP", "Enter IP to allow:")
        if ip:
            password = simpledialog.askstring("Password", "Enter password:", show="*")
            if password == "hawkeye":  # Replace with your desired password
                if self.is_ip_in_blacklist(ip):
                    self.update_nftables(ip, block=True, remove=True)  # Remove from blacklist
                if not self.is_ip_in_whitelist(ip):
                    self.update_nftables(ip, block=False)
            else:
                messagebox.showerror("Error", "Incorrect password. IP not added to whitelist.")

    def remove_from_blacklist(self):
        """Remove an IP from the blacklist."""
        ip = simpledialog.askstring("Unblock IP", "Enter IP to remove from blacklist:")
        if ip:
            if self.is_ip_in_blacklist(ip):
                self.update_nftables(ip, block=False, remove=True)
                self.blocked_ips.discard(ip)  # Remove from blocked IPs set

    def remove_from_whitelist(self):
        """Remove an IP from the whitelist."""
        ip = simpledialog.askstring("Remove from Whitelist", "Enter IP to remove from whitelist:")
        if ip:
            if self.is_ip_in_whitelist(ip):
                self.update_nftables(ip, block=False, remove=True, whitelist=True)

    def is_ip_in_blacklist(self, ip):
        """Check if an IP is already in the blacklist."""
        cmd = "sudo nft list set inet filter blacklist"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=True)
        return ip in result.stdout

    def is_ip_in_whitelist(self, ip):
        """Check if an IP is already in the whitelist."""
        cmd = "sudo nft list set inet filter whitelist"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=True)
        return ip in result.stdout

    def update_nftables(self, ip, block=True, remove=False, whitelist=False):
        """Update nftables with an IP for blocking, allowing, or removing."""
        if remove:
            if whitelist:
                cmd = f"sudo nft delete element inet filter whitelist {{ {ip} }}"
            else:
                cmd = f"sudo nft delete element inet filter blacklist {{ {ip} }}"
        elif block:
            cmd = f"sudo nft add element inet filter blacklist {{ {ip} }}"
        else:
            cmd = f"sudo nft add element inet filter whitelist {{ {ip} }}"
        
        try:
            subprocess.run(cmd, shell=True, check=True)
            action = "removed from whitelist" if (remove and whitelist) else ("removed from blacklist" if remove else ("blocked" if block else "allowed"))
            self.update_text(f"IP {ip} has been {action}.")
        except subprocess.CalledProcessError as e:
            action = "remove from whitelist" if (remove and whitelist) else ("remove from blacklist" if remove else ("block" if block else "allow"))
            self.update_text(f"Failed to {action} IP {ip}: {str(e)}")

    def show_blacklist(self):
        """Display the current blacklist."""
        cmd = "sudo nft list set inet filter blacklist"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=True)

        if "elements =" in result.stdout:
            blacklist_entries = result.stdout.split("elements = {")[1].split("}")[0].strip()
            if blacklist_entries:
                messagebox.showinfo("Blacklist", f"Blacklisted IPs:\n{blacklist_entries}")
            else:
                messagebox.showinfo("Blacklist", "The blacklist is currently empty.")
        else:
            messagebox.showinfo("Blacklist", "The blacklist is currently empty.")

    def show_whitelist(self):
        """Display the current whitelist."""
        cmd = "sudo nft list set inet filter whitelist"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=True)

        if "elements =" in result.stdout:
            whitelist_entries = result.stdout.split("elements = {")[1].split("}")[0].strip()
            if whitelist_entries:
                messagebox.showinfo("Whitelist", f"Whitelisted IPs:\n{whitelist_entries}")
            else:
                messagebox.showinfo("Whitelist", "The whitelist is currently empty.")
        else:
                messagebox.showinfo("Whitelist", "The whitelist is currently empty.")

    def refresh_logs(self):
        """Clear seen IPs and refresh log display."""
        self.seen_ips.clear()
        self.log_output.delete(1.0, tk.END)
        self.log_output.insert(tk.END, "Logs refreshed.\n")

    def show_stats(self):
        """Show basic stats such as number of scans and blocked IPs."""
        messagebox.showinfo("Stats", f"Scans Today: {self.scan_count}\nBlocked IPs: {len(self.blocked_ips)}")

    def show_visualization(self):
        """Show the visualization of scan data."""
        if self.scan_data_by_ip_and_time:
            times = []
            ips = []
            for ip, timestamps in self.scan_data_by_ip_and_time.items():
                for timestamp in timestamps:
                    times.append(timestamp)
                    ips.append(ip)

            if times and ips:
                # Create the graph
                plt.figure(figsize=(10, 6))
                plt.scatter(times, ips, marker='o', color='blue')  # Scatter plot for clarity
                plt.xlabel('Date and Time')
                plt.ylabel('IP Address')
                plt.xticks(rotation=45, ha="right")
                plt.title('Scans by IP and Time')
                plt.tight_layout()
                plt.show()
            else:
                messagebox.showinfo("Stats", "No scan data available.")
        else:
            messagebox.showinfo("Stats", "No scan data available.")

    # Method to open the HTML manual page
    def open_manual_html(self):
        """Open the HTML manual page using subprocess."""
        try:
            subprocess.run(["sudo", "-u", os.getenv("SUDO_USER"), "xdg-open", "/home/abin/Desktop/Project/manual.html"], check=True)
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to open manual: {e}")

if __name__ == '__main__':
    root = tk.Tk()
    app = IntrusionDetector(root)
    root.mainloop()

