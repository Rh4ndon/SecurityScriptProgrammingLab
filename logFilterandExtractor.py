import tkinter as tk
from tkinter import filedialog
import re

def open_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        process_log(file_path)

def process_log(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    failed_attempts = []
    for line in lines:
        if "Failed password" in line:
        # Extract details using regex
            match = re.search(r'(\w+\s+\d+\s[\d:]+).*Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                timestamp = match.group(1)
                username = match.group(2)
                ip_address = match.group(3)
                failed_attempts.append((timestamp, username, ip_address))
                
    display_results(failed_attempts)
    
def display_results(results):
    results_window = tk.Toplevel(root)
    results_window.title("Failed Login Attempts")
    tk.Label(results_window, text="Timestamp\tUsername\tIP Address").grid(row=0,column=0, sticky="w")
    
    for i, (timestamp, username, ip_address) in enumerate(results, start=1):
        tk.Label(results_window, text=f"{timestamp}\t{username}\t{ip_address}").grid(row=i, column=0, sticky="w")
    
# Create GUI
root = tk.Tk()
root.title("Log Filter and Extractor")

tk.Button(root, text="Open Log File", command=open_file).pack(pady=20)

root.mainloop()