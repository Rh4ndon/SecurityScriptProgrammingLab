import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
from scapy.all import sniff, TCP, IP
import threading
import os

# Check if the script is running with root privileges
if os.geteuid() != 0:
    print("This script requires root privileges. Please run with sudo.")
    messagebox.showerror("Error", "This script requires root privileges. Please run with sudo.")
    exit(1)
    


# Initialize the main Tkinter window
root = tk.Tk()
root.title("Packet Sniffer")
root.geometry("1080x720")

label = tk.Label(root, text="Click 'Start Capture' to sniff 100 TCP packets", font=("Helvetica", 14))
label.pack(pady=10)

# Create a frame for the packet sniffer section
sniffer_frame = tk.Frame(root)
sniffer_frame.pack(fill="both", expand=True, padx=10, pady=10)

# Treeview to display packet information
packet_tree = ttk.Treeview(sniffer_frame, columns=("Source IP", "Destination IP", "Source Port", "Destination Port"), show="headings")
packet_tree.heading("Source IP", text="Source IP")
packet_tree.heading("Destination IP", text="Destination IP")
packet_tree.heading("Source Port", text="Source Port")
packet_tree.heading("Destination Port", text="Destination Port")
packet_tree.pack(fill="both", expand=True)

# Button to start packet capture
start_button = tk.Button(sniffer_frame, text="Start Packet Capture", command=lambda: start_capture())
start_button.pack(pady=10)


# Function to process each packet
def process_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        
        # Insert packet info into the Treeview
        packet_tree.insert("", "end", values=(src_ip, dst_ip, src_port, dst_port))
        root.update()  # Force GUI update

# Function to start packet capture
def start_capture():
    # Clear the packet Treeview
    for row in packet_tree.get_children():
        packet_tree.delete(row)
    
    # Start capturing packets in a separate thread
    capture_thread = threading.Thread(target=sniff, kwargs={"filter": "tcp", "prn": process_packet, "count": 100})
    capture_thread.daemon = True  # Daemonize thread to exit when the main program exits
    capture_thread.start()


# Start the Tkinter main loop
root.mainloop()