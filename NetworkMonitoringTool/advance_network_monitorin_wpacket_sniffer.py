import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
from scapy.all import sniff, TCP, UDP, ICMP, IP
import threading
import os

# Check if the script is running with root privileges
if os.geteuid() != 0:
    print("This script requires root/administrator privileges. Please run with sudo.")
    messagebox.showerror("Error", "This script requires root/administrator privileges. Please run with sudo.")
    exit(1)

# Initialize the main Tkinter window
root = tk.Tk()
root.title("Advanced Network Monitoring Tool")
root.attributes('-zoomed', True)

# Create a frame for the network monitoring section
monitor_frame = tk.Frame(root)
monitor_frame.pack(fill="x", padx=10, pady=5)  # Reduced padding

# Treeview to display network information
tree = ttk.Treeview(monitor_frame, columns=("Metric", "Value"), show="headings", height=4)  # Reduced height
tree.heading("Metric", text="Metric")
tree.heading("Value", text="Value")
tree.pack(fill="x")

# Matplotlib Figure and Canvas for Visualization
fig, ax = plt.subplots(figsize=(10, 4))  # Reduced figure size (width, height)
ax.set_title("Network I/O Visualization")
ax.set_xlabel("Time (s)")
ax.set_ylabel("Bytes")

canvas = FigureCanvasTkAgg(fig, master=monitor_frame)
canvas.get_tk_widget().pack(fill="x", pady=5)  # Reduced padding

# Create a frame for the packet sniffer section
sniffer_frame = tk.Frame(root)
sniffer_frame.pack(fill="both", expand=True, padx=10, pady=5)  # Reduced padding

# Treeview to display packet information
packet_tree = ttk.Treeview(
    sniffer_frame,
    columns=("Protocol", "Source IP", "Destination IP", "Source Port", "Destination Port"),
    show="headings"
)
packet_tree.heading("Protocol", text="Protocol")
packet_tree.heading("Source IP", text="Source IP")
packet_tree.heading("Destination IP", text="Destination IP")
packet_tree.heading("Source Port", text="Source Port")
packet_tree.heading("Destination Port", text="Destination Port")
packet_tree.pack(fill="both", expand=True)

# Create a frame for filter controls
filter_frame = tk.Frame(sniffer_frame)
filter_frame.pack(fill="x", pady=5)  # Reduced padding

# Dropdown for protocol filter
protocol_label = tk.Label(filter_frame, text="Protocol:")
protocol_label.grid(row=1, column=0, padx=5)
protocol_var = tk.StringVar(value="All")
protocol_dropdown = ttk.Combobox(filter_frame, textvariable=protocol_var, values=["All", "TCP", "UDP", "ICMP"])
protocol_dropdown.grid(row=1, column=1, padx=5)

# Entry for port filter
port_label = tk.Label(filter_frame, text="Port:")
port_label.grid(row=1, column=2, padx=5)
port_var = tk.StringVar()
port_entry = tk.Entry(filter_frame, textvariable=port_var)
port_entry.grid(row=1, column=3, padx=5)

# Button to start packet capture
start_button = tk.Button(filter_frame, text="Start Packet Capture", command=lambda: start_capture())
start_button.grid(row=1, column=4, padx=5)



# Initialize network metrics
metrics = {
    "Bytes Send": 0,
    "Bytes Receive": 0,
    "Packets Send": 0,
    "Packets Receive": 0
}

# Data for the plot
x_data = []
y_sent_data = []
y_received_data = []
start_time = time.time()

# Function to update the Treeview with network statistics
def update_tree():
    net_io = psutil.net_io_counters()
    metrics["Bytes Send"] = net_io.bytes_sent
    metrics["Bytes Receive"] = net_io.bytes_recv
    metrics["Packets Send"] = net_io.packets_sent
    metrics["Packets Receive"] = net_io.packets_recv
    
    # Clear the Treeview and update with new data
    for i in tree.get_children():
        tree.delete(i)
    for key, value in metrics.items():
        tree.insert("", "end", text=key, values=(key, f"{value:,}"))
    
    # Schedule the next update
    root.after(1000, update_tree)

# Function to update the Matplotlib plot
def update_plot():
    current_time = time.time() - start_time
    net_io = psutil.net_io_counters()
    
    x_data.append(current_time)
    y_sent_data.append(net_io.bytes_sent)
    y_received_data.append(net_io.bytes_recv)
    
    # Keep data points limited to 60
    if len(x_data) > 60:
        x_data.pop(0)
        y_sent_data.pop(0)
        y_received_data.pop(0)
    
    # Clear the axes and re-plot
    ax.clear()
    ax.set_title("Network I/O Visualization")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Bytes")
    ax.plot(x_data, y_sent_data, label="Bytes Sent")
    ax.plot(x_data, y_received_data, label="Bytes Received")
    ax.legend()
    
    canvas.draw()
    
    # Schedule the next update
    root.after(1000, update_plot)

# Function to process each packet
def process_packet(packet):
    if IP in packet:
        protocol = ""
        src_port = ""
        dst_port = ""
        
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"
            # ICMP doesn't have ports, so we leave them blank
            src_port = ""
            dst_port = ""
        else:
            # Handle other protocols (optional)
            protocol = "Other"
            src_port = ""
            dst_port = ""
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Apply filters
        filter_protocol = protocol_var.get()
        filter_port = port_var.get()
        
        if (filter_protocol == "All" or filter_protocol == protocol) and \
           (not filter_port or filter_port in (str(src_port), str(dst_port))):
            # Insert packet info into the Treeview
            packet_tree.insert("", "end", values=(protocol, src_ip, dst_ip, src_port, dst_port))
            root.update()  # Force GUI update

# Function to start packet capture
def start_capture():
    # Clear the packet Treeview
    for row in packet_tree.get_children():
        packet_tree.delete(row)
    
    # Start capturing packets in a separate thread
    capture_thread = threading.Thread(target=sniff, kwargs={"prn": process_packet, "store": False})
    capture_thread.daemon = True  # Daemonize thread to exit when the main program exits
    capture_thread.start()

# Start the Monitoring
update_tree()
update_plot()

# Start the Tkinter main loop
root.mainloop()