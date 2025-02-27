import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import sniff, TCP, IP

# Function to capture packets
def capture_packets():
    try:
        packets = sniff(count=100, filter="tcp", prn=process_packet, store=False)
    except PermissionError:
        messagebox.showerror("Error", "This script requires root/administrator privileges.")

# Function to process and display each packet
def process_packet(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        
        packet_info = (f"Source IP: {src_ip}, Source Port: {src_port}, \n"
                       f"Destination IP: {dst_ip}, Destination Port: {dst_port}\n")
        
        text_area.insert(tk.END, packet_info)
        text_area.insert(tk.END, "\n")

# GUI setup
root = tk.Tk()
root.title("TCP Port Scanner")
root.geometry("700x500")

label = tk.Label(root, text="Click 'Start Capture' to sniff 100 TCP packets", font=("Helvetica", 14))
label.pack(pady=10)

text_area = scrolledtext.ScrolledText(root, width=80, height=20, font=("Courier", 10))
text_area.pack(padx=10, pady=10)

start_button = tk.Button(root, text="Start Capture", command=capture_packets, font=("Helvetica", 12))
start_button.pack(pady=10)


root.mainloop()