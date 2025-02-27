import tkinter as tk
from tkinter import messagebox
import socket
from threading import Thread

# Function to check the port status
def scan_port(ip, port):
    try:
        # Create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)  # Set timeout to 2 seconds
        result = s.connect_ex((ip, port))  # Try to connect to the port
        if result == 0:
            result_text.insert(tk.END, f"Port {port} is open\n", "open")
        else:
            result_text.insert(tk.END, f"Port {port} is closed\n", "closed")
        s.close()
    except socket.error:
        result_text.insert(tk.END, f"Error connecting to port {port}\n", "error")

# Function to start the scan
def start_scan():
    ip = entry_ip.get()
    port_range = entry_port_range.get()

    # Validate IP address
    if not ip:
        messagebox.showerror("Invalid Input", "Please enter a valid IP address.")
        return

    # Validate port range
    try:
        start_port, end_port = map(int, port_range.split("-"))
        if start_port > end_port or start_port < 1 or end_port > 65535:
            messagebox.showerror("Invalid Input", "Please enter a valid port range (1-65535).")
            return
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid port range (e.g., 20-1024).")
        return

    # Clear previous results
    result_text.delete(1.0, tk.END)

    # Start scanning ports in a separate thread
    def scan_ports():
        for port in range(start_port, end_port + 1):
            scan_port(ip, port)

    Thread(target=scan_ports, daemon=True).start()

# Function to clear results and input fields
def clear_results():
    entry_ip.delete(0, tk.END)
    entry_port_range.delete(0, tk.END)
    result_text.delete(1.0, tk.END)

# Create the main window
root = tk.Tk()
root.title("Port Scanner")

# Create labels and entry fields
label_ip = tk.Label(root, text="Enter the IP address or hostname:")
label_ip.grid(row=0, column=0, padx=10, pady=10)

entry_ip = tk.Entry(root, width=30)
entry_ip.grid(row=0, column=1, padx=10, pady=10)

label_port_range = tk.Label(root, text="Enter the port range (e.g., 20-1024):")
label_port_range.grid(row=1, column=0, padx=10, pady=10)

entry_port_range = tk.Entry(root, width=30)
entry_port_range.grid(row=1, column=1, padx=10, pady=10)

# Create a button to start the scan
scan_button = tk.Button(root, text="Start Scan", command=start_scan)
scan_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

# Create a button to clear the results and input fields
clear_button = tk.Button(root, text="Clear Results", command=clear_results)
clear_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

# Text widget to display the results in real-time
result_text = tk.Text(root, height=15, width=50)
result_text.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

# Configure text colors for open, closed, and error messages
result_text.tag_config("open", foreground="green")
result_text.tag_config("closed", foreground="red")
result_text.tag_config("error", foreground="orange")

# Run the Tkinter main loop
root.mainloop()