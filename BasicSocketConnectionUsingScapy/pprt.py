import tkinter as tk
from tkinter import messagebox
import socket

# Function to check the port status
def check_port():
    ip = entry_ip.get()
    port = int(entry_port.get())
    try:
        port = int(port)
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid port number.")
        return
    # Valid IP address format (basic check)
    if not ip:
        messagebox.showerror("Invalid Input", "Please enter a valid IP address.")
        return
    
    # Try to connect to the IP address and port
    try:
        # Create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2) # Set timeout to 2 seconds
        result = s.connect_ex((ip, port)) # Try to connect to the port
        if result == 0:
            label_result.config(text=f"Port is open", fg="green")
        else:
            label_result.config(text=f"Port is closed", fg="red")
        s.close()
    except socket.error:
        label_result.config(text=f"Error connecting to the server", fg="red")

# Create the main window
root = tk.Tk()
root.title("Port Status Checker")

# Create labels and entry fields
label_ip = tk.Label(root, text="Enter the IP address:")
label_ip.grid(row=0, column=0, padx=10, pady=10)

entry_ip = tk.Entry(root, width=30)
entry_ip.grid(row=0, column=1, padx=10, pady=10)

label_port = tk.Label(root, text="Enter the port number:")
label_port.grid(row=1, column=0, padx=10, pady=10)

entry_port = tk.Entry(root, width=30)
entry_port.grid(row=1, column=1, padx=10, pady=10)

# Create a button to check the port status
check_button = tk.Button(root, text="Check Port", command=check_port)
check_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

# Label to display the result
label_result = tk.Label(root, text="", font=("Helvetica", 14))
label_result.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

# Run the Tkinter main loop
root.mainloop()