import tkinter as tk
from tkinter import ttk
import psutil
import matplotlib.pyplot
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time

# Initialize the main Tkinter window
root = tk.Tk()
root.title("Basic Network Monitoring Tool")
root.geometry("800x600")

# Treeview to display network information
tree = ttk.Treeview(root, columns=("Metric", "Value"), show="headings")
tree.heading("Metric", text="Metric")
tree.heading("Value", text="Value")
tree.pack(pady=10, fill="x")

# Initialize network metrics
metrics = {
    "Bytes Send": 0,
    "Bytes Receive": 0,
    "Packets Send": 0,
    "Packets Receive": 0
}

# Matplotlib Figure and Canvas for Visualization
fig, ax = matplotlib.pyplot.subplots()
ax.set_title("Network I/O Visualization")
ax.set_xlabel("Time (s)")
ax.set_ylabel("Bytes")

canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack(pady=10 , fill="both", expand=True)

# Data for the plot
x_data = []
y_sent_date = []
y_received_date = []
start_time = time.time()

# Function to update the Treeview with network statistics
def updated_tree():
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
    root.after(1000, updated_tree)
    
    # Function to update the Matplotlib plot
def update_plot():
    current_time = time.time() - start_time
    net_io = psutil.net_io_counters()
    
    x_data.append(current_time)
    y_sent_date.append(net_io.bytes_sent)
    y_received_date.append(net_io.bytes_recv)
    
    
    # Keep data points limited to 60
    if len(x_data) > 60:
        x_data.pop(0)
        y_sent_date.pop(0)
        y_received_date.pop(0)
    
    # Clear the axes and re-plot
    ax.clear()
    ax.set_title("Network I/O Visualization")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Bytes")
    ax.plot(x_data, y_sent_date, label="Bytes Sent")
    ax.plot(x_data, y_received_date, label="Bytes Received")
    ax.legend()
    
    canvas.draw()
    
    # Schedule the next update
    root.after(1000, update_plot)
    

# Start the Monitoring
updated_tree()
update_plot()

# Save the Tkinter main loop
root.mainloop()