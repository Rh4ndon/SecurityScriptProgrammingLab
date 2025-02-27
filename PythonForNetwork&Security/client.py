import socket
import tkinter as tk

# Function to send a message to the server
def send_message():
    message = message_entry.get()
    if message:
        # Create a socket to connect to the server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(("localhost", 65432))
        
        # Send the message to the server
        client_socket.sendall(message.encode())
        
        # Receive the server's response
        response = client_socket.recv(1024).decode('utf-8')
        response_label.config(text="Server response: " + response)
        
        # Close the connection
        client_socket.close()
        
        
# Set up the GUI window
window = tk.Tk()
window.title("Client-Server Communication")

# Label and text entry for the message
message_label = tk.Label(window, text="Enter your message:")
message_label.pack()

# Text entry for the message
message_entry = tk.Entry(window)
message_entry.pack()

# Button to send the message
send_button = tk.Button(window, text="Send", command=send_message)
send_button.pack()

# Label to display the server's response
response_label = tk.Label(window, text="Server Response: ")
response_label.pack()

# Run the Tkinter main loop
window.mainloop()    
    