import socket
import threading


def handle_client(client_socket):
    # Receive data from the client
    msg = client_socket.recv(1024).decode('utf-8')
    print(f"Received message: {msg}")
    
    #@ Send a response back to the client
    client_socket.send("Message received".encode('utf-8'))
    
    # Close the client socket
    client_socket.close()
    

def start_server():
    # Define server host and port
    host = '127.0.0.1'
    port = 65432
    
    # Set up the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    
    print(f"Server listening on {host}:{port}")
    
    while True:
        # Accept client connections
        client_socket, addr = server_socket.accept()
        print(f"Connected to {addr}")
        
        # Handle each client in a new thread
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()
        
if __name__ == '__main__':
    start_server()