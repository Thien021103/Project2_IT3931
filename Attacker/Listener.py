import socket

def start_server(interface, port):
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Bind the socket to the provided interface and port
    server_socket.bind((interface, port))
    
    # Listen for incoming connections (max 5 queued connections)
    server_socket.listen(5)
    
    print(f"Server listening on {interface}:{port}")
    
    while True:
        # Accept a new connection
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")
        
        # Communicate with the client
        while True:
            # Receive data from the client
            data = client_socket.recv(1024)
            if not data:
                # If no data is received, break out of the loop
                break
            
            print(f"Received from client: {data.decode()}")
            
            # Send a response back to the client
            response = input("Enter response to client: ")
            client_socket.send(response.encode())
        
        # Close the client socket
        client_socket.close()
        print(f"Connection with {client_address} closed")

# Specify the interface and port
interface = '192.168.56.1'  # localhost
port = 65432

start_server(interface, port)
