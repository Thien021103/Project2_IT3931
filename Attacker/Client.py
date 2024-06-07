import socket

def start_client(server_ip, server_port):
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect to the server
    client_socket.connect((server_ip, server_port))
    
    print(f"Connected to server at {server_ip}:{server_port}")
    
    while True:
        # Get user input to send to the server
        message = input("Enter message to send to server (or 'exit' to quit): ")
        
        if message.lower() == 'exit':
            break
        
        # Send the message to the server
        client_socket.send(message.encode())
        
        # Receive the response from the server
        response = client_socket.recv(1024)
        print(f"Received from server: {response.decode()}")
    
    # Close the connection
    client_socket.close()
    print("Connection closed")

# Specify the server IP and port
server_ip = '192.168.56.1'  # Replace with the server's IP address
server_port = 65432      # Replace with the server's port

start_client(server_ip, server_port)