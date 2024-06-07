import socket

def handle_http_request(client_socket):
    # Receive the request from the client
    request_data = b''
    while True:
        chunk = client_socket.recv(4096)
        if not chunk:
            break
        request_data += chunk

    request_data = request_data.decode('utf-8')
    print(request_data)

    # Send a response back to the client
    response = 'HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!'
    client_socket.sendall(response.encode())

# Example usage:
server_address = '127.0.0.1'  # Listen on all available network interfaces
server_port = 8080

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reuse of the address
server_socket.bind((server_address, server_port))
server_socket.listen(1)

print(f'Server listening on {server_address}:{server_port}...')

try:
    while True:
        client_socket, client_address = server_socket.accept()
        print(f'Connection from {client_address}')
        handle_http_request(client_socket)
        client_socket.close()
except KeyboardInterrupt:
    print("Server shutting down...")
    server_socket.close()
