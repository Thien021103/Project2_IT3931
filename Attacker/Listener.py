def handle_http_request(client_socket):
    # Receive the request from the client
    request_data = client_socket.recv(4096).decode('utf-8')
    print(request_data)

    # Send a response back to the client
    response = 'POST/ post HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'
    client_socket.sendall(response.encode())

# Example usage:
import socket

server_address = '0.0.0.0'
server_port = 80

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((server_address, server_port))
server_socket.listen(1)

print(f'Server listening on {server_address}:{server_port}...')

while True:
    client_socket, client_address = server_socket.accept()
    print(f'Connection from {client_address}')
    handle_http_request(client_socket)
    client_socket.close()
