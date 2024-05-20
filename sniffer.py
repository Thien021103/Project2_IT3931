import socket
import struct

# Create a raw socket
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

# Specify the network interface to sniff on (e.g., eth0)
interface = "enp0s8"

# Sniff HTTP packets
while True:
    packet = s.recvfrom(65565)[0]  # Adjust buffer size as needed
    # Extract Ethernet, IP, and TCP headers
    eth_length = 14
    eth_header = packet[:eth_length]
    ip_header = packet[eth_length:20+eth_length]
    ip_header_fields = struct.unpack("!BBHHHBBH4s4s", ip_header)
    protocol = ip_header_fields[6]
    if protocol == 6:  # Check if the protocol is TCP
        tcp_header_offset = eth_length + (ip_header_fields[0] & 0xF) * 4
        tcp_header = packet[tcp_header_offset:tcp_header_offset + 20]
        tcp_header_fields = struct.unpack("!HHLLBBHHH", tcp_header)
        src_port = tcp_header_fields[0]
        dst_port = tcp_header_fields[1]
        if dst_port == 80 or dst_port == 443:  # Check if the destination port is HTTP (80) or HTTPS (443)
            http_data_offset = tcp_header_offset + (tcp_header_fields[4] >> 4) * 4
            http_data = packet[http_data_offset:]

            # Filter out non-printable characters
            filtered_data = b''.join([x for x in http_data if x in range(32, 127) or x == 10 or x == 13])

            # Process HTTP packet here

            print(filtered_data.decode('utf-8', errors='ignore'))