import socket
import struct

def sniff_packets(interface):
    # Create a raw socket and bind it to the interface
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sniffer.bind((interface, 0))

    print(f"Listening on {interface}")

    while True:
        # Capture packets
        raw_data, addr = sniffer.recvfrom(65536)
        eth_proto, data = ethernet_frame(raw_data)
        if eth_proto == 8:  # IPv4
            ip_proto, data = ipv4_packet(data)
            if ip_proto == 6:  # TCP
                src_port, dest_port, data = tcp_segment(data)
                if len(data) > 0:
                    print(f"TCP Packet from {src_port} to {dest_port}:")
                    print(data)

def ethernet_frame(data):
    eth_header = struct.unpack('!6s6sH', data[:14])
    eth_proto = socket.ntohs(eth_header[2])
    return eth_proto, data[14:]

def ipv4_packet(data):
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version_header_length = ip_header[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    proto = ip_header[6]
    src = socket.inet_ntoa(ip_header[8])
    dest = socket.inet_ntoa(ip_header[9])
    return proto, data[header_length:]

def tcp_segment(data):
    tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
    src_port = tcp_header[0]
    dest_port = tcp_header[1]
    data_offset = (tcp_header[4] >> 4) * 4
    return src_port, dest_port, data[data_offset:]

if __name__ == "__main__":
    INTERFACE = "eth0"  # Change this to your network interface
    sniff_packets(INTERFACE)
