import socket
import struct
import platform

def get_interface():
    system = platform.system()
    if system == "Windows":
        # On Windows, use the default interface
        return socket.gethostbyname(socket.gethostname())
    elif system == "Linux":
        # On Linux, specify the interface name (e.g., "enp0s8")
        return "enp0s8"  # Change this to your desired interface
    else:
        raise Exception("Unsupported operating system")

def sniff_tcp_packets(interface):
    # Create a raw socket
    if platform.system() == "Windows":
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    elif platform.system() == "Linux":
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))  # 0x0003 is ETH_P_ALL
    else:
        raise Exception("Unsupported operating system")
    
    # Bind the socket to the specified network interface
    s.bind((interface, 0))

    while True:
        # Receive packets
        packet = s.recvfrom(65565)
        
        # Extract the packet data
        packet_data = packet[0]
        
        # Extract the Ethernet header
        eth_length = 14
        eth_header = packet_data[:eth_length]
        eth_header = struct.unpack("!6s6sH", eth_header)
        
        # IP header starts after the Ethernet header
        ip_header = packet_data[eth_length:]
        
        # Extract the protocol
        protocol = ip_header[9]
        
        # Check if it's a TCP packet (protocol number 6)
        if protocol == 6:
            # Extract the TCP payload
            tcp_header = ip_header[20:]
            tcp_payload = tcp_header[32:]
            
            # Check if it has payload
            if tcp_payload and len(tcp_payload) > 0:
                try:
                    # Decode the TCP payload as UTF-8
                    decoded_payload = tcp_payload.decode('utf-8')
                    print(decoded_payload)
                except UnicodeDecodeError:
                    continue
                    
if __name__ == "__main__":
    # Specify the interface
    interface = get_interface()
    sniff_tcp_packets(interface)
