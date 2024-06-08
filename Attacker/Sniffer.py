from scapy.all import sniff, IP, TCP

# Define the network interface and parameters
interface = "eth0"  # Replace with your network interface name
packet_count = 10   # Number of packets to capture
timeout = 10        # Timeout in seconds
ip_source = "192.168.1.1"  # Replace with the source IP address
ip_destination = "192.168.1.2"  # Replace with the destination IP address

# Function to process and display TCP packet payloads
def process_tcp_packet(pkt):
    if pkt.haslayer(TCP):
        # Extract the TCP payload
        tcp_payload = bytes(pkt[TCP].payload)
        if tcp_payload:
            try:
                # Decode the payload as UTF-8
                decoded_payload = tcp_payload.decode('utf-8', errors='replace')
                print(f"TCP Payload: {decoded_payload}")
            except UnicodeDecodeError as e:
                print(f"Failed to decode TCP payload: {e}")

# Capture TCP packets with specific source and destination IP addresses
filter_str = f"tcp and src host {ip_source} and dst host {ip_destination}"
print(f"Capturing {packet_count} TCP packets from {ip_source} to {ip_destination} on interface {interface} or until timeout of {timeout} seconds...")
tcp_packets = sniff(filter=filter_str, iface=interface, count=packet_count, timeout=timeout)

# Process and display each captured TCP packet's payload
for pkt in tcp_packets:
    process_tcp_packet(pkt)
