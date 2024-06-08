from scapy.all import sniff, TCP, IP

# Define the network interface and parameters
interface = "enp0s8"  # Replace with your network interface name
ip_source = "192.168.56.101"  # Replace with the source IP address
ip_destination = "192.168.56.1"  # Replace with the destination IP address

# Function to process and display TCP packet payloads
def process_tcp_packet(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        # Extract the TCP payload
        tcp_payload = bytes(pkt[TCP].payload)
        if tcp_payload:
            try:
                # Decode the payload as UTF-8
                decoded_payload = tcp_payload.decode('utf-8', errors='replace')
                # Determine the direction of the packet and print the payload
                if pkt[IP].src == ip_source and pkt[IP].dst == ip_destination:
                    print(f"From {ip_source} to {ip_destination}: {decoded_payload}")
                elif pkt[IP].src == ip_destination and pkt[IP].dst == ip_source:
                    print(f"From {ip_destination} to {ip_source}: {decoded_payload}")
            except UnicodeDecodeError as e:
                print(f"Failed to decode TCP payload: {e}")

# Capture TCP packets with specific source and destination IP addresses
filter_str = f"tcp and (src host {ip_source} and dst host {ip_destination} or src host {ip_destination} and dst host {ip_source})"
print(f"Starting continuous capture of TCP packets between {ip_source} and {ip_destination} on interface {interface}...")

# Continuous sniffing
sniff(filter=filter_str, iface=interface, prn=process_tcp_packet, store=0)
