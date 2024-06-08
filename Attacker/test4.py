from scapy.all import sniff, ARP

# Define the network interface and parameters
interface = "Ethernet 3"  # Replace with your network interface name
packet_count = 10   # Number of packets to capture
timeout = 10        # Timeout in seconds

# Function to display ARP packet details
def display_arp_packet(pkt):
    if ARP in pkt:
        print(f"ARP Packet: {pkt.summary()}")
        if pkt[ARP].op == 1:
            print("Opcode: 1 (ARP Request)")
        elif pkt[ARP].op == 2:
            print("Opcode: 2 (ARP Reply)")

# Capture ARP packets
print(f"Capturing {packet_count} ARP packets on interface {interface} or until timeout of {timeout} seconds...")
arp_packets = sniff(filter="arp", iface=interface, count=packet_count, timeout=timeout)

# Process and display each captured ARP packet
for pkt in arp_packets:
    display_arp_packet(pkt)