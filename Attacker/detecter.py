import socket
import struct
from collections import defaultdict

def get_mac_address(mac_raw):
    return ':'.join('%02x' % b for b in mac_raw)

def get_ip_address(ip_raw):
    return '.'.join(map(str, ip_raw))

def parse_arp_packet(packet):
    ethernet_header = packet[0:14]
    arp_header = packet[14:42]
    
    eth = struct.unpack("!6s6s2s", ethernet_header)
    arp = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
    
    src_mac = get_mac_address(arp[5])
    src_ip = get_ip_address(arp[6])
    dest_mac = get_mac_address(arp[7])
    dest_ip = get_ip_address(arp[8])
    
    return src_mac, src_ip, dest_mac, dest_ip

def detect_arp_spoofing(interface):
    # Create a raw socket and bind it to the interface
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    raw_socket.bind((interface, 0))
    
    arp_table = defaultdict(list)
    
    try:
        while True:
            packet = raw_socket.recvfrom(65565)[0]
            ethertype = struct.unpack("!6s6sH", packet[0:14])[2]
            
            if ethertype == 0x0806:  # ARP packet
                src_mac, src_ip, dest_mac, dest_ip = parse_arp_packet(packet)
                
                if src_ip in arp_table:
                    if src_mac not in arp_table[src_ip]:
                        print(f"ARP Spoofing detected! IP: {src_ip} is being spoofed.")
                        print(f"Original MACs: {arp_table[src_ip]}, Spoofed MAC: {src_mac}")
                        arp_table[src_ip].append(src_mac)
                else:
                    arp_table[src_ip].append(src_mac)
    
    except KeyboardInterrupt:
        print("\nARP Spoofing detection stopped.")
        raw_socket.close()

if __name__ == "__main__":
    interface = "eth0"  # Thay thế bằng tên giao diện mạng của bạn
    detect_arp_spoofing(interface)
