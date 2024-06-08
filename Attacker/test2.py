from scapy.all import ARP, Ether, srp

def send_arp_request(target_ip):
    # Craft ARP request packet
    arp_request = ARP(pdst=target_ip)

    # Craft Ethernet frame
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine Ethernet frame and ARP request packet
    packet = ether_frame / arp_request

    # Send packet and receive responses
    result = srp(packet, timeout=2, iface='Ethernet 3', verbose=False)[0]

    # Check for response
    if result:
        for sent, received in result:
            if received.haslayer(ARP):
                print(f"IP: {received.psrc} - MAC: {received.hwsrc}")
    else:
        print("No response received.")

# Example usage
<<<<<<< HEAD
target_ip = "192.168.56.101"  # Specify the target IP address
=======
target_ip = "192.168.56.102"  # Specify the target IP address
>>>>>>> 2c22c15da0ca21af0acafc2b231a37cd1176221c
send_arp_request(target_ip)
