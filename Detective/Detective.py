from scapy.all import *
from scapy.arch.windows import get_windows_if_list
import sys

# Need more work on compatibility with linux OS.

def get_mac(ip):
    """
    Returns the MAC address for the specified IP address using ARP request
    """
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None

def restore_arp(target_ip, correct_mac, source_ip):
    """
    Sends out correct ARP replies to the network to restore proper IP to MAC mappings in other device's ARP tables.
    """
    packet = ARP(op=2, hwsrc=correct_mac, psrc=source_ip, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip)
    send(packet, verbose=False, count=5)

def monitor_and_protect(interface):
    """
    Monitor ARP replies and detect ARP poisoning, also corrects it by broadcasting true ARP responses.
    """
    print(f"Monitoring for ARP poisoning and protecting network on interface: {interface}...")
    try:
        sniff(iface=interface, filter="arp", store=0, prn=process_packet)
    except Exception as e:
        print(f"Error on interface {interface}: {e}")
    except KeyboardInterrupt:
        print("Stopping ARP monitor.")
        sys.exit(0)

def process_packet(packet):
    """
    Process each ARP reply and detect ARP poisoning by checking for inconsistencies in IP to MAC mappings.
    """
    if packet.haslayer(ARP):
        if packet[ARP].op == 2:  # Is it an ARP Reply?
            try:
                real_mac = get_mac(packet[ARP].psrc)
                response_mac = packet[ARP].hwsrc

                if real_mac != response_mac:
                    print(f"!!! ARP Poisoning Detected !!! IP: {packet[ARP].psrc} has changed from {real_mac} to {response_mac}")
                    print("Sending corrective ARP response.")
                    restore_arp(packet[ARP].psrc, real_mac, packet[ARP].pdst)
                else:
                    print(f"No poisoning detected for IP: {packet[ARP].psrc}")
            except Exception as e:
                print(f"Error retrieving MAC address: {e}")

if __name__ == "__main__":
    interfaces = get_windows_if_list()
    print("Available interfaces:")
    for iface in interfaces:
        print(f"{iface['name']} - {iface['description']}")

    # Print descriptions to check input matching
    print("\nCopy and paste one of the following descriptions:")
    for iface in interfaces:
        print(f"Description: '{iface['description']}'")

    selected_description = input("Enter the network interface description (copy and paste from above): ")
    selected_interface = next((item['name'] for item in interfaces if item['description'].strip() == selected_description.strip()), None)

    if selected_interface:
        monitor_and_protect(selected_interface)
    else:
        print("Invalid interface description. Make sure to copy and paste exactly, including any special characters or spaces.")
