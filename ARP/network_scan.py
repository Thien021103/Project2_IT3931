import psutil
from scapy.all import ARP, Ether, srp
import socket

def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return interfaces

def get_ip_address(interface):
    addresses = psutil.net_if_addrs()[interface]
    for address in addresses:
        if address.family == socket.AF_INET:
            return address.address
    return None

def scan_network(ip_range):
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    result = srp(packet, timeout=2, verbose=False)[0]

    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    return clients

if __name__ == "__main__":
    interfaces = get_network_interfaces()

    print("Available network interfaces:")
    for i, interface in enumerate(interfaces):
        print(f"{i}. {interface}")

    choice = int(input("Select an interface (number): "))
    selected_interface = list(interfaces.keys())[choice]
    local_ip = get_ip_address(selected_interface)

    if local_ip is None:
        print("Unable to get IP address for the selected interface.")
    else:
        ip_range = '.'.join(local_ip.split('.')[:3]) + '.1/24'
        print(f"Scanning network: {ip_range}")

        devices = scan_network(ip_range)

        print("Available devices in the network:")
        print("IP" + " "*18 + "MAC")
        for device in devices:
            print(f"{device['ip']:<20}{device['mac']}")
