import psutil
import socket
from scapy.all import ARP, Ether, srp

def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    result = []
    for interface, addresses in interfaces.items():
        for address in addresses:
            if address.family == socket.AF_INET:
                result.append({
                    'interface': interface,
                    'ip_address': address.address
                })
    return result

def print_network_interfaces(interfaces):
    print("Network Interfaces and their IP addresses:")
    for idx, interface in enumerate(interfaces):
        print(f"{idx + 1}: Interface: {interface['interface']}, IP Address: {interface['ip_address']}")

def scan_network(network_range):
    arp_request = ARP(pdst=network_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for sent, received in answered_list:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def print_devices(devices):
    print("\nAvailable devices in the network:")
    print("IP" + " " * 18 + "MAC")
    for device in devices:
        print("{:16}    {}".format(device['ip'], device['mac']))

def get_network_range(ip_address):
    ip_parts = ip_address.split('.')
    network_range = '.'.join(ip_parts[:-1]) + '.0/24'
    return network_range

if __name__ == "__main__":
    interfaces = get_network_interfaces()
    if not interfaces:
        print("No network interfaces found.")
        exit(1)

    print_network_interfaces(interfaces)

    try:
        choice = int(input("\nSelect the interface you want to scan (by number): ")) - 1
        if choice < 0 or choice >= len(interfaces):
            print("Invalid choice.")
            exit(1)
    except ValueError:
        print("Invalid input. Please enter a number.")
        exit(1)

    selected_interface = interfaces[choice]
    network_range = get_network_range(selected_interface['ip_address'])
    
    print(f"\nScanning network range: {network_range}")
    devices = scan_network(network_range)
    print_devices(devices)
