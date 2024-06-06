import psutil
import scapy.all as scapy
import ipaddress
import socket

def list_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return interfaces

def get_interface_ips(interface_name):
    addresses = psutil.net_if_addrs().get(interface_name)
    ip_netmask_pairs = []
    if addresses:
        for addr in addresses:
            if addr.family == socket.AF_INET:
                ip_netmask_pairs.append((addr.address, addr.netmask))
    return ip_netmask_pairs

def scan_network(ip, netmask):
    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    ip_list = []
    for ip in network.hosts():
        response = scapy.sr1(scapy.IP(dst=str(ip))/scapy.ICMP(), timeout=1, verbose=False)
        if response:
            ip_list.append(str(ip))
    return ip_list

def display_scan_results(interface, ips):
    print(f"Scan results for interface {interface}:")
    for ip in ips:
        print(ip)

def main():
    interfaces = list_network_interfaces()
    print("Available network interfaces:")
    for i, iface in enumerate(interfaces.keys()):
        print(f"{i}. {iface}")

    choice = int(input("Select the interface number you want to scan: "))
    selected_interface = list(interfaces.keys())[choice]
    ip_netmask_pairs = get_interface_ips(selected_interface)

    if ip_netmask_pairs:
        all_ips = []
        for ip, netmask in ip_netmask_pairs:
            print(f"Scanning network for interface {selected_interface} with IP {ip} and netmask {netmask}")
            ip_list = scan_network(ip, netmask)
            all_ips.extend(ip_list)
        display_scan_results(selected_interface, all_ips)
    else:
        print(f"Could not get IP addresses for interface {selected_interface}")

if __name__ == "__main__":
    main()
