import psutil
import socket
from scapy.all import ARP, Ether, srp
import ipaddress

def get_network_interfaces():
    interfaces = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                interfaces.append((iface, addr.address, addr.netmask))
    return interfaces

def scan_subnet(subnet):
    arp = ARP(pdst=str(subnet))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=2, verbose=0)[0]

    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    return clients

def main():
    interfaces = get_network_interfaces()

    if not interfaces:
        print("No network interfaces found.")
        return

    print("Available network interfaces:")
    for i, (iface, ip, netmask) in enumerate(interfaces):
        print(f"{i}: {iface} - IP: {ip}, Netmask: {netmask}")

    choice = int(input("Select the interface you want to scan: "))

    if choice < 0 or choice >= len(interfaces):
        print("Invalid choice.")
        return

    selected_iface, local_ip, local_netmask = interfaces[choice]
    network = ipaddress.IPv4Network(f"{local_ip}/{local_netmask}", strict=False)

    all_devices = []
    for subnet in network.subnets(new_prefix=24):
        print(f"Scanning subnet: {subnet}")
        devices = scan_subnet(subnet)
        all_devices.extend(devices)

    print("Available devices in the network:")
    for device in all_devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

if __name__ == "__main__":
    main()
