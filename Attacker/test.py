import threading
import psutil
import socket
import struct
import fcntl
import tkinter as tk
from tkinter import messagebox
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError, wait

# Testing file for UI, solo function, etc..

def get_local_network_ips(interface_name):
    """ Get the IP address and subnet mask for a given interface. """
    addresses = psutil.net_if_addrs()[interface_name]
    ip_address = None
    netmask = None
    for address in addresses:
        if address.family == socket.AF_INET:
            ip_address = address.address
            netmask = address.netmask
            break
    
    print(ip_address + "///" + netmask)
    
def get_mac_address(interface):
    """Get the MAC address of the given network interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', bytes(interface[:15], 'utf-8')))
    return info[18:24]

def ip_to_mac(ip, interface):
    """Get MAC address for a given IP using ARP request."""
    try:
        # Create a raw socket
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))  # htons(0x0806) for ARP
        
        # Bind the socket to the specified interface
        s.bind((interface, 0))
        s.settimeout(0.01)

        # Prepare the ARP request packet
        src_mac = get_mac_address(interface)  # Source MAC address
        src_ip = socket.inet_aton("192.168.1.102")  # Replace with your source IP address
        dst_mac = b'\xff\xff\xff\xff\xff\xff'  # Broadcast MAC address
        target_ip = socket.inet_aton(ip)  # Target IP address in binary format

        eth_header = dst_mac + src_mac + b'\x08\x06'  # Ethernet header (dst_mac + src_mac + ethertype for ARP)
        arp_header = struct.pack('!HHBBH6s4s6s4s',
                                 1,                # Hardware type (Ethernet)
                                 0x0800,           # Protocol type (IPv4)
                                 6,                # Hardware size
                                 4,                # Protocol size
                                 1,                # Opcode (request)
                                 src_mac,          # Sender MAC address
                                 src_ip,           # Sender IP address
                                 b'\x00\x00\x00\x00\x00\x00',  # Target MAC address
                                 target_ip)        # Target IP address

        arp_request_packet = eth_header + arp_header

        # Send the ARP request packet
        s.send(arp_request_packet)

        attempts = 0
        while attempts < 5:
            attempts+=1

            # Receive the response
            response = s.recv(2048)

            # Check if it's an ARP reply
            # Ethernet frame type and ARP reply
            if response[12:14] == b'\x08\x06' and response[20:22] == b'\x00\x02':  
                
                # Check if it's the correct IP address
                if response[28:32] == target_ip:  
                    mac_address = ':'.join('%02x' % b for b in response[22:28])
                    print(mac_address)
                    return mac_address
            

    except Exception as e:
        return False



def scan_network(ip_address, netmask, interface_name):
    """Scan the network for active devices using ARP requests."""
    # Calculate the network address and CIDR
    network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
    network_range = ["172.17.208.1", "172.17.208.2", "172.17.208.3"]

    devices = []

    for ip in network_range:
        try:
            mac = ip_to_mac(ip, interface_name)
            if mac:
                devices.append({'ip': ip, 'mac': mac})
                print(devices)
        except Exception as e:
            print(f"Error retrieving result for IP {ip}: {e}")
        
        # Add a short delay between requests to avoid flooding the network

    print(devices)
    return devices

if __name__ == "__main__":
    scan_network("172.17.216.224", "255.255.240.0", "eth0")

