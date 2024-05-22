import psutil
import socket
import struct
import fcntl
import tkinter as tk
from tkinter import messagebox
import ipaddress
from concurrent.futures import ThreadPoolExecutor

def get_interfaces():
    """ Get network interfaces and their addresses. """

    interfaces = psutil.net_if_addrs()
    return interfaces

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
    return ip_address, netmask

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

        while True:
            # Receive the response
            response = s.recv(2048)

            # Check if it's an ARP reply
            # Ethernet frame type and ARP reply
            if response[12:14] == b'\x08\x06' and response[20:22] == b'\x00\x02':  
                
                # Check if it's the correct IP address
                if response[28:32] == target_ip:  
                    mac_address = ':'.join('%02x' % b for b in response[22:28])
                    return mac_address

    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def scan_network(ip_address, netmask, interface_name):
    """ Scan the network for active devices using ARP requests. """

    # Calculate the network address and CIDR
    network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
    network_range = [str(ip) for ip in network.hosts()]

    devices = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ip_to_mac, ip, interface_name): ip for ip in network_range}
 
        print("here ")
        for future in futures:
            mac = future.result()
            print(mac)
            if mac:
                devices.append({'ip': futures[future], 'mac': mac})

    return devices

def on_button_click(interface_name):
    """ Handle button click to display selected interface info. """

    ip_address, netmask = get_local_network_ips(interface_name)

    if ip_address and netmask:
        devices = scan_network(ip_address, netmask, interface_name)
        device_info = "\n".join([f"IP: {device['ip']}, MAC: {device['mac']}" for device in devices])
        messagebox.showinfo("Network Scan Result", f"Devices on {interface_name}:\n{device_info}")
        
    else:
        messagebox.showerror("Error", "Unable to get IP address or netmask for the selected interface.")

# Get network interfaces and their addresses
interfaces = get_interfaces()

# Create the main Tkinter window
root = tk.Tk()
root.title("Network Interfaces")

# Create and place buttons for each network interface
for interface_name in interfaces:
    addresses = interfaces[interface_name]
    address_str = ', '.join([f"{address.address}" for address in addresses if address.address])
    button_text = f"{interface_name} - {address_str}"
    button = tk.Button(root, text=button_text, command=lambda name=interface_name: on_button_click(name))
    button.pack(pady=5)

# Run the Tkinter event loop
root.mainloop()
