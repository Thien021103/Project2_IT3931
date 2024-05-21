import psutil
import os
import socket
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

def ip_to_mac(ip):
    """ Get MAC address for a given IP using ARP request. """
    pid = os.getpid()
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    s.bind(('eth0', socket.htons(0x0806)))
    arp_frame = [
        b'\xff\xff\xff\xff\xff\xff',  # Destination MAC
        socket.inet_aton(ip)  # Source IP
    ]
    s.send(b''.join(arp_frame))
    s.close()

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    s.settimeout(2)
    try:
        while True:
            frame, addr = s.recvfrom(2048)
            if frame[12:14] == b'\x08\x06':  # ARP
                if frame[28:32] == socket.inet_aton(ip):
                    return ':'.join(['%02x' % b for b in frame[6:12]])
    except socket.timeout:
        pass
    finally:
        s.close()
    return None

def scan_network(ip_address, netmask):
    """ Scan the network for active devices using ARP requests. """
    # Calculate the network address and CIDR
    network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
    network_range = [str(ip) for ip in network.hosts()]

    devices = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ip_to_mac, ip): ip for ip in network_range}
        for future in futures:
            mac = future.result()
            if mac:
                devices.append({'ip': futures[future], 'mac': mac})

    return devices

def on_button_click(interface_name):
    """ Handle button click to display selected interface info. """
    ip_address, netmask = get_local_network_ips(interface_name)
    if ip_address and netmask:
        devices = scan_network(ip_address, netmask)
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
