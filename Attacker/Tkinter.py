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
    return psutil.net_if_addrs()

def get_local_network_ips(interface_name):
    """ Get the IP address and subnet mask for a given interface. """
    addresses = psutil.net_if_addrs().get(interface_name)
    if addresses:
        for address in addresses:
            if address.family == socket.AF_INET:
                return address.address, address.netmask
    return None, None

def ip_to_mac(ip, interface):
    """ Get MAC address for a given IP using ARP request. """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect((ip, 0))
        hwaddr = fcntl.ioctl(
            s.fileno(),
            0x8927,  # SIOCGARP
            struct.pack('256s', interface[:15].encode('utf-8'))
        )
        s.close()
        return ':'.join('%02x' % b for b in hwaddr[18:24])
    except Exception as e:
        return None

def scan_network(ip_address, netmask, interface_name):
    """ Scan the network for active devices using ARP requests. """
    network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
    network_range = [str(ip) for ip in network.hosts()]

    devices = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ip_to_mac, ip, interface_name): ip for ip in network_range}
        for future in futures:
            mac = future.result()
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

# Create the main Tkinter window
root = tk.Tk()
root.title("Network Interfaces")

# Get network interfaces and their addresses
interfaces = get_interfaces()

# Create and place buttons for each network interface
for interface_name in interfaces:
    addresses = interfaces[interface_name]
    address_str = ', '.join([f"{address.address}" for address in addresses if address.address])
    button_text = f"{interface_name} - {address_str}"
    button = tk.Button(root, text=button_text, command=lambda name=interface_name: on_button_click(name))
    button.pack(pady=5)

# Run the Tkinter event loop
root.mainloop()

