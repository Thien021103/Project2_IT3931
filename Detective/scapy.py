import socket
import tkinter as tk
from tkinter import messagebox

def get_lan_interfaces():
    interfaces = []
    for interface in socket.if_nameindex():
        if interface[1].startswith('eth') or interface[1].startswith('wlan'):
            interfaces.append(interface[1])
    return interfaces

def scan_lan(interface):
    try:
        ans, _ = scapy.srp(Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst="192.168.1.0/24"), timeout=2, iface=interface, verbose=False)
        devices = []
        for _, rcv in ans:
            devices.append((rcv.psrc, rcv.hwsrc))
        return devices
    except Exception as e:
        print(f"Error scanning LAN: {e}")
        return []

def show_devices(interface):
    devices = scan_lan(interface)
    if devices:
        message = "IP Address\t\tMAC Address\n"
        for ip, mac in devices:
            message += f"{ip}\t\t{mac}\n"
        messagebox.showinfo("Devices on LAN", message)
    else:
        messagebox.showinfo("No Devices", "No devices found on this LAN.")

def main():
    interfaces = get_lan_interfaces()

    root = tk.Tk()
    root.title("LAN Interface Scanner")

    for interface in interfaces:
        button = tk.Button(root, text=interface, command=lambda intf=interface: show_devices(intf))
        button.pack()

    root.mainloop()

if __name__ == "__main__":
    main()

