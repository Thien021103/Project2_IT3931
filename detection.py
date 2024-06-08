import os
import socket
import psutil
from scapy.all import ARP, Ether, srp, conf, sniff
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import traceback
import queue
import datetime

# Adjust Scapy timeout and retry settings for large networks
conf.verb = 0  # Disable verbose output
SCAN_TIMEOUT = 2  # Increase timeout
SCAN_RETRIES = 3  # Number of retries

class NetworkScanGUI:
    def __init__(self, master):
        self.master = master
        master.title("Network Scanner Tool")
        self.create_widgets()
        self.scan_thread = None
        self.devices = []  # Store scanned devices
        self.scan_stop_event = threading.Event()
        self.log_queue = queue.Queue()
        self.set_network_interfaces()
        self.update_log()

    def create_widgets(self):
        self.create_scan_frame()
        self.create_devices_frame()
        self.create_log_frame()
        self.create_detection_frame()

    def create_scan_frame(self):
        self.frame_scan = ttk.Frame(self.master)
        self.frame_scan.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        self.label_interface = ttk.Label(self.frame_scan, text="Network Interface:")
        self.label_interface.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.interfaces = ttk.Combobox(self.frame_scan)
        self.interfaces.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.scan_button = ttk.Button(self.frame_scan, text="Scan Network", command=self.safe_scan_network)
        self.scan_button.grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)

    def create_devices_frame(self):
        self.frame_devices = ttk.Frame(self.master)
        self.frame_devices.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
        self.devices_treeview = ttk.Treeview(self.frame_devices, columns=("IP Address", "MAC Address"))
        self.devices_treeview.heading("#0", text="Device")
        self.devices_treeview.heading("IP Address", text="IP Address")
        self.devices_treeview.heading("MAC Address", text="MAC Address")
        self.devices_treeview.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W+tk.E)

    def create_log_frame(self):
        self.frame_log = ttk.Frame(self.master)
        self.frame_log.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W+tk.E)
        self.log_text = scrolledtext.ScrolledText(self.frame_log, wrap=tk.WORD, width=60, height=10, state='disabled')
        self.log_text.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W+tk.E)

    def create_detection_frame(self):
        self.frame_detection = ttk.Frame(self.master)
        self.frame_detection.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
        self.detection_button = ttk.Button(self.frame_detection, text="Start Detection", command=self.safe_start_detection)
        self.detection_button.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.stop_detection_button = ttk.Button(self.frame_detection, text="Stop Detection", command=self.safe_stop_detection)
        self.stop_detection_button.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

    def set_network_interfaces(self):
        interfaces = self.get_network_interfaces()
        if interfaces:
            self.interfaces['values'] = list(interfaces)
            self.interfaces.set(list(interfaces)[0])

    def get_network_interfaces(self):
        return psutil.net_if_addrs().keys()

    def safe_scan_network(self):
        self.safe_method(self.scan_network)

    def scan_network(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.log_message("Network scan is already in progress.")
            return
        selected_network = self.interfaces.get()
        self.scan_thread = threading.Thread(target=self.do_scan_network, args=(selected_network,))
        self.scan_thread.start()

    def do_scan_network(self, selected_network):
        ip_range = self.get_ip_range(selected_network)
        if not ip_range:
            self.log_message("Unable to get IP range for the selected network interface.")
            return

        self.log_message(f"Scanning network: {ip_range}...")

        # Use Scapy for scanning
        devices = self.scan_with_scapy(ip_range=ip_range, interface=selected_network)
        unique_devices = {device['ip']: device for device in devices if device['ip'] and device['mac']}
        self.devices = list(unique_devices.values())  # Store scanned devices

        for device in self.devices:
            self.insert_to_treeview(device['ip'], device['mac'])

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

    def scan_with_scapy(self, ip_range, interface):
        results = []
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=SCAN_TIMEOUT, retry=SCAN_RETRIES, iface=interface, verbose=False)[0]
        for sent, received in result:
            results.append({'ip': received.psrc, 'mac': received.hwsrc})
        return results

    def insert_to_treeview(self, ip, mac=None):
        if mac:
            self.devices_treeview.insert("", tk.END, text="Device", values=(ip, mac))
        else:
            self.devices_treeview.insert("", tk.END, text="Info", values=(ip, ""))

    def log_message(self, message, important=False):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if important:
            formatted_message = f"[{timestamp}] *** {message} ***"
        else:
            formatted_message = f"[{timestamp}] {message}"
        self.log_queue.put(formatted_message)

    def update_log(self):
        while not self.log_queue.empty():
            message = self.log_queue.get_nowait()
            self.log_text.configure(state='normal')
            self.log_text.insert(tk.END, message + '\n')
            self.log_text.configure(state='disabled')
            self.log_text.yview(tk.END)
        self.master.after(100, self.update_log)

    def get_mac(self, ip):
        interface = self.interfaces.get()
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, iface=interface, verbose=False)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
        else:
            self.log_message(f"No response for IP {ip}")
        return None
    
    def safe_method(self, method):
        try:
            method()
        except Exception as e:
            self.log_message(f"Error: {e}\n{traceback.format_exc()}", important=True)

    def safe_start_detection(self):
        self.safe_method(self.start_detection)

    def safe_stop_detection(self):
        self.safe_method(self.stop_detection)

    def start_detection(self):
        selected_interface = self.interfaces.get()
        self.scan_stop_event.clear()  # Ensure the stop event is clear before starting
        self.detection_thread = threading.Thread(target=self.detect_arp_spoofing, args=(selected_interface,))
        self.detection_thread.start()
        self.log_message(f"ARP spoofing detection started on interface {selected_interface}.", important=True)

    def stop_detection(self):
        if hasattr(self, 'detection_thread') and self.detection_thread.is_alive():
            self.scan_stop_event.set()
            self.detection_thread.join()
            self.log_message("ARP spoofing detection stopped.", important=True)
        else:
            self.log_message("No ARP spoofing detection is running.", important=True)

    def detect_arp_spoofing(self, interface):
        self.log_message(f"Detecting ARP spoofing on interface {interface}.")
        while not self.scan_stop_event.is_set():
            arp_packets = sniff(iface=interface, filter="arp", count=100, timeout=10)
            unique_ips = set()
            for packet in arp_packets:
                if packet[ARP].op == 2:  # Response
                    unique_ips.add(packet[ARP].psrc)
            if len(unique_ips) > 1:
                self.log_message(f"Possible ARP spoofing detected on interface {interface}!", important=True)
                for ip in unique_ips:
                    mac = self.get_mac(ip)
                    if mac:
                        self.log_message(f"IP: {ip}, MAC: {mac}", important=True)
                    else:
                        self.log_message(f"IP: {ip}, MAC: Unknown", important=True)
            else:
                self.log_message(f"No ARP spoofing detected on interface {interface}.")
        self.log_message(f"ARP spoofing detection stopped on interface {interface}.")

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
