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
import logging
from collections import defaultdict
import sys

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Cache for IP to MAC mappings
mac_cache = defaultdict(lambda: None)

# Lock for thread-safe access to the cache
cache_lock = threading.Lock()

# Variable to control ARP monitoring
monitoring = False

# Adjust Scapy timeout and retry settings for large networks
conf.verb = 0  # Disable verbose output
SCAN_TIMEOUT = 2  # Increase timeout
SCAN_RETRIES = 3  # Number of retries

class NetworkScanGUI:
    def __init__(self, master):
        self.master = master
        master.title("Network Scanner and ARP Detection Tool")
        self.create_widgets()
        self.scan_thread = None
        self.devices = []  # Store scanned devices
        self.scan_stop_event = threading.Event()
        self.log_queue = queue.Queue()
        self.device_queue = queue.Queue()
        self.set_network_interfaces()
        self.update_log()
        self.update_devices()
        self.monitoring_thread = None
        self.monitoring_stop_event = threading.Event()

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
            self.log_message(message="Network scan is already in progress.", color='blue')
            return
        selected_network = self.interfaces.get()
        self.scan_thread = threading.Thread(target=self.do_scan_network, args=(selected_network,))
        self.scan_thread.start()

    def do_scan_network(self, selected_network):
        ip_range = self.get_ip_range(selected_network)
        if not ip_range:
            self.log_message(message="Unable to get IP range for the selected network interface.", color='red')
            return

        self.log_message(message=f"Scanning network: {ip_range}...", color='blue')

        # Use Scapy for scanning
        devices = self.scan_with_scapy(ip_range=ip_range, interface=selected_network)
        unique_devices = {device['ip']: device for device in devices if device['ip'] and device['mac']}
        self.devices = list(unique_devices.values())  # Store scanned devices

        for device in self.devices:
            self.device_queue.put(device)

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

    def update_devices(self):
        while not self.device_queue.empty():
            device = self.device_queue.get_nowait()
            self.insert_to_treeview(device['ip'], device['mac'])
        self.master.after(100, self.update_devices)

    def insert_to_treeview(self, ip, mac=None):
        if mac:
            self.devices_treeview.insert("", tk.END, text="Device", values=(ip, mac))
        else:
            self.devices_treeview.insert("", tk.END, text="Info", values=(ip, ""))

    def log_message(self, message, important=False, color='black'):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if important:
            formatted_message = f"[{timestamp}] *** {message} ***"
            self.log_queue.put((formatted_message, color))
        else:
            formatted_message = f"[{timestamp}] {message}"
            self.log_queue.put((formatted_message, color))
        

    def update_log(self):
        # Configure the tag to display red text
        self.log_text.tag_configure('red', foreground='red')
        self.log_text.tag_configure('green', foreground='green')
        self.log_text.tag_configure('blue', foreground='blue')
        self.log_text.tag_configure('black', foreground='black')       
        
        while not self.log_queue.empty():
            message, color = self.log_queue.get_nowait()
            self.log_text.configure(state='normal')
            # Insert the message with a color tag
            self.log_text.insert(tk.END, message + '\n', color)
            self.log_text.configure(state='disabled')
            self.log_text.yview(tk.END)

        # Recurring Call
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
            self.log_message(message=f"No response for IP {ip}", color='red')
        return None
    
    def safe_method(self, method):
        try:
            method()
        except Exception as e:
            self.log_message(message=f"Error: {e}\n{traceback.format_exc()}", important=True, color='red')

    def safe_start_detection(self):
        self.safe_method(self.start_detection)

    def safe_stop_detection(self):
        self.safe_method(self.stop_detection)

    def start_detection(self):
        selected_interface = self.interfaces.get()
        self.scan_stop_event.clear()  # Ensure the stop event is clear before starting
        self.monitoring_stop_event.clear()  # Clear the stop event for monitoring
        self.monitoring_thread = threading.Thread(target=self.monitor_and_detect, args=(selected_interface,))
        self.monitoring_thread.start()
        self.log_message(message=f"ARP spoofing detection started on interface {selected_interface}.", important=True, color='blue')

    def stop_detection(self):
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_stop_event.set()  # Signal the monitoring thread to stop
            self.monitoring_thread.join(timeout=5)  # Join with timeout to avoid indefinite blocking
            if self.monitoring_thread.is_alive():
                self.log_message(message="Failed to stop ARP spoofing detection thread within the timeout period.", important=True, color='red')
            else:
                self.log_message(message="ARP spoofing detection stopped.", important=True, color='blue')
        else:
            self.log_message(message="No ARP spoofing detection is running.", important=True, color='blue')

    def monitor_and_detect(self, interface):
        global monitoring
        monitoring = True
        self.log_message(message=f"Monitoring for ARP poisoning on interface: {interface}...", important=True, color='blue')
        try:
            sniff(iface=interface, filter="arp", prn=self.process_packet, store=0, stop_filter=self.should_stop_sniffing)
        except Exception as e:
            self.log_message(message=f"Error on interface {interface}: {e}", important=True, color='red')
        monitoring = False
        self.log_message(message=f"ARP spoofing detection stopped on interface {interface}.", important=True, color='green')

    def should_stop_sniffing(self, packet):
        return self.monitoring_stop_event.is_set()

    def process_packet(self, packet):
        if packet.haslayer(ARP):
            self.handle_arp_reply(packet)

    def handle_arp_reply(self, packet):
        try:
            real_mac = self.get_mac(packet[ARP].psrc)
            response_mac = packet[ARP].hwsrc

            # Validate MAC addresses
            if response_mac == "00:00:00:00:00:00":
                self.log_message(message=f"Invalid MAC address received from IP: {packet[ARP].psrc}", color='red')
                return

            if real_mac is None:
                self.log_message(message=f"Unable to determine real MAC address for IP: {packet[ARP].psrc}", color='red')
                return

            if real_mac != response_mac:
                self.log_message(message=f"!!! ARP Poisoning Detected !!! IP: {packet[ARP].psrc} has changed from {real_mac} to {response_mac}", important=True, color='red')
            else:
                self.log_message(message=f"No poisoning detected for IP: {packet[ARP].psrc}", color='green')
        except Exception as e:
            self.log_message(message=f"Error handling ARP reply: {e}\n{traceback.format_exc()}", important=True, color='red')

def main():
    try:
        root = tk.Tk()
        gui = NetworkScanGUI(root)
        root.protocol("WM_DELETE_WINDOW", lambda: on_close(gui, root))
        root.mainloop()
    except Exception as e:
        print(f"GUI Error: {e}")

def on_close(gui, root):
    if gui.monitoring_thread and gui.monitoring_thread.is_alive():
        gui.monitoring_stop_event.set()
        gui.monitoring_thread.join(timeout=5)
    root.destroy()
    sys.exit(0)

if __name__ == "__main__":
    main()
