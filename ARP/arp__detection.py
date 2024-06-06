import psutil
import logging
import threading
import time
import tkinter as tk
from tkinter import ttk
from scapy.all import *
import socket

# Configure logging
logging.basicConfig(filename='arp_spoof_detection.log', level=logging.INFO, format='%(asctime)s - %(message)s')
logging.info("ARP Spoof Detection Program Started")

# The ARP table
arp_table = {}
last_spoof_detection = 0
INTERFACE = None
NETWORK_RANGE = None

def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())

def get_network_range(interface):
    addrs = psutil.net_if_addrs()[interface]
    ip_address = None
    netmask = None

    for addr in addrs:
        if addr.family == socket.AF_INET:
            ip_address = addr.address
            netmask = addr.netmask

    if ip_address and netmask:
        ip_parts = ip_address.split('.')
        mask_parts = netmask.split('.')
        network_parts = [str(int(ip_parts[i]) & int(mask_parts[i])) for i in range(4)]
        network = '.'.join(network_parts)
        cidr = sum([bin(int(x)).count('1') for x in mask_parts])
        return f"{network}/{cidr}"
    return None

def detect_arp_spoof(pkt):
    global last_spoof_detection
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP response
        hwsrc = pkt[ARP].hwsrc
        psrc = pkt[ARP].psrc

        if psrc in arp_table:
            if arp_table[psrc] != hwsrc:
                message = f"[!] Detected ARP Spoofing: {psrc} is claimed by {hwsrc}, but it should be {arp_table[psrc]}"
                print(message)
                logging.warning(message)
                gui_log(message)
                prevent_arp_spoofing(psrc, arp_table[psrc])
                last_spoof_detection = time.time()
        else:
            arp_table[psrc] = hwsrc

def prevent_arp_spoofing(ip, correct_mac):
    pkt = ARP(op=2, psrc=ip, hwsrc=correct_mac, hwdst='ff:ff:ff:ff:ff:ff', pdst=ip)
    send(pkt, iface=INTERFACE, verbose=False)
    message = f"[+] Sent ARP response to correct spoofed entry for IP {ip} with MAC {correct_mac}"
    print(message)
    logging.info(message)
    gui_log(message)

def gui_log(message):
    log_text.insert(tk.END, message + '\n')
    log_text.yview(tk.END)

def start_sniffing():
    sniff(iface=INTERFACE, store=False, prn=detect_arp_spoof, filter="arp")

def start_monitoring():
    global INTERFACE, NETWORK_RANGE, last_spoof_detection
    INTERFACE = interface_var.get()
    if not INTERFACE:
        gui_log("Please select a network interface.")
        return
    NETWORK_RANGE = get_network_range(INTERFACE)
    if not NETWORK_RANGE:
        gui_log("Unable to determine network range for the selected interface.")
        return

    gui_log(f"[*] Selected interface: {INTERFACE}")
    logging.info(f"Selected interface: {INTERFACE}")
    gui_log(f"[*] Network range: {NETWORK_RANGE}")
    logging.info(f"Network range: {NETWORK_RANGE}")
    gui_log("[*] Starting ARP Spoofing Detection...")
    logging.info("Starting ARP Spoofing Detection...")
    last_spoof_detection = time.time()

    # Start periodic check thread
    periodic_thread = threading.Thread(target=periodic_check)
    periodic_thread.daemon = True
    periodic_thread.start()

    # Start sniffing thread
    sniffing_thread = threading.Thread(target=start_sniffing)
    sniffing_thread.daemon = True
    sniffing_thread.start()

def periodic_check():
    global last_spoof_detection
    while True:
        time_since_last_spoof = time.time() - last_spoof_detection
        if time_since_last_spoof > 10:  # 10 seconds
            message = "[*] No ARP spoofing detected in the last 10 seconds."
            print(message)
            logging.info(message)
            gui_log(message)
        time.sleep(10)

# Update ARP table periodically
def update_arp_table():
    while True:
        if NETWORK_RANGE:
            arp_request = ARP(pdst=NETWORK_RANGE)
            broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

            for element in answered_list:
                arp_table[element[1].psrc] = element[1].hwsrc

        time.sleep(60)  # Update every 60 seconds

# Set up GUI
root = tk.Tk()
root.title("ARP Spoofing Detection")

main_frame = ttk.Frame(root, padding="10")
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

interface_label = ttk.Label(main_frame, text="Select Network Interface:")
interface_label.grid(row=0, column=0, sticky=tk.W)

interface_var = tk.StringVar()
interfaces = get_network_interfaces()
interface_menu = ttk.OptionMenu(main_frame, interface_var, *interfaces)
interface_menu.grid(row=0, column=1, sticky=(tk.W, tk.E))

start_button = ttk.Button(main_frame, text="Start Monitoring", command=start_monitoring)
start_button.grid(row=1, column=0, columnspan=2, pady=10)

log_text = tk.Text(main_frame, width=80, height=20)
log_text.grid(row=2, column=0, columnspan=2, pady=10)
log_text.config(state=tk.NORMAL)

# Start the ARP table update thread
arp_update_thread = threading.Thread(target=update_arp_table)
arp_update_thread.daemon = True
arp_update_thread.start()

root.mainloop()
