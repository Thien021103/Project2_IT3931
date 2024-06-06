import psutil
import logging
import threading
import time
import tkinter as tk
from tkinter import ttk
from scapy.all import *

# Configure logging
logging.basicConfig(filename='arp_spoof_detection.log', level=logging.INFO, format='%(asctime)s - %(message)s')
logging.info("ARP Spoof Detection Program Started")

# The ARP table
arp_table = {}
last_spoof_detection = 0
INTERFACE = None

def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())

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
    # Send correct ARP response to overwrite spoofed entry in victim's ARP table
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
    global INTERFACE, last_spoof_detection
    INTERFACE = interface_var.get()
    if not INTERFACE:
        gui_log("Please select a network interface.")
        return
    gui_log(f"[*] Selected interface: {INTERFACE}")
    logging.info(f"Selected interface: {INTERFACE}")
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

root.mainloop()
