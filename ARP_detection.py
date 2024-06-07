import sys
import threading
import logging
import tkinter as tk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
from collections import defaultdict
from scapy.all import *
import os
import platform

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Cache for IP to MAC mappings
mac_cache = defaultdict(lambda: None)

# Lock for thread-safe access to the cache
cache_lock = threading.Lock()

# Variable to control ARP monitoring
monitoring = False

class ARPMonitorGUI:
    def __init__(self, root):
        """
        Initialize the GUI and its components.
        """
        self.root = root
        self.root.title("ARP Monitor and Protection")

        # Interface selection
        self.interface_label = tk.Label(root, text="Select Network Interface:")
        self.interface_label.pack()

        self.interface_var = tk.StringVar()
        self.interface_menu = tk.OptionMenu(root, self.interface_var, *self.get_interfaces())
        self.interface_menu.pack()

        # Refresh button for network interfaces
        self.refresh_button = tk.Button(root, text="Refresh Interfaces", command=self.refresh_interfaces)
        self.refresh_button.pack()

        # Start button
        self.start_button = tk.Button(root, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack()

        # Stop button
        self.stop_button = tk.Button(root, text="Stop Monitoring", command=self.stop_monitoring, state='disabled')
        self.stop_button.pack()

        # Log display
        self.log_display = ScrolledText(root, state='disabled', height=15, width=80)
        self.log_display.pack()

        # Redirect logging to the log display
        self.log_handler = TextHandler(self.log_display)
        logging.getLogger().addHandler(self.log_handler)

    def get_interfaces(self):
        """
        Retrieve the list of network interfaces available on the system.
        """
        try:
            from scapy.arch.windows import get_windows_if_list
            interfaces = get_windows_if_list()
            return [iface['name'] for iface in interfaces]
        except ImportError:
            logging.warning("Scapy is not running on Windows, trying Linux interface retrieval...")
            from scapy.arch import get_if_list
            return get_if_list()

    def refresh_interfaces(self):
        """
        Refresh the list of network interfaces displayed in the dropdown menu.
        """
        interfaces = self.get_interfaces()
        menu = self.interface_menu["menu"]
        menu.delete(0, "end")
        for interface in interfaces:
            menu.add_command(label=interface, command=tk._setit(self.interface_var, interface))
        logging.info("Network interfaces updated.")

    def start_monitoring(self):
        """
        Start the ARP monitoring process on the selected network interface.
        """
        selected_interface = self.interface_var.get()
        if selected_interface:
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')
            global monitoring
            monitoring = True
            threading.Thread(target=monitor_and_protect, args=(selected_interface,)).start()
            logging.info(f"Started monitoring on interface: {selected_interface}")
        else:
            messagebox.showerror("Error", "Invalid interface selection. Please select an interface from the dropdown.")

    def stop_monitoring(self):
        """
        Stop the ARP monitoring process.
        """
        global monitoring
        monitoring = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        logging.info("Stopped monitoring.")

class TextHandler(logging.Handler):
    def __init__(self, text):
        """
        Initialize the handler to redirect logging messages to a Tkinter ScrolledText widget.
        """
        logging.Handler.__init__(self)
        self.text = text

    def emit(self, record):
        """
        Emit a record to the ScrolledText widget.
        """
        msg = self.format(record)
        def append():
            self.text.configure(state='normal')
            self.text.insert(tk.END, msg + '\n')
            self.text.configure(state='disabled')
            self.text.yview(tk.END)
        self.text.after(0, append)

def get_mac(ip):
    """
    Returns the MAC address for the specified IP address using an ARP request.
    """
    with cache_lock:
        if ip in mac_cache:
            return mac_cache[ip]

    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    try:
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        mac_address = answered_list[0][1].hwsrc if answered_list else None
    except Exception as e:
        logging.error(f"Error sending ARP request: {e}")
        mac_address = None

    with cache_lock:
        mac_cache[ip] = mac_address

    return mac_address

def restore_arp(target_ip, correct_mac, source_ip):
    """
    Sends out correct ARP replies to the network to restore proper IP to MAC mappings in other device's ARP tables.
    """
    try:
        packet = ARP(op=2, hwsrc=correct_mac, psrc=source_ip, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip)
        send(packet, verbose=False, count=5)
    except Exception as e:
        logging.error(f"Error sending ARP response: {e}")

def monitor_and_protect(interface):
    """
    Monitor ARP replies and detect ARP poisoning, also corrects it by broadcasting true ARP responses.
    """
    logging.info(f"Monitoring for ARP poisoning and protecting network on interface: {interface}...")
    while monitoring:
        try:
            sniff(iface=interface, filter="arp", prn=process_packet, store=0)
        except Exception as e:
            logging.error(f"Error on interface {interface}: {e}")
            break

def process_packet(packet):
    """
    Process each ARP reply and detect ARP poisoning by checking for inconsistencies in IP to MAC mappings.
    """
    if monitoring and packet.haslayer(ARP):
        handle_arp_reply(packet)

def handle_arp_reply(packet):
    """
    Handle ARP replies to detect and correct ARP poisoning.
    """
    try:
        real_mac = get_mac(packet[ARP].psrc)
        response_mac = packet[ARP].hwsrc

        if real_mac is None:
            logging.warning(f"Unable to determine real MAC address for IP: {packet[ARP].psrc}")
        elif real_mac != response_mac:
            logging.warning(f"!!! ARP Poisoning Detected !!! IP: {packet[ARP].psrc} has changed from {real_mac} to {response_mac}")
            logging.info("Sending corrective ARP response.")
            restore_arp(packet[ARP].psrc, real_mac, packet[ARP].pdst)
        else:
            logging.info(f"No poisoning detected for IP: {packet[ARP].psrc}")
    except Exception as e:
        logging.error(f"Error handling ARP reply: {e}")

if __name__ == "__main__":
    # Ensure the script is running with appropriate privileges
    if platform.system() == "Linux":
        if os.geteuid() != 0:
            print("Please run this script with root privileges.")
            exit()
    elif platform.system() == "Windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Please run this script with administrator privileges.")
            exit()

    root = tk.Tk()
    app = ARPMonitorGUI(root)
    root.mainloop()
