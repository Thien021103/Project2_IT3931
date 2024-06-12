import sys
import threading
import logging
from collections import defaultdict
from scapy.all import *
import tkinter as tk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
import platform
import signal

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Cache for IP to MAC mappings
mac_cache = defaultdict(lambda: None)

# Lock for thread-safe access to the cache
cache_lock = threading.Lock()

# Variable to control ARP monitoring
monitoring = False

def get_interfaces():
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

def monitor_and_protect(interface, log_display):
    """
    Monitor ARP replies and detect ARP poisoning, also corrects it by broadcasting true ARP responses.
    """
    logging.info(f"Monitoring for ARP poisoning and protecting network on interface: {interface}...")
    global monitoring
    monitoring = True
    while monitoring:
        try:
            sniff(iface=interface, filter="arp", prn=process_packet, store=0)
        except Exception as e:
            logging.error(f"Error on interface {interface}: {e}")
            break
    root.quit()  # Quit the GUI after stopping monitoring

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

        # Validate MAC addresses
        if response_mac == "00:00:00:00:00:00":
            logging.warning(f"Invalid MAC address received from IP: {packet[ARP].psrc}")
            return

        if real_mac is None:
            logging.warning(f"Unable to determine real MAC address for IP: {packet[ARP].psrc}")
            return

        if real_mac != response_mac:
            logging.warning(f"!!! ARP Poisoning Detected !!! IP: {packet[ARP].psrc} has changed from {real_mac} to {response_mac}")
            logging.info("Sending corrective ARP response.")
            restore_arp(packet[ARP].psrc, real_mac, packet[ARP].pdst)
        else:
            logging.info(f"No poisoning detected for IP: {packet[ARP].psrc}")
    except Exception as e:
        logging.error(f"Error handling ARP reply: {e}")

def stop_monitoring():
    """
    Stop monitoring.
    """
    global monitoring
    monitoring = False
    logging.info("Monitoring stopped.")

def signal_handler(sig, frame):
    """
    Signal handler to stop the monitoring thread.
    """
    stop_monitoring()
    logging.info("Monitoring stopped by user.")
    sys.exit(0)

def main():
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # Create the GUI
    root = tk.Tk()
    root.title("ARP Monitor and Protection")

    # Interface selection
    interface_label = tk.Label(root, text="Select Network Interface:")
    interface_label.pack()

    interface_var = tk.StringVar(root)
    interface_menu = tk.OptionMenu(root, interface_var, *get_interfaces())
    interface_menu.pack()

    # Start button
    start_button = tk.Button(root, text="Start Monitoring", command=lambda: threading.Thread(target=monitor_and_protect, args=(interface_var.get(), log_display)).start())
    start_button.pack()

    # Stop button
    stop_button = tk.Button(root, text="Stop Monitoring", command=stop_monitoring)
    stop_button.pack()

    # Log display
    log_display = ScrolledText(root, state='disabled', height=15, width=80)
    log_display.pack()

    # Redirect logging to the log display
    log_handler = TextHandler(log_display)
    logging.getLogger().addHandler(log_handler)

    root.mainloop()

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

if __name__ == "__main__":
    main()
