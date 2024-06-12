
import os
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import logging
import queue
import platform

class ArpSpoofDetector:
    def __init__(self, cache_timeout=60):
        self.arp_cache = {}
        self.cache_timeout = cache_timeout
        self.sniffing = False
        self.sniffing_thread = None
        self.auto_scroll = True
        self.prevent_spoofing = False
        self.log_queue = queue.Queue()
        logging.basicConfig(filename='arp_spoofing_detection.log', level=logging.INFO, format='%(asctime)s - %(message)s')

    def get_network_interfaces(self):
        try:
            if platform.system() == "Windows":
                interfaces = os.popen("ipconfig /all | findstr /R /C:\"Description\"").read().strip().split('\n')
                interfaces = [interface.split(': ')[1] for interface in interfaces if ': ' in interface]
            else:  # For Linux/Ubuntu
                interfaces = os.popen("ifconfig -a | grep flags | cut -d: -f1").read().strip().split('\n')
            return interfaces
        except Exception as e:
            self.log_detection(f"Error: Failed to retrieve network interfaces: {e}")
            return []

    def get_mac(self, ip):
        if ip in self.arp_cache and (time.time() - self.arp_cache[ip][1]) < self.cache_timeout:
            return self.arp_cache[ip][0]
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        if answered_list:
            mac = answered_list[0][1].hwsrc
            self.arp_cache[ip] = (mac, time.time())
            return mac
        return None

    def send_corrective_arp_response(self, ip, real_mac):
        target_mac = self.get_mac(ip)
        if target_mac:
            arp_response = scapy.ARP(op=2, pdst=ip, hwdst=target_mac, psrc=ip, hwsrc=real_mac)
            scapy.send(arp_response, verbose=False)
            self.log_detection(f"Sent corrective ARP response: IP: {ip}, MAC: {real_mac}")

    def sniff_packets(self, interface):
        self.sniffing = True
        scapy.sniff(iface=interface, store=False, prn=self.process_packet, filter="arp", stop_filter=lambda x: not self.sniffing)

    def process_packet(self, packet):
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            try:
                real_mac = self.get_mac(packet[scapy.ARP].psrc)
                response_mac = packet[scapy.ARP].hwsrc

                if real_mac and real_mac != response_mac:
                    message = f"ARP Spoofing Detected! IP: {packet[scapy.ARP].psrc}, Real MAC: {real_mac}, Fake MAC: {response_mac}"
                    self.log_detection(message)
                    if self.prevent_spoofing:
                        self.send_corrective_arp_response(packet[scapy.ARP].psrc, real_mac)
            except IndexError:
                pass

    def log_detection(self, message):
        logging.info(message)
        self.log_queue.put(message)

    def start_sniffing(self, interface):
        self.sniffing_thread = threading.Thread(target=self.sniff_packets, args=(interface,), daemon=True)
        self.sniffing_thread.start()
        self.update_gui_on_start(interface)

    def stop_sniffing(self):
        self.sniffing = False
        if self.sniffing_thread and self.sniffing_thread.is_alive():
            self.sniffing_thread.join()
        self.update_gui_on_stop()

    def update_gui_on_start(self, interface):
        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)
        refresh_button.config(state=tk.DISABLED)
        clear_log_button.config(state=tk.DISABLED)
        status_label.config(text="Status: Sniffing", foreground="green")
        self.log_detection(f"Started sniffing on {interface}")

    def update_gui_on_stop(self):
        start_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)
        refresh_button.config(state=tk.NORMAL)
        clear_log_button.config(state=tk.NORMAL)
        status_label.config(text="Status: Stopped", foreground="red")
        self.log_detection("Stopped sniffing.")

    def refresh_interfaces(self):
        interfaces = self.get_network_interfaces()
        interface_combo['values'] = interfaces
        self.log_detection("Network interfaces refreshed.")

    def set_cache_timeout(self, value):
        try:
            self.cache_timeout = int(value)
            self.log_detection(f"Set ARP cache timeout to {self.cache_timeout} seconds")
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid number for cache timeout.")

    def toggle_auto_scroll(self):
        self.auto_scroll = not self.auto_scroll
        self.log_detection(f"Auto-scroll {'enabled' if self.auto_scroll else 'disabled'}")

    def toggle_prevent_spoofing(self):
        self.prevent_spoofing = not self.prevent_spoofing
        self.log_detection(f"ARP spoofing prevention {'enabled' if self.prevent_spoofing else 'disabled'}")

    def clear_log(self):
        log_text.config(state=tk.NORMAL)
        log_text.delete(1.0, tk.END)
        log_text.config(state=tk.DISABLED)

    def periodic_cache_cleanup(self):
        while self.sniffing:
            current_time = time.time()
            self.arp_cache = {ip: (mac, timestamp) for ip, (mac, timestamp) in self.arp_cache.items() if current_time - timestamp < self.cache_timeout}
            time.sleep(self.cache_timeout)

def create_gui(detector):
    global interface_var, start_button, stop_button, refresh_button, clear_log_button, log_text, status_label
    root = tk.Tk()
    root.title("ARP Spoofing Detection and Prevention")
    root.geometry("800x600")

    main_frame = ttk.Frame(root, padding="10")
    main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    main_frame.columnconfigure(0, weight=1)
    main_frame.rowconfigure(3, weight=1)

    # Network Interface Selection
    interface_frame = ttk.LabelFrame(main_frame, text="Network Interface", padding="10")
    interface_frame.grid(row=0, column=0, padx=10, pady=10, sticky=(tk.W, tk.E))
    interface_frame.columnconfigure(1, weight=1)

    ttk.Label(interface_frame, text="Select Network Interface:").grid(row=0, column=0, pady=5, sticky=tk.W)
    interfaces = detector.get_network_interfaces()
    interface_var = tk.StringVar()
    interface_combo = ttk.Combobox(interface_frame, textvariable=interface_var, values=interfaces, state="readonly")
    interface_combo.grid(row=0, column=1, pady=5, sticky=(tk.W, tk.E))
    interface_combo.set(interfaces[0] if interfaces else "")

    refresh_button = ttk.Button(interface_frame, text="Refresh", command=detector.refresh_interfaces)
    refresh_button.grid(row=0, column=2, padx=5)
    CreateToolTip(refresh_button, "Refresh the list of network interfaces")

    # Control Buttons
    control_frame = ttk.Frame(main_frame)
    control_frame.grid(row=1, column=0, padx=10, pady=10, sticky=(tk.W, tk.E))
    control_frame.columnconfigure([0, 1, 2], weight=1)

    start_button = ttk.Button(control_frame, text="Start Detection", command=lambda: detector.start_sniffing(interface_var.get()))
    start_button.grid(row=0, column=0, padx=5, sticky=(tk.W, tk.E))
    CreateToolTip(start_button, "Start ARP spoofing detection on the selected network interface")

    stop_button = ttk.Button(control_frame, text="Stop Detection", command=detector.stop_sniffing, state=tk.DISABLED)
    stop_button.grid(row=0, column=1, padx=5, sticky=(tk.W, tk.E))
    CreateToolTip(stop_button, "Stop ARP spoofing detection")

    clear_log_button = ttk.Button(control_frame, text="Clear Log", command=detector.clear_log)
    clear_log_button.grid(row=0, column=2, padx=5, sticky=(tk.W, tk.E))
    CreateToolTip(clear_log_button, "Clear the log output")

    # Settings
    settings_frame = ttk.LabelFrame(main_frame, text="Settings", padding="10")
    settings_frame.grid(row=2, column=0, padx=10, pady=10, sticky=(tk.W, tk.E))
    settings_frame.columnconfigure([0, 1, 2], weight=1)

    ttk.Label(settings_frame, text="Cache Timeout (seconds):").grid(row=0, column=0, pady=5, sticky=tk.W)
    cache_timeout_var = tk.StringVar(value=str(detector.cache_timeout))
    cache_timeout_entry = ttk.Entry(settings_frame, textvariable=cache_timeout_var, width=10)
    cache_timeout_entry.grid(row=0, column=1, pady=5, sticky=(tk.W, tk.E))
    cache_timeout_entry.bind("<Return>", lambda event: detector.set_cache_timeout(cache_timeout_var.get()))
    CreateToolTip(cache_timeout_entry, "Set the timeout for ARP cache entries (seconds)")

    auto_scroll_var = tk.BooleanVar(value=detector.auto_scroll)
    auto_scroll_check = ttk.Checkbutton(settings_frame, text="Auto-scroll Log", variable=auto_scroll_var, command=detector.toggle_auto_scroll)
    auto_scroll_check.grid(row=0, column=2, padx=5)
    CreateToolTip(auto_scroll_check, "Toggle automatic scrolling of the log")

    prevent_spoofing_var = tk.BooleanVar(value=detector.prevent_spoofing)
    prevent_spoofing_check = ttk.Checkbutton(settings_frame, text="Prevent ARP Spoofing", variable=prevent_spoofing_var, command=detector.toggle_prevent_spoofing)
    prevent_spoofing_check.grid(row=1, column=0, columnspan=3, pady=5)
    CreateToolTip(prevent_spoofing_check, "Toggle ARP spoofing prevention by sending corrective ARP responses")

    # Log Output
    log_frame = ttk.LabelFrame(main_frame, text="Log Output", padding="10")
    log_frame.grid(row=3, column=0, padx=10, pady=10, sticky=(tk.W, tk.E, tk.N, tk.S))
    log_frame.columnconfigure(0, weight=1)
    log_frame.rowconfigure(0, weight=1)

    log_text = scrolledtext.ScrolledText(log_frame, state=tk.DISABLED, width=80, height=20)
    log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    # Status
    status_frame = ttk.Frame(main_frame)
    status_frame.grid(row=4, column=0, padx=10, pady=10, sticky=(tk.W, tk.E))

    status_label = ttk.Label(status_frame, text="Status: Stopped", foreground="red")
    status_label.grid(row=0, column=0, sticky=(tk.W, tk.E))

    root.after(100, lambda: process_log_queue(detector, root))
    root.mainloop()

def process_log_queue(detector, root):
    while not detector.log_queue.empty():
        message = detector.log_queue.get()
        log_text.config(state=tk.NORMAL)
        log_text.insert(tk.END, message + "\n")
        if detector.auto_scroll:
            log_text.yview(tk.END)
        log_text.config(state=tk.DISABLED)
    root.after(100, lambda: process_log_queue(detector, root))

class CreateToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tooltip, text=self.text, justify='left', background="#ffffe0", relief='solid', borderwidth=1, wraplength=150)
        label.pack(ipadx=1)

    def hide_tooltip(self, event):
        if self.tooltip:
            self.tooltip.destroy()
        self.tooltip = None

if __name__ == "__main__":
    detector = ArpSpoofDetector()
    create_gui(detector)
