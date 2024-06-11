import socket
import struct
from scapy.all import sniff, TCP, IP, Raw

def decode_payload(payload):
    try:
        return payload.decode('utf-8')
    except UnicodeDecodeError:
        try:
            return payload.decode('latin-1')
        except UnicodeDecodeError:
            return repr(payload)

def is_http_request(payload):
    http_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE"]
    return any(payload.startswith(method) for method in http_methods)

def log_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        # Extract the TCP payload
        if packet.haslayer(Raw):
            tcp_payload = bytes(packet[Raw].load)
            if tcp_payload:
                try:
                    # Decode the payload as UTF-8
                    decoded_payload = decode_payload(tcp_payload)
                    if decoded_payload and is_http_request(decoded_payload):
                        print(f'{packet[IP].src} : {decoded_payload}')
                except UnicodeDecodeError as e:
                    print(f"Failed to decode TCP payload: {e}")

def sniff_packets(interface, target_ip, gateway_ip):
    filter_str = f"tcp and ((src host {target_ip} and dst host {gateway_ip}) or (src host {gateway_ip} and dst host {target_ip}))"
    try:
        sniff(filter=filter_str, prn=log_packet, iface=interface, count=20, timeout=15)
    except Exception as e:
        print(f"Error in sniffing packets: {e}")

if __name__ == "__main__":
    # Change these to your desired interface and IPs
    interface = "enp0s8"
    target_ip = "192.168.56.1"
    gateway_ip = "192.168.56.101"

    try:
        sniff_packets(interface, target_ip, gateway_ip)
    except KeyboardInterrupt:
        print("Sniffing stopped.")
