
import socket
import psutil
import socket


# Testing file for UI, solo function, etc..

def get_local_network_ips(interface_name):
    """ Get the IP address and subnet mask for a given interface. """
    addresses = psutil.net_if_addrs()[interface_name]
    ip_address = None
    netmask = None
    for address in addresses:
        if address.family == socket.AF_INET:
            ip_address = address.address
            netmask = address.netmask
            break
    
    print(ip_address + "///" + netmask)
    
def ip_to_mac(ip, interface):
    """ Get MAC address for a given IP using ARP request. """
    try:
        # Create a raw socket
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
        
        # Bind the socket to the specified interface
        s.bind((interface, 0))
        
        # Prepare the ARP request packet
        src_mac = b'\x00\x00\x00\x00\x00\x00'  # Source MAC address (any)
        dst_mac = b'\xff\xff\xff\xff\xff\xff'  # Broadcast MAC address
        ethertype = b'\x08\x06'  # EtherType for ARP
        hardware_type = b'\x00\x01'  # Hardware type (Ethernet)
        protocol_type = b'\x08\x00'  # Protocol type (IPv4)
        hardware_size = b'\x06'  # Size of hardware addresses
        protocol_size = b'\x04'  # Size of protocol addresses
        opcode = b'\x00\x01'  # ARP request opcode

        target_ip = socket.inet_aton(ip)  # Target IP address in binary format

        # Construct the ARP request packet
        arp_request_packet = dst_mac + src_mac + ethertype + \
                             hardware_type + protocol_type + \
                             hardware_size + protocol_size + \
                             opcode + src_mac + target_ip + \
                             dst_mac + target_ip

        # Send the ARP request packet
        s.send(arp_request_packet)

        # Receive the response
        response = s.recv(2048)

        # Extract the MAC address from the response
        mac_address = response[6:12].hex(':')
        print(mac_address)

        return mac_address
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

if __name__ == "__main__":
    ip_to_mac("172.17.216.224", "eth0")