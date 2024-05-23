import subprocess

def get_arp_table_unix(interface):
    arp_output = subprocess.check_output(['arp', '-i', interface, '-n'])
    arp_lines = arp_output.decode().split('\n')[1:]  # Skip header line
    arp_table = [line.split() for line in arp_lines if line.strip()]  # Split lines into columns
    return arp_table

arp_table = get_arp_table_unix('lo')  # Replace 'eth0' with the desired interface name
for entry in arp_table:
    print("IP Address:", entry[0], " MAC Address:", entry[2])
