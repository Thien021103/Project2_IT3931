    @handle_exceptions
    def scan_with_scapy(self, ip_range):
        
        results = []
        arp = ARP(pdst='192.168.56.0/24')
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=SCAN_TIMEOUT, retry=SCAN_RETRIES, verbose=False)[0]
        for sent, received in result:
            results.append({'ip': received.psrc, 'mac': received.hwsrc})
        return results