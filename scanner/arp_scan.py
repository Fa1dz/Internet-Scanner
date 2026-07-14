from scapy.all import ARP, Ether, srp


def scan_network(ip_range):
    devices = []
    try:
        if isinstance(ip_range, list):
            pdst = ','.join(ip_range)
        else:
            pdst = ip_range

        arp = ARP(pdst=pdst)
        ether = Ether(dst='ff:ff:ff:ff:ff:ff')
        packet = ether / arp

        result = srp(packet, timeout=2, verbose=0)[0]

        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    except Exception as e:
        print(f'Network scan error: {e}')
    return devices
