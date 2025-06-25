from ethernet import EthernetFrame
from arp import ARP_Frame, arp_request
from scapy.all import conf, get_if_hwaddr
from binascii import unhexlify

ARP_ETHER_TYPE = 0x806

IFACE = "Intel(R) Wi-Fi 6 AX200 160MHz"
IFACE_MAC = get_if_hwaddr(IFACE)
sock = conf.L2socket(iface=IFACE, promisc=True)  # Create the socket

data = arp_request(IFACE_MAC, "192.168.68.102", "192.168.68.1")
ethernet_frame = EthernetFrame(data)
ethernet_frame.print_frame()
arp_frame = ARP_Frame(ethernet_frame.data)
arp_frame.print_frame()

sock.send(data)

arp_cache = {}

while True:
    recv = sock.recv_raw()  # Receive data
    if recv[1]:
        ethernet_frame = EthernetFrame(recv[1])
        if ethernet_frame.type == ARP_ETHER_TYPE and ethernet_frame.is_destined_to(unhexlify(IFACE_MAC.replace(':', ''))):
            ethernet_frame.print_frame()
            arp_frame = ARP_Frame(ethernet_frame.data)
            arp_frame.print_frame()
            arp_cache[arp_frame.src_ip] = arp_frame.src_mac
