from arp import arp_request, arp_reply
from scapy.all import conf, get_if_hwaddr

IFACE = "Intel(R) Wi-Fi 6 AX200 160MHz"
IFACE_MAC = get_if_hwaddr(IFACE)
sock = conf.L2socket(iface=IFACE, promisc=True)  # Create the socket

frame = arp_request(IFACE_MAC, "192.168.68.102", "192.168.68.1")
sock.send(frame)
frame = arp_reply(IFACE_MAC, "192.168.68.102", "84:d8:1b:b4:91:9c", "192.168.68.1")
sock.send(frame)
