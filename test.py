from ethernet import EthernetFrame
from scapy.all import conf, get_if_hwaddr
from binascii import unhexlify

IFACE = "Intel(R) Wi-Fi 6 AX200 160MHz"
IFACE_MAC = unhexlify(get_if_hwaddr(IFACE).replace(':', ''))

sock = conf.L2socket(iface=IFACE, promisc=True)  # Create the socket
while True:
    recv = sock.recv_raw()  # Receive data
    if recv[1]:
        frame = EthernetFrame(recv[1])
        frame.print_frame()
        print(frame.is_destined_to(IFACE_MAC))
