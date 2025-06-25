from ethernet import EthernetFrame
from scapy.all import conf, IFACES

IFACE = "Intel(R) Wi-Fi 6 AX200 160MHz"
IFACE_MAC = b'\x84\xd8\x1b\xb4\x91\x9c'

sock = conf.L2socket(iface=IFACE, promisc=True)  # Create the socket
while True:
    recv = sock.recv_raw()  # Receive data
    if recv[1]:
        frame = EthernetFrame(recv[1])
        frame.print_frame()
        print(frame.is_destined_to(IFACE_MAC))
