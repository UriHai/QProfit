from utils import BROADCAST_MAC_ADDRESS, ARP_ETHER_TYPE, ARP_OPERATION_REQUEST, ARP_OPERATION_REPLY
from ethernet import build_ethernet_frame, EthernetFrame
from arp import build_arp_request_frame, build_arp_reply_frame, ARPFrame

from typing import Dict
from scapy.all import conf, get_if_hwaddr, get_if_addr

"""
Information about this module by layer
--------------------------------------

Link layer:
Supported protocols: Ethernet, ARP
MAC address format: "xx:xx:xx:xx:xx:xx"

Network layer:
Supported protocols: IPv4, ICMP
IPv4 address format: "0.0.0.0"
"""


class Interface:
    def __init__(self, name: str) -> None:
        """
        Initialize network interface
        :param name: The interface name
        """
        self.mac: str = get_if_hwaddr(name)
        self.ip: str = get_if_addr(name)
        self.sock = conf.L2socket(iface=name, promisc=True)
        self.arp_cache: Dict[str, str] = {}
        self.routing_table = {}

    def handle_incoming_frames(self) -> None:
        """Show and handle incoming frames"""
        while True:
            recv = self.sock.recv_raw()
            if recv[1]:
                ethernet_frame = EthernetFrame(recv[1])
                if self.should_handle(ethernet_frame):
                    ethernet_frame.print_frame_headers()
                    if ethernet_frame.ethernet_type == ARP_ETHER_TYPE:
                        self.handle_arp_frame(ethernet_frame)

    def should_handle(self, ethernet_frame: EthernetFrame) -> bool:
        """
        Determine whether the Ethernet frame is addressed to this interface
        :param ethernet_frame: The Ethernet frame
        :return: True if the frames was addressed to this interface, False otherwise
        """
        return (
                       self.mac == ethernet_frame.dst or BROADCAST_MAC_ADDRESS == ethernet_frame.dst) and self.mac != ethernet_frame.src

    def send_ethernet(self, dst_mac: str, protocol_type: int, data: bytes) -> None:
        """
        Send an Ethernet frame
        :param dst_mac: The target MAC address
        :param protocol_type: The protocol type
        :param data: The data to send
        """
        ethernet_frame: bytes = build_ethernet_frame(dst_mac, self.mac, protocol_type, data)
        self.sock.send(ethernet_frame)

    def send_arp_request(self, dst_ip: str) -> None:
        """
        Send an ARP request
        :param dst_ip: The target IP address
        """
        arp_frame: bytes = build_arp_request_frame(self.mac, self.ip, dst_ip)
        self.send_ethernet(BROADCAST_MAC_ADDRESS, ARP_ETHER_TYPE, arp_frame)

    def send_arp_reply(self, dst_mac: str, dst_ip: str) -> None:
        """
        Send an ARP reply
        :param dst_mac: The target MAC address
        :param dst_ip: The target IP address
        """
        arp_frame: bytes = build_arp_reply_frame(self.mac, self.ip, dst_mac, dst_ip)
        self.send_ethernet(dst_mac, ARP_ETHER_TYPE, arp_frame)

    def handle_arp_frame(self, ethernet_frame: EthernetFrame) -> None:
        """
        Handle arp frames
        :param ethernet_frame: The Ethernet frame encapsulating the ARP frame
        """
        arp_frame = ARPFrame(ethernet_frame.data)
        arp_frame.print_arp_frame()
        self.arp_cache[arp_frame.src_ip] = arp_frame.src_mac
        if arp_frame.operation == ARP_OPERATION_REQUEST:
            self.send_arp_reply(arp_frame.src_mac, arp_frame.src_ip)
