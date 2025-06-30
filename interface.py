from utils import BROADCAST_MAC_ADDRESS, ARP_ETHER_TYPE, ARP_OPERATION_REQUEST, IPv4_ETHER_TYPE, IP_ICMP_TYPE, \
    belongs_to_subnet
from ethernet import build_ethernet_frame, EthernetFrame
from arp import build_arp_request_frame, build_arp_reply_frame, ARPFrame
from ip import build_ip_packet
from icmp import build_ping_packet

from typing import Dict, Tuple, Union
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

LAP = "28:39:26:BA:12:B1"


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
        self.routing_table: Dict[Tuple[str, int], Union[str, None]] = {
            ("192.168.68.0", 24): None,
            ("0.0.0.0", 0): "192.168.68.1"
        }
        self.sequence_number: int = 0

    def handle_incoming_frames(self) -> None:
        """Show and handle incoming frames"""
        while True:
            recv = self.sock.recv_raw()
            if recv[1]:
                ethernet_frame = EthernetFrame(recv[1])
                self.print_frame(ethernet_frame)
                if self.should_handle(ethernet_frame):
                    if ethernet_frame.ethernet_type == ARP_ETHER_TYPE:
                        self.handle_arp_frame(ethernet_frame)

    def print_frame(self, ethernet_frame: EthernetFrame) -> None:
        if ethernet_frame.src == LAP or ethernet_frame.dst == LAP:
            ethernet_frame.print_frame_headers()

    # Link layer
    def should_handle(self, ethernet_frame: EthernetFrame) -> bool:
        """
        Determine whether the Ethernet frame is addressed to this interface
        :param ethernet_frame: The Ethernet frame
        :return: True if the frames was addressed to this interface, False otherwise
        """
        return (self.mac == ethernet_frame.dst or BROADCAST_MAC_ADDRESS == ethernet_frame.dst) \
               and self.mac != ethernet_frame.src

    def send_ethernet_frame(self, dst_mac: str, protocol_type: int, data: bytes) -> None:
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
        self.send_ethernet_frame(BROADCAST_MAC_ADDRESS, ARP_ETHER_TYPE, arp_frame)

    def send_arp_reply(self, dst_mac: str, dst_ip: str) -> None:
        """
        Send an ARP reply
        :param dst_mac: The target MAC address
        :param dst_ip: The target IP address
        """
        arp_frame: bytes = build_arp_reply_frame(self.mac, self.ip, dst_mac, dst_ip)
        self.send_ethernet_frame(dst_mac, ARP_ETHER_TYPE, arp_frame)

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

    # Network layer
    def send_ip_packet(self, ip_protocol: int, dst_ip: str, data: bytes) -> None:
        """
        Send an IPv4 packet
        :param ip_protocol: IP protocol type
        :param dst_ip: The target IP address
        :param data: The data of the packet
        """
        gateway: Union[str, None] = self.get_gateway(dst_ip)
        if not gateway:
            gateway = dst_ip
        if gateway not in self.arp_cache:
            self.send_arp_request(gateway)
        else:
            ip_packet: bytes = build_ip_packet(ip_protocol, self.ip, dst_ip, data)
            self.send_ethernet_frame(self.arp_cache[gateway], IPv4_ETHER_TYPE, ip_packet)

    def get_gateway(self, dst_ip: str) -> Union[str, None]:
        """
        Find the gateway for an IPv4 packet
        :param dst_ip: The target IP address
        :return: None if the target is On-link or the IPv4 address of the gateway
        """
        for subnet, gateway in self.routing_table.items():
            if belongs_to_subnet(subnet, dst_ip):
                return gateway

    def ping(self, dst_ip: str) -> None:
        """
        Send ICMP echo request
        :param dst_ip: The target IP address
        """
        ping_packet: bytes = build_ping_packet(self.sequence_number)
        self.sequence_number += 1
        self.send_ip_packet(IP_ICMP_TYPE, dst_ip, ping_packet)
