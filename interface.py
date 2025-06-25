from utils import BROADCAST_MAC_ADDRESS, ARP_ETHER_TYPE
from new_ethernet import build_ethernet_frame
from new_arp import build_arp_request_frame, build_arp_reply_frame
from scapy.all import conf, get_if_hwaddr, get_if_addr


class Interface:
    def __init__(self, name: str) -> None:
        """
        Initialize network interface
        :param name: The interface name
        """
        self.mac: str = get_if_hwaddr(name)
        self.ip: str = get_if_addr(name)
        self.sock = conf.L2socket(iface=name, promisc=True)
        self.arp_cache = {}
        self.routing_table = {}

    def handle_incoming_frames(self) -> None:
        """Show and handle all incoming frames"""
        while True:
            recv = self.sock.recv_raw()
            if recv[1]:
                ethernet_frame = EthernetFrame(recv[1])
                if ethernet_frame.type == ARP_ETHER_TYPE and ethernet_frame.is_destined_to(
                        unhexlify(IFACE_MAC.replace(':', ''))):
                    ethernet_frame.print_frame()
                    arp_frame = ARP_Frame(ethernet_frame.data)
                    arp_frame.print_frame()
                    arp_cache[arp_frame.src_ip] = arp_frame.src_mac

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
