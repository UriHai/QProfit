from new_ethernet import build_ethernet_frame
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

    def send_ethernet(self, dst_mac: str, protocol_type: int, data: bytes) -> None:
        """
        Send an Ethernet frame
        :param dst_mac: The target MAC address
        :param protocol_type: The protocol type
        :param data: The data to send
        """
        ethernet_frame = build_ethernet_frame(dst_mac, self.mac, protocol_type, data)
        self.sock.send(ethernet_frame)

    def send_arp_request(self, dst_ip) -> None:
        """
        Send an ARP request
        :param dst_ip: The target IP address
        """
        arp_frame = build_arp_frame()