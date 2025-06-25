from utils import BROADCAST_MAC_ADDRESS, ARP_ETHER_TYPE, convert_mac_string_to_bytes
from struct import pack, unpack, calcsize
from typing import Dict

ETHERNET_HEADERS_FORMAT: str = ">6s6sH"
ETHERNET_HEADERS_LENGTH: int = calcsize(ETHERNET_HEADERS_FORMAT)
ETHERNET_TYPES: Dict[int, str] = {}

def build_ethernet_frame(dst: str, src: str, protocol_type: int, data: bytes) -> bytes:
    """
    Build an Ethernet frame
    :param dst: Target MAC address
    :param src: Source MAC address
    :param protocol_type: The protocol type
    :param data: The data to send
    :return: Bytes representation of the Ethernet frame
    """
    dst_bytes: bytes = convert_mac_string_to_bytes(dst)
    src_bytes: bytes = convert_mac_string_to_bytes(src)
    headers = pack(ETHERNET_FORMAT, dst_bytes, src_bytes, protocol_type)
    ethernet_frame = headers + data
    return ethernet_frame


class EthernetFrame:
    def __init__(self, buffer) -> None:
        """
        Initialize Ethernet Frame
        :param buffer: Buffer containing raw bytes of the Ethernet frame
        """
        headers, self.data = buffer[:ETHERNET_HEADERS_LENGTH], buffer[ETHERNET_HEADERS_LENGTH:]
        dst, src, self.type = unpack(ETHERNET_HEADERS_FORMAT, headers)

    def print_frame(self) -> None:
        """Print the dst, src and data fields of a frame"""
        print("Ethernet")
        print(f"dst: {str(hexlify(self.dst, ':'))[2:-1]}")
        print(f"src: {str(hexlify(self.src, ':'))[2:-1]}")
        print(f"data: {self.data}\n")

    def is_destined_to(self, mac) -> bool:
        """
        Check if a frame is designated to a mac address
        :param mac: The mac address to check
        :return: True if the frames was addressed to this mac, False otherwise
        """
        return (self.dst == mac or self.dst == self.BROADCAST) and self.src != mac
