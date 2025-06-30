from utils import ARP_ETHER_TYPE, convert_mac_bytes_to_string, convert_mac_string_to_bytes

from typing import Dict
from struct import pack, unpack, calcsize

ETHERNET_HEADERS_FORMAT: str = ">6s6sH"
ETHERNET_HEADERS_LENGTH: int = calcsize(ETHERNET_HEADERS_FORMAT)
ETHERNET_TYPES: Dict[int, str] = {ARP_ETHER_TYPE: "ARP"}


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
    headers = pack(ETHERNET_HEADERS_FORMAT, dst_bytes, src_bytes, protocol_type)
    ethernet_frame = headers + data
    return ethernet_frame


class EthernetFrame:
    def __init__(self, buffer: bytes) -> None:
        """
        Initialize Ethernet Frame
        :param buffer: Buffer containing raw bytes of the Ethernet frame
        """
        headers, self.data = buffer[:ETHERNET_HEADERS_LENGTH], buffer[ETHERNET_HEADERS_LENGTH:]
        dst, src, self.ethernet_type = unpack(ETHERNET_HEADERS_FORMAT, headers)
        self.dst: str = convert_mac_bytes_to_string(dst)
        self.src: str = convert_mac_bytes_to_string(src)

    def print_frame_headers(self) -> None:
        """Print the dst, src and data fields of a frame"""
        print("Ethernet")
        if self.ethernet_type in ETHERNET_TYPES:
            print(f"Type: {ETHERNET_TYPES[self.ethernet_type]}")
        else:
            print(f"Type: {hex(self.ethernet_type)}")
        print(f"dst: {self.dst}")
        print(f"src: {self.src}\n")
