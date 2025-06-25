from utils import convert_mac_to_bytes
from struct import pack

ETHERNET_FORMAT = ">6s6sH"


def build_ethernet_frame(dst: str, src: str, protocol_type: int, data: bytes) -> bytes:
    """
    Build an Ethernet frame
    :param dst: Target MAC address
    :param src: Source MAC address
    :param protocol_type: The protocol type
    :param data: The data to send
    :return: Bytes representation of the Ethernet frame
    """
    dst_bytes: bytes = convert_mac_to_bytes(dst)
    src_bytes: bytes = convert_mac_to_bytes(src)
    headers = pack(ETHERNET_FORMAT, dst_bytes, src_bytes, protocol_type)
    ethernet_frame = headers + data
    return ethernet_frame
