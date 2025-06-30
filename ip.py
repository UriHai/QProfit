from utils import convert_ip_string_to_bytes

from struct import pack, unpack, calcsize

IP_HEADERS_FORMAT: str = ">BBHHHBBH4s4s"
IP_HEADERS_LENGTH: int = calcsize(IP_HEADERS_FORMAT)
IP_VERSION_AND_IHL: int = 0x45
IP_DSF: int = 0
IP_IDENTIFICATION: int = 0
IP_FLAGS_AND_OFFSET: int = 0
IP_TTL: int = 128
IP_HEADER_CHECKSUM: int = 0


def build_ip_packet(ip_protocol: int, src_ip: str, dst_ip: str, data: bytes) -> bytes:
    """
    Build an IPv4 packet
    :param ip_protocol: IP protocol type
    :param src_ip: The source IP address
    :param dst_ip: The target IP address
    :param data: The data of the packet
    :return: Bytes representation of the IP packet
    """
    total_length: int = IP_HEADERS_LENGTH + len(data)
    headers: bytes = pack(IP_HEADERS_FORMAT, IP_VERSION_AND_IHL, IP_DSF, total_length, IP_IDENTIFICATION,
                          IP_FLAGS_AND_OFFSET, IP_TTL, ip_protocol, IP_HEADER_CHECKSUM,
                          convert_ip_string_to_bytes(src_ip), convert_ip_string_to_bytes(dst_ip))
    return headers + data
