from utils import convert_ip_string_to_bytes, convert_ip_bytes_to_string

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


class IPPacket:
    def __init__(self, buffer: bytes) -> None:
        """
        Initialize IP packet
        :param buffer: buffer containing raw bytes of the ARP frame
        """
        headers: bytes = buffer[:IP_HEADERS_LENGTH]
        self.version_and_ihl, self.ip_dsf, self.total_length, self.identification, self.flags_and_offset, self.ttl, self.protocol, self.header_checksum, src_ip, dst_ip = unpack(
            IP_HEADERS_FORMAT, headers)
        self.src_ip = convert_ip_bytes_to_string(src_ip)
        self.dst_ip = convert_ip_bytes_to_string(dst_ip)
        self.data = buffer[IP_HEADERS_LENGTH:]
