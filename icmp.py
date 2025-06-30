from utils import ICMP_PING_TYPE, ICMP_PONG_TYPE

from struct import pack, unpack, calcsize

ICMP_HEADERS_FORMAT: str = "<BBH4s"
ICMP_HEADERS_LENGTH: int = calcsize(ICMP_HEADERS_FORMAT)
ICMP_CODE: int = 0
ICMP_CHECKSUM: int = 0

PING_FORMAT: str = "<HH"
PING_IDENTIFIER: int = 1
PING_DATA = b"abcdefghijklmnopqrstuvwabcdefghi"


def build_icmp_packet(icmp_type: int, rest: bytes, data: bytes) -> bytes:
    """
    Build an ICMP packet
    :param icmp_type: The ICMP type
    :param rest: Rest of the header
    :param data: The data section
    :return: Bytes representation of the ICMP packet
    """
    headers: bytes = pack(ICMP_HEADERS_FORMAT, icmp_type, ICMP_CODE, ICMP_CHECKSUM, rest)
    return headers + data


def build_ping_packet(sequence_number: int) -> bytes:
    """
    Build an ICMP Echo Request packet
    :param sequence_number: Ping sequence number
    :return: Bytes representation of the ping packet
    """
    headers: bytes = pack(PING_FORMAT, PING_IDENTIFIER, sequence_number)
    return build_icmp_packet(ICMP_PING_TYPE, headers, PING_DATA)


def build_pong_packet(identifier: int, sequence_number: int) -> bytes:
    """
    Build an ICMP Echo Reply packet
    :param identifier: Ping identifier
    :param sequence_number: Ping sequence number
    :return: Bytes representation of the pong packet
    """
    headers: bytes = pack(PING_FORMAT, identifier, sequence_number)
    return build_icmp_packet(ICMP_PONG_TYPE, headers, PING_DATA)


class ICMPPacket:
    def __init__(self, buffer: bytes) -> None:
        """
        Initialize ICMP packet
        :param buffer: buffer containing raw bytes of the ICMP packet
        """
        headers: bytes = buffer[:ICMP_HEADERS_LENGTH]
        self.icmp_type, self.code, self.checksum, self.rest = unpack(ICMP_HEADERS_FORMAT, headers)
        self.data: bytes = buffer[ICMP_HEADERS_LENGTH:]


class PingPacket:
    def __init__(self, buffer: bytes) -> None:
        """
        Initialize ICMP Echo Request packet
        :param buffer: buffer containing raw bytes of the ICMP packet
        """
        self.identifier, self.sequence_number = unpack(PING_FORMAT, buffer)
