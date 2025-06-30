from utils import convert_mac_string_to_bytes, convert_ip_string_to_bytes, convert_mac_bytes_to_string, \
    convert_ip_bytes_to_string, BROADCAST_MAC_ADDRESS, ARP_OPERATION_REPLY, ARP_OPERATION_REQUEST

from struct import pack, unpack, calcsize

ARP_FORMAT: str = ">HHbbH6s4s6s4s"
ARP_LENGTH: int = calcsize(ARP_FORMAT)
HARDWARE_TYPE: int = 1
PROTOCOL_TYPE: int = 0x800
HARDWARE_SIZE: int = 6
PROTOCOL_SIZE: int = 4


def build_arp_frame(operation: int, src_mac: str, src_ip: str, dst_mac: str, dst_ip: str) -> bytes:
    """
    Build an ARP frame
    :param operation: Operation type (1 - request, 2- reply)
    :param src_mac: The source MAC address
    :param src_ip: The source IP address
    :param dst_mac: The target MAC address
    :param dst_ip: The target IP address
    :return: Bytes representation of the ARP frame
    """
    src_mac_bytes: bytes = convert_mac_string_to_bytes(src_mac)
    src_ip_bytes: bytes = convert_ip_string_to_bytes(src_ip)
    dst_mac_bytes: bytes = convert_mac_string_to_bytes(dst_mac)
    dst_ip_bytes: bytes = convert_ip_string_to_bytes(dst_ip)
    arp_frame: bytes = pack(ARP_FORMAT, HARDWARE_TYPE, PROTOCOL_TYPE, HARDWARE_SIZE, PROTOCOL_SIZE, operation,
                            src_mac_bytes, src_ip_bytes, dst_mac_bytes, dst_ip_bytes)
    return arp_frame


def build_arp_request_frame(src_mac: str, src_ip: str, dst_ip: str) -> bytes:
    """
    Build an ARP request frame
    :param src_mac: The source MAC address
    :param src_ip: The source IP address
    :param dst_ip: The target IP address
    :return: Bytes representation of the ARP request frame
    """
    return build_arp_frame(ARP_OPERATION_REQUEST, src_mac, src_ip, BROADCAST_MAC_ADDRESS, dst_ip)


def build_arp_reply_frame(src_mac: str, src_ip: str, dst_mac: str, dst_ip: str) -> bytes:
    """
    Build an ARP request frame
    :param src_mac: The source MAC address
    :param src_ip: The source IP address
    :param dst_mac: The target MAC address
    :param dst_ip: The target IP address
    :return: Bytes representation of the ARP request frame
    """
    return build_arp_frame(ARP_OPERATION_REPLY, src_mac, src_ip, dst_mac, dst_ip)


class ARPFrame:
    def __init__(self, buffer: bytes) -> None:
        """
        Initialize ARP Frame
        :param buffer: buffer containing raw bytes of the ARP frame
        """
        buffer = buffer[:ARP_LENGTH]
        self.hardware_type, self.protocol_type, self.hardware_length, self.protocol_length, \
        self.operation, src_mac, src_ip, dst_mac, dst_ip = unpack(ARP_FORMAT, buffer)
        self.src_mac = convert_mac_bytes_to_string(src_mac)
        self.src_ip = convert_ip_bytes_to_string(src_ip)
        self.dst_mac = convert_mac_bytes_to_string(src_mac)
        self.dst_ip = convert_ip_bytes_to_string(dst_ip)

    def print_arp_frame(self) -> None:
        """Print the dst, src and data fields of a frame"""
        if self.operation == ARP_OPERATION_REQUEST:
            print("ARP Request")
            print(f"Who has {self.dst_ip}? Tell {self.src_ip}")
        else:
            print("ARP Reply")
            print(f"{self.src_ip} is at {self.src_mac}\n")
