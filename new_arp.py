from utils import convert_mac_string_to_bytes, convert_ip_string_to_bytes
from struct import pack

ARP_FORMAT = ">HHbbH6s4s6s4s"
HARDWARE_TYPE = 1
PROTOCOL_TYPE = 0x800
HARDWARE_SIZE = 6
PROTOCOL_SIZE = 4
OPERATION_REQUEST = 1
OPERATION_REPLY = 2
BROADCAST_MAC_ADDRESS = "ff:ff:ff:ff:ff:ff"


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
    arp_frame = pack(ARP_FORMAT, HARDWARE_TYPE, PROTOCOL_TYPE, HARDWARE_SIZE, PROTOCOL_SIZE, operation, src_mac_bytes,
                     src_ip_bytes, dst_mac_bytes, dst_ip_bytes)
    return arp_frame


def build_arp_request_frame(src_mac: str, src_ip: str, dst_ip: str) -> bytes:
    """
    Build an ARP request frame
    :param src_mac: The source MAC address
    :param src_ip: The source IP address
    :param dst_ip: The target IP address
    :return: Bytes representation of the ARP request frame
    """
    return build_arp_frame(OPERATION_REQUEST, src_mac, src_ip, BROADCAST_MAC_ADDRESS, dst_ip)


def build_arp_reply_frame(src_mac: str, src_ip: str, dst_mac: str, dst_ip: str) -> bytes:
    """
    Build an ARP request frame
    :param src_mac: The source MAC address
    :param src_ip: The source IP address
    :param dst_mac: The target MAC address
    :param dst_ip: The target IP address
    :return: Bytes representation of the ARP request frame
    """
    return build_arp_frame(OPERATION_REPLY, src_mac, src_ip, dst_mac, dst_ip)
