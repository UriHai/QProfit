from typing import Tuple
from binascii import hexlify

BROADCAST_MAC_ADDRESS: str = "ff:ff:ff:ff:ff:ff"

ARP_ETHER_TYPE: int = 0x806
ARP_OPERATION_REQUEST: int = 1
ARP_OPERATION_REPLY: int = 2

IPv4_ETHER_TYPE: int = 0x800

IP_ICMP_TYPE: int = 1
ICMP_PING_TYPE: int = 8
ICMP_PONG_TYPE: int = 0


def convert_mac_string_to_bytes(mac: str) -> bytes:
    """
    Convert string representation of a MAC address to bytes
    :param mac: String representation of the MAC address
    :return: Bytes representation of the MAC address
    """
    return bytes([int(byte, 16) for byte in mac.split(':')])


def convert_ip_string_to_bytes(ip: str) -> bytes:
    """
    Convert string representation of an IP address to bytes
    :param ip: String representation of the IP address
    :return: Bytes representation of the IP address
    """
    return bytes([int(byte) for byte in ip.split('.')])


def convert_mac_bytes_to_string(mac: bytes) -> str:
    """
    Convert MAC bytes representation to string
    :param mac: Bytes representation of the MAC address
    :return: String representation of the MAC address
    """
    return str(hexlify(mac, ':'))[2:-1]


def convert_ip_bytes_to_string(ip: bytes) -> str:
    """
    Convert IP bytes representation to string
    :param ip: Bytes representation of the IP address
    :return: String representation of the IP address
    """
    return '.'.join([str(byte) for byte in ip])


def convert_ip_string_to_binary(ip: str) -> str:
    """
    Convert IP string to a binary string representation
    :param ip: String representation of the IP address
    :return: Binary string representation of the IP address
    """
    return ''.join([bin(int(byte))[2:].zfill(8) for byte in ip.split('.')])


def belongs_to_subnet(subnet: Tuple[str, int], ip: str) -> bool:
    """
    Check if an IPv4 address belongs to a subnet
    :param subnet: The subnet - (address, mask)
    :param ip: The IP address
    :return: True if the IP is part of the subnet, false otherwise
    """
    subnet_address, subnet_mask = subnet
    ip_binary: str = convert_ip_string_to_binary(ip)
    subnet_binary: str = convert_ip_string_to_binary(subnet_address)
    return ip_binary[:subnet_mask] == subnet_binary[:subnet_mask]
