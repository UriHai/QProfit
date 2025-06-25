from ethernet import ethernet_frame
import struct
from binascii import unhexlify, hexlify

FORMAT = ">HHbbH6s4s6s4s"
HARDWARE_TYPE = 1
PROTOCOL_TYPE = 0x800
HARDWARE_SIZE = 6
PROTOCOL_SIZE = 4
REQUEST = 1
REPLY = 2
BROADCAST_BYTES = b'\xff\xff\xff\xff\xff\xff'
BROADCAST_STRING = "ff:ff:ff:ff:ff:ff"
ARP_ETHER_TYPE = 0x806


def arp_request(src_mac: str, src_ip: str, dst_ip: str) -> bytes:
    """
    Send an ARP request
    :param src_mac: The source mac
    :param src_ip: The source ip
    :param dst_ip: The target ip
    :return: Ethernet frame
    """
    src_mac_bytes = bytes([int(byte, 16) for byte in src_mac.split(':')])
    src_ip_bytes = bytes([int(byte) for byte in src_ip.split('.')])
    dst_ip_bytes = bytes([int(byte) for byte in dst_ip.split('.')])
    arp_frame = struct.pack(FORMAT, HARDWARE_TYPE, PROTOCOL_TYPE, HARDWARE_SIZE, PROTOCOL_SIZE, REQUEST, src_mac_bytes,
                            src_ip_bytes, BROADCAST_BYTES, dst_ip_bytes)
    frame = ethernet_frame(BROADCAST_STRING, src_mac, ARP_ETHER_TYPE, arp_frame)
    return frame


def arp_reply(src_mac: str, src_ip: str, dst_mac: str, dst_ip: str) -> bytes:
    """
    Send an ARP reply
    :param src_mac: The source mac
    :param src_ip: The source ip
    :param dst_mac: The target mac
    :param dst_ip: The target ip
    :return: Ethernet frame
    """
    src_mac_bytes = bytes([int(byte, 16) for byte in src_mac.split(':')])
    src_ip_bytes = bytes([int(byte) for byte in src_ip.split('.')])
    dst_mac_bytes = bytes([int(byte, 16) for byte in dst_mac.split(':')])
    dst_ip_bytes = bytes([int(byte) for byte in dst_ip.split('.')])
    arp_frame = struct.pack(FORMAT, HARDWARE_TYPE, PROTOCOL_TYPE, HARDWARE_SIZE, PROTOCOL_SIZE, REPLY, src_mac_bytes,
                            src_ip_bytes, dst_mac_bytes, dst_ip_bytes)
    frame = ethernet_frame(dst_mac, src_mac, ARP_ETHER_TYPE, arp_frame)
    return frame
