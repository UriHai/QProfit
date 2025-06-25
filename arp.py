from ethernet import ethernet_frame
import struct
from binascii import unhexlify, hexlify

FORMAT = ">HHbbH6s4s6s4s"
FRAME_SIZE = struct.calcsize(FORMAT)
HARDWARE_TYPE = 1
PROTOCOL_TYPE = 0x800
HARDWARE_SIZE = 6
PROTOCOL_SIZE = 4
REQUEST = 1
REPLY = 2
BROADCAST_BYTES = b'\xff\xff\xff\xff\xff\xff'
BROADCAST_STRING = "ff:ff:ff:ff:ff:ff"
ARP_ETHER_TYPE = 0x806


class ARP_Frame:
    """
    Initialize ARP Frame
    :param buffer: buffer containing raw bytes of the ARP frame
    """

    def __init__(self, buffer) -> None:
        buffer = buffer[:FRAME_SIZE]
        self.hardware_type, self.protocol_type, self.hardware_length, self.protocol_lentgh, self.operatrion, \
        self.src_mac, self.src_ip, self.dst_mac, self.dst_ip = struct.unpack(FORMAT, buffer)

    def print_frame(self) -> None:
        """Print the dst, src and data fields of a frame"""
        if self.operatrion == REQUEST:
            print("ARP Request")
        else:
            print("ARP Reply")
        print(f"src mac: {str(hexlify(self.src_mac, ':'))[2:-1]}")
        print(f"src ip: {'.'.join([str(byte) for byte in self.src_ip])}")
        print(f"dst mac: {str(hexlify(self.dst_mac, ':'))[2:-1]}")
        print(f"dst ip: {'.'.join([str(byte) for byte in self.dst_ip])}\n")


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
