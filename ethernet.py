import struct
from binascii import hexlify, unhexlify

FORMAT = ">6s6sH"


def ethernet_frame(dst: str, src: str, prot_type: int, data: bytes) -> bytes:
    dst = unhexlify(dst.replace(':', ''))
    src = unhexlify(src.replace(':', ''))
    headers = struct.pack(FORMAT, dst, src, prot_type)
    frame = headers + data
    return frame


class EthernetFrame:
    HEADERS_SIZE = struct.calcsize(FORMAT)
    BROADCAST = b'\xff\xff\xff\xff\xff\xff'

    def __init__(self, buffer) -> None:
        """
        Initialize Ethernet Frame
        :param buffer: buffer containing raw bytes of the ethernet frame
        """
        headers, self.data = buffer[:self.HEADERS_SIZE], buffer[self.HEADERS_SIZE:]
        self.dst, self.src, self.type = struct.unpack(FORMAT, headers)

    def print_frame(self) -> None:
        """Print the dst, src and data fields of a frame"""
        print("Ethernet")
        print(f"dst: {str(hexlify(self.dst, ':'))[2:-1]}")
        print(f"src: {str(hexlify(self.src, ':'))[2:-1]}")
        print(f"data: {self.data}\n")

    def is_destined_to(self, mac) -> bool:
        """
        Check if a frame is designated to a mac address
        :param mac: The mac address to check
        :return: True if the frames was addressed to this mac, False otherwise
        """
        return (self.dst == mac or self.dst == self.BROADCAST) and self.src != mac
