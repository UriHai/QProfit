import struct


class EthernetFrame:
    FORMAT = f"<6s6sH"
    HEADERS_SIZE = struct.calcsize(FORMAT)
    BROADCAST = b'\xff\xff\xff\xff\xff\xff'

    def __init__(self, buffer) -> None:
        """
        Initialize Ethernet Frame
        :param buffer: buffer containing raw bytes of the ethernet frame
        """
        headers, self.data = buffer[:self.HEADERS_SIZE], buffer[self.HEADERS_SIZE:]
        self.dst, self.src, self.type = struct.unpack(self.FORMAT, headers)

    def print_frame(self) -> None:
        """Print the dst, src and data fields of a frame"""
        print(f"dst: {self.dst}")
        print(f"src: {self.src}")
        print(f"data: {self.data}")

    def is_destined_to(self, mac) -> bool:
        """
        Check if a frame is designated to a mac address
        :param mac: The mac address to check
        :return: True if the frames was addressed to this mac, False otherwise
        """
        return self.dst == mac or self.dst == self.BROADCAST
