from binascii import unhexlify


def convert_mac_to_bytes(mac: str) -> bytes:
    """
    Convert string representation of a MAC address to bytes
    :param mac: String representation of the MAC address
    :return: Bytes representation of the MAC address
    """
    return unhexlify(mac.replace(':', ''))


def convert_ip_to_bytes(ip: str) -> bytes:
    """
    Convert string representation of an IP address to bytes
    :param ip: String representation of the IP address
    :return: Bytes representation of the IP address
    """
    return unhexlify(ip.replace(':', ''))
