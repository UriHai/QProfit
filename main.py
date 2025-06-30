from interface import Interface


def main():
    interface = Interface("Intel(R) Wi-Fi 6 AX200 160MHz")
    interface.send_arp_request("192.168.68.103")
    interface.send_ip_packet(1, "192.168.1.103", b'123456')
    interface.handle_incoming_frames()


if __name__ == '__main__':
    main()
