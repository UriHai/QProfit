from interface import Interface


def main():
    interface = Interface("Intel(R) Wi-Fi 6 AX200 160MHz")
    interface.send_arp_request("192.168.68.1")
    interface.handle_incoming_frames()


if __name__ == '__main__':
    main()
