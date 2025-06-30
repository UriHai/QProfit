from interface import Interface
from time import sleep


def main():
    interface = Interface("Intel(R) Wi-Fi 6 AX200 160MHz")
    interface.handle_incoming_frames()


if __name__ == '__main__':
    main()
