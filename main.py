from interface import Interface
from time import sleep


def main():
    interface = Interface("Intel(R) Wi-Fi 6 AX200 160MHz")
    interface.ping("192.168.68.103")
    sleep(5)
    interface.ping("192.168.68.103")


if __name__ == '__main__':
    main()
