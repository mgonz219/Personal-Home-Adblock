import socket

from config import LISTEN_IP, LISTEN_PORT
from resolver import AdBlockResolver


def start_dns_server():
    resolver = AdBlockResolver()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))

    print(f"DNS server running on {LISTEN_IP}:{LISTEN_PORT}")

    while True:
        data, client_address = sock.recvfrom(4096)

        response = resolver.resolve(data)

        if response:
            sock.sendto(response, client_address)