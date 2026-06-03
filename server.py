from dnslib.server import DNSServer
from resolver import AdBlockResolver
import time


def start_dns_server():
    resolver = AdBlockResolver()

    server = DNSServer(
        resolver,
        port=53,
        address="127.0.0.1"
    )

    print("DNS server running on 127.0.0.1:53")

    server.start_thread()

    while True:
        time.sleep(1)