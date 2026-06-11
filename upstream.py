import socket

from config import UPSTREAM_DNS, UPSTREAM_TIMEOUT


def forward_to_upstream(data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(UPSTREAM_TIMEOUT)

    try:
        sock.sendto(data, UPSTREAM_DNS)
        response, _ = sock.recvfrom(4096)
        return response

    except socket.timeout:
        print("[UPSTREAM ERROR] DNS request timed out")
        return None

    except Exception as error:
        print(f"[UPSTREAM ERROR] {error}")
        return None

    finally:
        sock.close()