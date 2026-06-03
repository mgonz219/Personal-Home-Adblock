from dnslib import DNSRecord, RR, A, QTYPE
from blocklist import load_blocklist
import socket


class AdBlockResolver:
    def __init__(self):
        self.blocked_domains = load_blocklist()
        print(f"Loaded {len(self.blocked_domains)} blocked domains")

    def resolve(self, request, handler):
        domain = str(request.q.qname).rstrip(".").lower()

        print(f"Query: {domain}")

        if self.is_blocked(domain):
            print(f"Blocked: {domain}")
            return self.block_response(request)

        return self.forward_request(request)

    def is_blocked(self, domain):
        return any(
            domain == blocked or domain.endswith("." + blocked)
            for blocked in self.blocked_domains
        )

    def block_response(self, request):
        reply = request.reply()

        reply.add_answer(
            RR(
                rname=request.q.qname,
                rtype=QTYPE.A,
                rclass=1,
                ttl=60,
                rdata=A("0.0.0.0")
            )
        )

        return reply

    def forward_request(self, request):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)

            sock.sendto(request.pack(), ("1.1.1.1", 53))

            data, _ = sock.recvfrom(4096)

            return DNSRecord.parse(data)

        except Exception as e:
            print("Forwarding error:", e)
            return request.reply()