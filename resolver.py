from dnslib import DNSRecord, RR, A, QTYPE
from blocklist import load_blocklist
from cache import DNSCache
from logger import DNSLogger

import socket


class AdBlockResolver:
    def __init__(self):
        self.blocked_domains = load_blocklist()
        self.cache = DNSCache()
        self.logger = DNSLogger()

        print(f"Loaded {len(self.blocked_domains)} blocked domains")

    def resolve(self, request, handler):
        domain = str(request.q.qname).rstrip(".").lower()
        qtype = QTYPE[request.q.qtype]

        cache_key = f"{domain}:{qtype}"

        cached_response = self.cache.get(cache_key)

        if cached_response:
            self.logger.cache_hit(cache_key)
            return DNSRecord.parse(cached_response)

        if self.is_blocked(domain):
            self.logger.blocked(domain)
            return self.block_response(request)

        self.logger.allowed(domain)

        response = self.forward_request(request)

        self.cache.set(
            cache_key,
            response.pack(),
            ttl=300
        )

        self.logger.cache_store(cache_key)

        return response

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

            sock.sendto(
                request.pack(),
                ("1.1.1.1", 53)
            )

            data, _ = sock.recvfrom(4096)

            return DNSRecord.parse(data)

        except Exception as e:
            print("Forwarding error:", e)

            return request.reply()