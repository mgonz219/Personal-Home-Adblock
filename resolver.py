from dnslib import DNSRecord, RR, A, AAAA, QTYPE, RCODE

from config import BLOCKLIST_FILE, CACHE_ENABLED, DEFAULT_TTL
from blocklist import Blocklist
from cache import DNSCache
from logger import DNSLogger
from upstream import forward_to_upstream


class AdBlockResolver:
    def __init__(self):
        self.blocklist = Blocklist([
            BLOCKLIST_FILE,
            "blocklists"
        ])
        self.cache = DNSCache()
        self.logger = DNSLogger()

    def resolve(self, data):
        try:
            request = DNSRecord.parse(data)

            domain = str(request.q.qname).rstrip(".").lower()
            qtype = QTYPE[request.q.qtype]

            if self.blocklist.is_blocked(domain):
                self.logger.blocked(domain)
                return self.make_block_response(request)

            cache_key = self.get_cache_key(request)

            if CACHE_ENABLED:
                cached_response = self.cache.get(cache_key)

                if cached_response:
                    cached_packet = DNSRecord.parse(cached_response)
                    cached_packet.header.id = request.header.id

                    self.logger.cache_hit(domain)
                    return cached_packet.pack()

            response = forward_to_upstream(data)

            if CACHE_ENABLED and response:
                ttl = self.extract_ttl(response)
                self.cache.set(cache_key, response, ttl)
                self.logger.cache_store(domain)

            self.logger.allowed(domain)
            return response

        except Exception as error:
            print(f"[RESOLVER ERROR] {error}")
            return None

    def make_block_response(self, request):
        reply = request.reply()
        reply.header.rcode = RCODE.NOERROR

        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]

        if qtype == "A":
            reply.add_answer(
                RR(
                    rname=qname,
                    rtype=QTYPE.A,
                    rclass=1,
                    ttl=DEFAULT_TTL,
                    rdata=A("0.0.0.0")
                )
            )

        elif qtype == "AAAA":
            reply.add_answer(
                RR(
                    rname=qname,
                    rtype=QTYPE.AAAA,
                    rclass=1,
                    ttl=DEFAULT_TTL,
                    rdata=AAAA("::")
                )
            )

        return reply.pack()

    def get_cache_key(self, request):
        qname = str(request.q.qname).lower()
        qtype = QTYPE[request.q.qtype]

        return f"{qname}:{qtype}"

    def extract_ttl(self, response_data):
        try:
            response = DNSRecord.parse(response_data)

            if response.rr:
                return min(record.ttl for record in response.rr)

        except Exception:
            pass

        return DEFAULT_TTL
