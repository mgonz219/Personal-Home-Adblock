from datetime import datetime


class DNSLogger:
    def __init__(self, filename="dns.log"):
        self.filename = filename

    def log(self, event_type, domain):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        message = f"[{timestamp}] [{event_type}] {domain}"

        print(message)

        with open(self.filename, "a", encoding="utf-8") as file:
            file.write(message + "\n")

    def blocked(self, domain):
        self.log("BLOCKED", domain)

    def allowed(self, domain):
        self.log("ALLOWED", domain)

    def cache_hit(self, domain):
        self.log("CACHE_HIT", domain)

    def cache_store(self, domain):
        self.log("CACHE_STORE", domain)