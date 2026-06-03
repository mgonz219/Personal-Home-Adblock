import time


class DNSCache:
    def __init__(self):
        self.cache = {}

    def get(self, key):
        if key not in self.cache:
            return None

        response, expires_at = self.cache[key]

        if time.time() > expires_at:
            del self.cache[key]
            return None

        return response

    def set(self, key, response, ttl=300):
        expires_at = time.time() + ttl
        self.cache[key] = (response, expires_at)