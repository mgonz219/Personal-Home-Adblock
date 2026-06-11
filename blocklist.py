class Blocklist:
    def __init__(self, path):
        self.path = path
        self.blocked = set()
        self.load()

    def load(self):
        self.blocked.clear()

        try:
            with open(self.path, "r", encoding="utf-8") as file:
                for line in file:
                    domain = line.strip().lower()

                    if not domain or domain.startswith("#"):
                        continue

                    self.blocked.add(domain.rstrip("."))
        except FileNotFoundError:
            print(f"[WARN] Blocklist not found: {self.path}")

    def is_blocked(self, domain):
        domain = domain.lower().rstrip(".")

        if domain in self.blocked:
            return True

        parts = domain.split(".")

        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.blocked:
                return True

        return False