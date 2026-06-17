import os


class Blocklist:
    def __init__(self, paths):
        if isinstance(paths, str):
            paths = [paths]

        self.paths = paths
        self.blocked = set()
        self.load()

    def load(self):
        self.blocked.clear()

        for path in self.paths:
            if os.path.isdir(path):
                for filename in os.listdir(path):
                    full_path = os.path.join(path, filename)

                    if os.path.isfile(full_path):
                        self._load_file(full_path)
            else:
                self._load_file(path)

        print(f"[INFO] Loaded {len(self.blocked)} blocked domains", flush=True)

    def _load_file(self, path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as file:
                for line in file:
                    domain = self._parse_line(line)

                    if domain:
                        self.blocked.add(domain)

        except FileNotFoundError:
            print(f"[WARN] Blocklist not found: {path}", flush=True)

    def _parse_line(self, line):
        line = line.strip().lower()

        if not line:
            return None

        if line.startswith("#"):
            return None

        if line.startswith("!"):
            return None

        if line.startswith("@@"):
            return None

        line = line.split("#", 1)[0].strip()

        parts = line.split()

        if not parts:
            return None

        # Hosts format:
        # 0.0.0.0 ads.example.com
        # 127.0.0.1 ads.example.com
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::1"):
            domain = parts[1]
        else:
            domain = parts[0]

        # uBlock / OISD format:
        # ||example.com^
        if domain.startswith("||"):
            domain = domain[2:]

        domain = domain.split("^", 1)[0]
        domain = domain.split("/", 1)[0]
        domain = domain.lstrip(".").rstrip(".")

        if not domain:
            return None

        if domain in ("localhost", "local", "broadcasthost"):
            return None

        if "." not in domain:
            return None

        return domain

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
