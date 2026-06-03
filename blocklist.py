def load_blocklist(filename="blocklist.txt"):
    blocked = set()

    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line in file:
                domain = line.strip().lower()

                if not domain:
                    continue

                if domain.startswith("#"):
                    continue

                blocked.add(domain)

    except FileNotFoundError:
        print(f"Warning: {filename} not found.")

    return blocked