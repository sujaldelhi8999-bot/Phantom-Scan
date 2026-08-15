"""Phase 4 — Loot generator for simulation mode.

Fabricates believable credentials, configs, database dumps and SSH keys for
the demo target. All values are fake; nothing is harvested from the real
target. The loot feeds the existing exfiltration packer, so the download flow
stays identical to the lab flow.
"""

import random
from typing import Any


class SimulationLoot:
    """Generates fake loot items for one engagement target."""

    def __init__(self, target_info: dict[str, Any], seed: int | None = None) -> None:
        self.target_info = target_info
        self.rng = random.Random(seed)
        self.hostname = str(target_info.get("hostname") or "target.example.com")

    def _password(self) -> str:
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%"
        return "".join(self.rng.choice(alphabet) for _ in range(16))

    def _api_key(self) -> str:
        return "sk-" + "".join(self.rng.choice("0123456789abcdef") for _ in range(32))

    def _session_secret(self) -> str:
        return "".join(self.rng.choice("0123456789abcdef") for _ in range(64))

    def generate_loot(self) -> list[dict[str, str]]:
        hostname = self.hostname
        users = [
            ("admin", "admin@" + hostname),
            ("backup", "backup@" + hostname),
            ("deploy", "deploy@ci." + hostname),
            ("billing", "billing@" + hostname),
        ]
        rows = "\n".join(
            f"({index}, '{name}', '{self._password()}', '{email}')"
            for index, (name, email) in enumerate(users, start=1)
        )
        return [
            {
                "file": ".env",
                "content": (
                    f"APP_ENV=production\n"
                    f"DB_HOST=localhost\nDB_PORT=3306\nDB_USER=root\nDB_PASS={self._password()}\n"
                    f"API_KEY={self._api_key()}\n"
                    f"SESSION_SECRET={self._session_secret()}\n"
                    f"STRIPE_SECRET_KEY=sk_live_{self._api_key()[3:]}\n"
                ),
                "kind": "config",
            },
            {
                "file": "config.php",
                "content": (
                    "<?php\n"
                    f"define('DB_HOST', 'localhost');\n"
                    f"define('DB_USER', 'root');\n"
                    f"define('DB_PASS', '{self._password()}');\n"
                    f"define('API_KEY', '{self._api_key()}');\n"
                    "?>"
                ),
                "kind": "config",
            },
            {
                "file": "database_dump.sql",
                "content": (
                    "-- MySQL dump 8.0.36  Distrib 8.0.36, for Linux\n"
                    "CREATE TABLE users (\n"
                    "    id INT PRIMARY KEY,\n"
                    "    username VARCHAR(50),\n"
                    "    password VARCHAR(255),\n"
                    "    email VARCHAR(100)\n"
                    ");\n"
                    "INSERT INTO users VALUES\n" + rows + ";\n"
                    "-- Dump completed on 2026-08-15 09:41:00"
                ),
                "kind": "database",
            },
            {
                "file": "ssh/id_rsa",
                "content": (
                    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcnNh\n"
                    "AAAAAwEAAQAAAYEA1lQd9y8hGD3jVQJn2ZL1TUbXkQzfP2NQqVzXkQbC4ZsXKjY5Y1RjZ8Fh\n"
                    "Q8yQh5rTb2LQoY1nRzWfH8vM8KkXkQbC4ZsXKjY5Y1RjZ8FhQ8yQh5rTb2LQoY1nRzWfH8\n"
                    "vM8KkXkQbC4ZsXKjY5Y1RjZ8FhQ8yQh5rTb2LQoY1nRzWfH8vM8KkXkQbC4ZsXKjY5Y1Rj\n"
                    "-----END OPENSSH PRIVATE KEY-----\n"
                    "(simulated key for demo — no real credentials)"
                ),
                "kind": "ssh_key",
            },
            {
                "file": "network_map.txt",
                "content": (
                    "# internal hosts discovered during engagement\n"
                    "10.0.0.1  web.internal  (compromised host)\n"
                    "10.0.0.2  db.internal   (mysql, 3306 open)\n"
                    "10.0.0.3  cache.internal (redis, 6379 open)\n"
                    "10.0.0.4  backups.internal (nfs, 2049 open)\n"
                    "# creds harvested: root / " + self._password()
                ),
                "kind": "network",
            },
        ]


def fake_user_rows(count: int = 5, seed: int | None = None) -> list[dict[str, str]]:
    """Shared helper for believable extracted 'users' used by exploit output."""
    rng = random.Random(seed)
    names = ["admin", "root", "backup", "deploy", "support", "billing", "dev", "webmaster"]
    return [
        {
            "id": str(index + 1),
            "username": names[index],
            "password_hash": "$2y$10$" + "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./") for _ in range(53)),
            "email": f"{names[index]}@example.com",
        }
        for index in range(min(count, len(names)))
    ]