"""Phase 3 — Simulated interactive shell for Brutal Mode.

A pure in-memory command interpreter. It never spawns subprocesses, never
touches the network and never writes to disk — every command is answered from
a filesystem tree that is built from the target's detected tech stack so the
demo feels specific to the scanned website.

State is kept per shell_id so consecutive WebSocket messages share one
filesystem (cd, cat, env all behave like a real session).
"""

import random
import time
import uuid
from typing import Any

from app.config import get_settings

PASSWD_FILE = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/bin/sh"
)


class SimulationShell:
    """Interactive simulated terminal for one engagement target."""

    def __init__(
        self,
        target_info: dict[str, Any],
        session_id: str,
        seed: int | None = None,
    ) -> None:
        self.target_info = target_info
        self.session_id = session_id
        self.target_url = str(target_info.get("target_url") or "")
        self.hostname = str(target_info.get("hostname") or "target")
        self.user = "www-data"
        self.rng = random.Random(seed)
        self.current_dir = "/"
        self.command_count = 0
        self.budget = get_settings().brutal_max_commands_per_shell
        self.remaining_budget = self.budget
        self.closed = False
        self._env: dict[str, str] = {
            "DB_HOST": "localhost",
            "DB_USER": "root",
            "DB_PASS": self.rng.choice(
                ["Sup3rS3cr3t!2026", "P@ssw0rd_1337", "r00t_db_!" + self.rng.choice("abcdef")],
            ),
            "API_KEY": "sk-" + "".join(self.rng.choice("0123456789abcdef") for _ in range(32)),
            "APP_ENV": "production",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": "/var/www",
        }
        self.filesystem = self._build_filesystem(target_info.get("tech_stack") or [])

    # -- filesystem ---------------------------------------------------------

    def _build_filesystem(self, tech_stack: list[str]) -> dict[str, dict[str, str]]:
        tech = [t.lower() for t in tech_stack]
        web_root = "/var/www/html"
        files: dict[str, dict[str, str]] = {
            "/etc": {
                "passwd": PASSWD_FILE,
                "hostname": self.hostname,
                "hosts": "127.0.0.1 localhost\n::1 localhost ip6-localhost\n10.0.0.2 db.internal\n10.0.0.3 cache.internal",
                "shadow": "root:!:19000:0:99999:7:::\nwww-data:!:19000:0:99999:7:::",
                "resolv.conf": "nameserver 10.0.0.53\nsearch internal",
                "issue": "Ubuntu 22.04.4 LTS \\n \\l",
            },
            "/var/www": {
                ".env": (
                    f"APP_ENV=production\n"
                    f"DB_HOST=localhost\nDB_PORT=3306\nDB_USER=root\nDB_PASS={self._env['DB_PASS']}\n"
                    f"API_KEY={self._env['API_KEY']}\n"
                    f"SESSION_SECRET={''.join(self.rng.choice('0123456789abcdef') for _ in range(64))}\n"
                    f"MAIL_PASSWORD={self.rng.choice(['Hunt3r!23', 'v3rY-$3cure']) }"
                ),
            },
            "/var/www/html": {},
            "/home/admin": {
                ".bash_history": "ls -la\ncd /var/www\ncat .env\nmysql -u root -p\n",
            },
            "/tmp": {"cache.txt": "session: ab01cd23ef45\nuser_agent: phantomscan-demo"},
            "/root": {"flag.txt": f"CTF{{simulated-access-{self.hostname.split('.')[0]}}}"},
        }
        if "wordpress" in tech:
            files["/var/www/html"] = {
                "wp-config.php": (
                    "<?php\n"
                    f"define('DB_NAME', 'wp_db');\n"
                    f"define('DB_USER', 'wp_user');\n"
                    f"define('DB_PASSWORD', '{self._env['DB_PASS']}');\n"
                    f"define('AUTH_KEY', '{''.join(self.rng.choice('0123456789abcdef') for _ in range(32))}');\n"
                    "?>"
                ),
                "index.php": "<?php get_header(); ?>",
                "xmlrpc.php": "<?php // xmlrpc endpoint enabled ?>",
            }
        elif "laravel" in tech:
            files["/var/www/html"] = {
                ".env": files["/var/www"][".env"],
                "artisan": "#!/usr/bin/env php",
                "storage/logs/laravel.log": "[2026-08-15 10:02:41] local.ERROR: SQLSTATE[HY000] [1045] Access denied for user 'root'@'localhost'",
            }
        elif "django" in tech:
            files["/var/www/html"] = {
                "manage.py": "#!/usr/bin/env python3",
                "settings.py": f"SECRET_KEY = '{''.join(self.rng.choice('0123456789abcdef') for _ in range(48))}'\nDEBUG = False\nDATABASES = {{'default': {{'NAME': 'app_db'}}}}",
            }
        else:
            files["/var/www/html"] = {
                "index.php": "<?php echo '<h1>Welcome</h1>';",
                "config.php": (
                    "<?php\n"
                    f"define('DB_HOST', 'localhost');\n"
                    f"define('DB_USER', 'root');\n"
                    f"define('DB_PASS', '{self._env['DB_PASS']}');\n"
                    "?>"
                ),
            }
        return files

    # -- command interpreter -------------------------------------------------

    async def execute(self, command: str) -> dict[str, Any]:
        started = time.monotonic()
        command = command.strip()
        if not command:
            return {"output": "", "exit_code": 0, "duration_ms": 0}
        self.command_count += 1
        self.remaining_budget = max(0, self.remaining_budget - 1)
        if self.closed:
            return {"output": "shell session is closed", "exit_code": -1, "duration_ms": 0}
        if self.command_count >= self.budget:
            return {"output": f"command budget exhausted ({self.budget})", "exit_code": -1, "duration_ms": 0}

        handler = self._dispatch(command)
        if handler is None:
            output = f"sh: 1: {command.split()[0]}: not found"
        else:
            try:
                output = handler(command)
            except Exception as exc:
                output = f"[simulated error: {exc}]"
        if output is None:
            output = ""
        return {
            "output": str(output)[:20_000],
            "exit_code": 0,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }

    def _dispatch(self, command: str) -> "object | None":
        parts = command.split()
        base = parts[0]
        table: dict[str, "object"] = {
            "whoami": lambda _: self.user,
            "id": lambda _: f"uid=33({self.user}) gid=33({self.user}) groups=33({self.user})",
            "pwd": lambda _: self.current_dir,
            "hostname": lambda _: self.hostname,
            "uname": lambda _: f"Linux {self.hostname} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
            "ls": self._cmd_ls,
            "cd": self._cmd_cd,
            "cat": self._cmd_cat,
            "env": self._cmd_env,
            "echo": lambda c: c[len("echo "):] if len(c) > 5 else "",
            "netstat": self._cmd_netstat,
            "ss": self._cmd_netstat,
            "ps": self._cmd_ps,
            "ifconfig": self._cmd_ifconfig,
            "ip": self._cmd_ip,
            "find": self._cmd_find,
            "sudo": self._cmd_sudo,
            "crontab": lambda _: "# m h  dom mon dow   command\n*/15 * * * * root /usr/local/bin/cleanup.sh >/dev/null 2>&1",
            "df": lambda _: "Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/sda1       51392892 42552360   6182416  88% /",
            "php": self._cmd_php,
            "python3": self._cmd_python3,
            "mysql": self._cmd_mysql,
            "sqlite3": self._cmd_mysql,
            "curl": self._cmd_curl,
            "wget": lambda _: "wget: missing URL\nUsage: wget [OPTION]... [URL]...",
            "service": lambda _: f" * Restarting web server (apache2)             [ OK ]",
            "systemctl": lambda _: "● php-fpm.service - PHP FastCGI Process Manager\n     Loaded: loaded (/lib/systemd/system/php-fpm.service; enabled)\n     Active: active (running) since Sat 2026-08-15 09:31:02 UTC",
            "strings": lambda c: c[len("strings "):][:40] + "\n... (simulated binary strings)",
        }
        if base in table:
            return table[base]
        if base == "exit" or base == "quit":
            return self._cmd_exit
        return None

    def _cmd_ls(self, command: str) -> str:
        path = self._resolve(command[len("ls"):].strip() or self.current_dir)
        entries = self.filesystem.get(path)
        if entries is None:
            return f"ls: cannot access '{path}': No such file or directory"
        flags = command.split()
        if "-la" in flags or "-l" in flags:
            lines = [f"drwxr-xr-x 2 {self.user} {self.user} 4096 {self.rng.randint(1, 28):02d} 2026 .",
                     f"drwxr-xr-x 4 root root 4096 2026-08-15 .."]
            for name, content in entries.items():
                if name.endswith("/"):
                    lines.append(f"drwxr-xr-x 2 {self.user} {self.user} 4096 2026-08-15 {name}")
                else:
                    size = len(str(content)) + self.rng.randint(10, 4000)
                    lines.append(f"-rw-r--r-- 1 {self.user} {self.user} {size:6d} 2026-08-15 {name}")
            return "\n".join(lines)
        return "\n".join(sorted(entries.keys()) or ["."])

    def _cmd_cd(self, command: str) -> str:
        parts = command.split()
        path = parts[1] if len(parts) > 1 else "/"
        target = self._resolve(path)
        if target in self.filesystem:
            self.current_dir = target
            return ""
        return f"cd: {path}: No such file or directory"

    def _cmd_cat(self, command: str) -> str:
        parts = command.split()
        if len(parts) < 2:
            return "usage: cat FILE"
        path = self._resolve(parts[1])
        for root, entries in self.filesystem.items():
            if path == root and isinstance(entries, dict):
                return f"cat: {parts[1]}: Is a directory"
        for root, entries in self.filesystem.items():
            if path in entries:
                return str(entries[path])
        return f"cat: {parts[1]}: No such file or directory"

    def _cmd_env(self, _: str) -> str:
        return "\n".join(f"{key}={value}" for key, value in self._env.items())

    def _cmd_netstat(self, _: str) -> str:
        db_port = "3306" if "mysql" in (self.target_info.get("tech_stack") or []) else "5432"
        return (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\n"
            f"tcp        0      0 127.0.0.1:{db_port}         0.0.0.0:*               LISTEN\n"
            "tcp        0      0 10.0.0.1:22             0.0.0.0:*               LISTEN"
        )

    def _cmd_ps(self, _: str) -> str:
        return (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.1 168888 11284 ?        Ss   Aug15   0:04 /sbin/init\n"
            "www-data   123  0.1  0.5  45678 12345 ?        S    Aug15   0:05 /usr/sbin/apache2\n"
            "www-data   456  0.0  0.3  34567  8901 ?        S    Aug15   0:02 /usr/sbin/php-fpm7.4\n"
            "mysql      789  0.2  1.1 899012 44789 ?        Ssl  Aug15   0:12 /usr/sbin/mysqld"
        )

    def _cmd_ifconfig(self, _: str) -> str:
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.0.0.1  netmask 255.255.255.0  broadcast 10.0.0.255\n"
            "        ether 0a:1b:2c:3d:4e:5f  txqueuelen 1000  (Ethernet)\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            "        inet 127.0.0.1  netmask 255.0.0.0"
        )

    def _cmd_ip(self, command: str) -> str:
        if "addr" in command:
            return self._cmd_ifconfig("")
        return "Usage: ip [ OPTIONS ] OBJECT { COMMAND }"

    def _cmd_find(self, command: str) -> str:
        if "perm -4000" in command:
            return "/usr/bin/passwd\n/usr/bin/sudo\n/usr/lib/dbus-1.0/dbus-daemon-launch-helper\n/usr/bin/mount"
        if "writable" in command:
            return "/tmp\n/var/www/html/uploads\n/var/cache\n/dev/shm"
        return "find: paths must precede expression"

    def _cmd_sudo(self, command: str) -> str:
        if "-l" in command:
            return "Matching Defaults entries for www-data on " + self.hostname + ":\n    env_reset, mail_badpass\n\nUser www-data may run the following commands on " + self.hostname + ":\n    (ALL) NOPASSWD: /usr/bin/php"
        return f"sudo: {self.user}: command not found"

    def _cmd_php(self, command: str) -> str:
        return "PHP Warning:  Cannot modify header information in /var/www/html/index.php on line 12\n"

    def _cmd_python3(self, command: str) -> str:
        return "Python 3.10.12 (main, Jun 11 2026, 09:26:02) [GCC 11.4.0] on linux\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n>>> "

    def _cmd_mysql(self, command: str) -> str:
        if "-e" in command:
            return (
                "+----+----------+---------------------+----------------+\n"
                "| id | username | password_hash       | role           |\n"
                "+----+----------+---------------------+----------------+\n"
                "|  1 | admin    | $2y$10$k2QxYJf8xBgQ1ZqL3qY/.. | administrator |\n"
                "|  2 | backup   | $2y$10$mZ8xYJf8xBgQ1ZqL3qY/.. | user          |\n"
                "+----+----------+---------------------+----------------+"
            )
        return "Welcome to the MySQL monitor.  Commands end with ; or \\g.\nType 'help;' or '\\h' for help."

    def _cmd_curl(self, command: str) -> str:
        url = [p for p in command.split() if p.startswith("http") or p.startswith("/")]
        if not url:
            return "curl: try 'curl --help' for more information"
        return f"< HTML> 200 OK\nContent-Type: text/html; charset=UTF-8\n\n( simulated response body for {url[0]} )"

    def _cmd_exit(self, _: str) -> str:
        self.closed = True
        return "__closed__"

    def _resolve(self, path: str) -> str:
        if path.startswith("/"):
            candidate = path
        else:
            candidate = (self.current_dir.rstrip("/") + "/" + path) if self.current_dir != "/" else "/" + path
        parts: list[str] = []
        for part in candidate.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(part)
        return "/" + "/".join(parts)


class SimulationShellRegistry:
    """In-memory registry mapping shell_id → SimulationShell."""

    _shells: dict[str, SimulationShell] = {}

    @classmethod
    def create(cls, session_id: str, target_info: dict[str, Any]) -> str:
        shell_id = uuid.uuid4().hex[:12]
        cls._shells[shell_id] = SimulationShell(target_info, session_id=session_id)
        return shell_id

    @classmethod
    def get(cls, shell_id: str) -> SimulationShell | None:
        return cls._shells.get(shell_id)

    @classmethod
    def close(cls, shell_id: str) -> bool:
        shell = cls._shells.get(shell_id)
        if shell is None:
            return False
        shell.closed = True
        return True

    @classmethod
    def remove(cls, shell_id: str) -> None:
        cls._shells.pop(shell_id, None)