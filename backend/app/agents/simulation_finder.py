"""Phase 2 — Finding generator for simulation mode.

Produces realistic, target-specific vulnerability findings derived from the
detected tech stack. Everything here is fabricated demonstration data for the
hackathon demo — no real exploit attempts are made.
"""

import random
from typing import Any

from app.brutal_sessions import BrutalSession
from app.agents.simulation_loot import fake_user_rows

SIM_SUPPORTED_CATEGORIES = {
    "sqli": "SQL Injection",
    "rce": "Remote Code Execution",
    "command_injection": "Command Injection",
    "lfi": "Local File Inclusion",
    "ssrf": "Server-Side Request Forgery",
    "file_upload": "Unrestricted File Upload",
    "xss": "Cross-Site Scripting",
    "injection": "Injection (auto)",
}


class SimulationExploitEngine:
    """Simulated exploitation flows. Never touches the target — output is
    generated from the session's intel + findings and captured as loot."""

    def __init__(self, session: BrutalSession, seed: int | None = None) -> None:
        self.session = session
        self.rng = random.Random(seed)

    async def exploit(self, category: str, finding: dict[str, Any] | None = None) -> dict[str, Any]:
        category_key = (category or "").lower().replace(" ", "_")
        if category_key not in SIM_SUPPORTED_CATEGORIES:
            return {"success": False, "error": f"Unsupported exploitation category: {category}"}
        handler = getattr(self, f"_exploit_{category_key}", None)
        if handler is None:
            return {"success": False, "error": f"No simulated flow implemented for {category}"}

        await self.session.log_op("exploit_started", "running", f"Exploiting {SIM_SUPPORTED_CATEGORIES[category_key]} (simulated)")
        result = await handler(finding)
        await self.session.log_op(
            "exploited",
            "success",
            result.get("summary", f"{SIM_SUPPORTED_CATEGORIES[category_key]} exploited"),
            output=result.get("output", "")[:4000],
        )
        return {"success": True, "category": category_key, "simulated": True, **result}

    def _matching_finding(self, category_key: str) -> dict[str, Any] | None:
        for finding in (self.session.sim_findings or []):
            title = str(finding.get("title", "")).lower()
            if category_key == "sqli" and "sql" in title:
                return finding
            if category_key == "lfi" and "local file" in title:
                return finding
            if category_key in ("rce", "command_injection") and ("eval" in title or "rce" in title or "code execution" in title):
                return finding
            if category_key == "xss" and "cross-site" in title:
                return finding
        return None

    async def _exploit_sqli(self, finding: dict[str, Any] | None) -> dict[str, Any]:
        rows = fake_user_rows(5, seed=random.randint(0, 2**31))
        self.session.add_loot("database", "users_dump.json", str(rows), "sqli (simulated)")
        self.session.add_loot(
            "database", "database_dump.sql",
            "CREATE TABLE users (id INT, username VARCHAR(50), password_hash VARCHAR(255), email VARCHAR(100));\n"
            + "\n".join(f"INSERT INTO users VALUES ({r['id']}, '{r['username']}', '{r['password_hash'][:28]}...', '{r['email']}');" for r in rows),
            "sqli (simulated)",
        )
        host = self.session.sim_intel.get("hostname") or "target"
        output = "\n".join(f"{r['id']}\t{r['username']}\t{r['password_hash'][:28]}…\t{r['email']}" for r in rows)
        return {
            "summary": f"SQLi exploited — dumped {len(rows)} user records from app_db@{host}",
            "rows": rows,
            "output": output,
            "shell_recommended": True,
        }

    async def _exploit_lfi(self, finding: dict[str, Any] | None) -> dict[str, Any]:
        passwd = "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/bin/sh\nbackup:x:1001:1001:backup:/home/backup:/bin/bash"
        self.session.add_loot("file", "etc_passwd.txt", passwd, "lfi (simulated)")
        return {
            "summary": "LFI confirmed — /etc/passwd readable through page parameter",
            "output": passwd,
            "shell_recommended": True,
        }

    async def _exploit_rce(self, finding: dict[str, Any] | None) -> dict[str, Any]:
        host = self.session.sim_intel.get("hostname") or "target"
        output = f"www-data@{host}\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\nLinux {host} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
        self.session.add_loot("command_output", "rce_probe.txt", output, "rce (simulated)")
        return {
            "summary": f"RCE confirmed on {host} — command execution as www-data",
            "output": output,
            "shell_recommended": True,
        }

    async def _exploit_command_injection(self, finding: dict[str, Any] | None) -> dict[str, Any]:
        return await self._exploit_rce(finding)

    async def _exploit_ssrf(self, finding: dict[str, Any] | None) -> dict[str, Any]:
        output = "SSRF scan: internal hosts reachable via /fetch?url=\n10.0.0.2:3306 mysql\n10.0.0.3:6379 redis\n10.0.0.4:2049 nfs\n"
        self.session.add_loot("network", "ssrf_internal_scan.txt", output, "ssrf (simulated)")
        return {"summary": "SSRF confirmed — internal network reachable", "output": output}

    async def _exploit_file_upload(self, finding: dict[str, Any] | None) -> dict[str, Any]:
        output = "Uploaded shell.php to /uploads/ — 200 OK, file executes as PHP"
        self.session.add_loot("file", "shell.php", "<?php system($_GET['c']); // simulated webshell", "file_upload (simulated)")
        return {"summary": "File upload bypassed — PHP webshell deployed", "output": output, "shell_recommended": True}

    async def _exploit_xss(self, finding: dict[str, Any] | None) -> dict[str, Any]:
        output = "Reflected XSS confirmed on /search — payload rendered unescaped in <div class=\"results\">"
        return {"summary": "Reflected XSS confirmed", "output": output}

    async def _exploit_injection(self, finding: dict[str, Any] | None) -> dict[str, Any]:
        for category_key, handler_name in (("sqli", "_exploit_sqli"), ("rce", "_exploit_rce")):
            if self._matching_finding(category_key):
                return await getattr(self, handler_name)(finding)
        return await self._exploit_sqli(finding)


class SimulationFinder:
    """Generates simulated findings for a target's detected tech stack."""

    def __init__(self, target_info: dict[str, Any], seed: int | None = None) -> None:
        self.target_info = target_info
        self.rng = random.Random(seed)
        self.hostname = str(target_info.get("hostname") or "target.example.com")

    def _hash(self, value: str) -> str:
        return self.rng.choice(
            [
                "3f8a9c2b1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
                "7d2b4f6a8c0e1d3f5a7b9c1e3d5f7a9b0c2e4d6f8a0b1c3e5d7f9a1b3c5e7d9f",
            ]
        )[:16]

    def _fake_users(self, count: int = 5) -> list[dict[str, str]]:
        domains = [self.hostname, "webmail." + self.hostname]
        users: list[dict[str, str]] = []
        names = ["admin", "root", "backup", "deploy", "support", "billing", "dev", "webmaster"]
        for index in range(min(count, len(names))):
            users.append(
                {
                    "id": str(index + 1),
                    "username": names[index],
                    "email": f"{names[index]}@{self.rng.choice(domains)}",
                    "password_hash": self._hash(names[index]),
                    "role": "administrator" if index == 0 else "user",
                }
            )
        return users

    def generate_findings(self) -> list[dict[str, Any]]:
        tech = [t.lower() for t in (self.target_info.get("tech_stack") or [])]
        findings: list[dict[str, Any]] = []

        if "wordpress" in tech:
            findings.append(
                {
                    "id": f"SIM-WP-{self.rng.randint(1000, 9999)}",
                    "title": "WordPress XML-RPC Brute Force",
                    "severity": "MEDIUM",
                    "cwe": "CWE-307",
                    "description": "The XML-RPC endpoint (xmlrpc.php) is enabled and allows system.multicall, enabling distributed credential brute-forcing against wp-login.php.",
                    "exploit": "wp-brute.py",
                    "payload": "POST /xmlrpc.php  method=system.multicall → wp.getUsersBlogs",
                }
            )
            findings.append(
                {
                    "id": f"SIM-WP-{self.rng.randint(1000, 9999)}",
                    "title": "WordPress Directory Listing",
                    "severity": "LOW",
                    "cwe": "CWE-548",
                    "description": "Directory listing is enabled for wp-content/uploads, exposing uploaded assets and prior backups.",
                    "exploit": "dirb http://{host}/wp-content/uploads/",
                    "payload": "GET /wp-content/uploads/ → 200 (Index of /)",
                }
            )

        if "mysql" in tech or "sqlite" in tech or "php" in tech or "wordpress" in tech:
            findings.append(
                {
                    "id": f"SIM-SQL-{self.rng.randint(1000, 9999)}",
                    "title": "SQL Injection in search parameter",
                    "severity": "CRITICAL",
                    "cwe": "CWE-89",
                    "description": "The 'q' (search) parameter is concatenated into a SQL query without parameterization. UNION-based injection can dump the entire database.",
                    "exploit": "sqlmap -u 'https://{host}/search?q=*' --dbs",
                    "payload": "search?q=' UNION SELECT id,username,password_hash,email FROM users --",
                    "extracted_data": {
                        "database": "app_db",
                        "tables": ["users", "sessions", "options", "audit_log"],
                        "sample": self._fake_users(),
                    },
                }
            )

        if "php" in tech:
            findings.append(
                {
                    "id": f"SIM-LFI-{self.rng.randint(1000, 9999)}",
                    "title": "Local File Inclusion",
                    "severity": "HIGH",
                    "cwe": "CWE-98",
                    "description": "The 'page' parameter is passed to include() without path validation, allowing arbitrary file reads on the server.",
                    "exploit": "lfi.py --url 'https://{host}/index.php?page='",
                    "payload": "index.php?page=../../../../etc/passwd",
                    "extracted_data": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/bin/sh",
                }
            )
            findings.append(
                {
                    "id": f"SIM-RCE-{self.rng.randint(1000, 9999)}",
                    "title": "PHP eval() Injection via template parameter",
                    "severity": "CRITICAL",
                    "cwe": "CWE-95",
                    "description": "User input reaches eval() in the theme renderer. Arbitrary PHP execution is possible.",
                    "exploit": "rce.py --url 'https://{host}/render'",
                    "payload": "render?tpl=system($_GET['c'])&c=id",
                }
            )

        if "asp.net" in tech:
            findings.append(
                {
                    "id": f"SIM-AZ-{self.rng.randint(1000, 9999)}",
                    "title": "ViewState without MAC validation",
                    "severity": "HIGH",
                    "cwe": "CWE-642",
                    "description": "ASP.NET ViewState is served without message authentication code, enabling deserialization attacks.",
                    "exploit": "ysoserial -p ViewState -g TypeConfuseDelegate",
                    "payload": "GET /Default.aspx → ViewState-encoded gadget chain",
                }
            )

        if "react" in tech or "angular" in tech or "node/express" in tech:
            findings.append(
                {
                    "id": f"SIM-XSS-{self.rng.randint(1000, 9999)}",
                    "title": "Reflected Cross-Site Scripting (XSS)",
                    "severity": "MEDIUM",
                    "cwe": "CWE-79",
                    "description": "The 'q' parameter is reflected into the SPA HTML without sanitization, allowing script injection.",
                    "exploit": "xss.py --url 'https://{host}/search'",
                    "payload": "q=<script>alert(document.domain)</script>",
                }
            )

        if "nginx" in tech or "apache" in tech:
            findings.append(
                {
                    "id": f"SIM-HDR-{self.rng.randint(1000, 9999)}",
                    "title": "Missing Security Headers",
                    "severity": "LOW",
                    "cwe": "CWE-693",
                    "description": "CSP, X-Frame-Options, HSTS and X-Content-Type-Options are absent from HTTP responses.",
                    "exploit": "curl -I https://{host}/",
                    "payload": "GET / → no Content-Security-Policy header",
                }
            )

        if not findings:
            findings.append(
                {
                    "id": f"SIM-GEN-{self.rng.randint(1000, 9999)}",
                    "title": "Exposed Admin Panel",
                    "severity": "MEDIUM",
                    "cwe": "CWE-306",
                    "description": "An administrative interface is reachable at /admin without rate limiting or lockout.",
                    "exploit": "dirb https://{host}/admin/",
                    "payload": "GET /admin/login → 200",
                }
            )

        for finding in findings:
            finding["description"] = finding["description"].replace("{host}", self.hostname)
            finding["exploit"] = finding["exploit"].replace("{host}", self.hostname)
            finding["payload"] = finding["payload"].replace("{host}", self.hostname)
        return findings

    @staticmethod
    def count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in findings:
            severity = str(finding.get("severity", "LOW")).upper()
            counts[severity] = counts.get(severity, 0) + 1
        return counts