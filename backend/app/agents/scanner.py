import asyncio
import json
import socket
import ssl
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import dns.asyncresolver
import dns.query
import dns.zone
import httpx

from app.agents import Agent


SUBDOOM_WORDLIST = [
    "admin", "dev", "staging", "api", "mail", "vpn", "portal", "dashboard",
    "internal", "beta", "test", "old", "backup", "cdn", "auth", "login",
    "app", "shop", "cms", "blog", "git", "jenkins", "jira", "grafana",
    "kibana", "redis", "db", "mysql", "mongo", "ftp", "smtp", "pop",
    "imap", "ns1", "ns2", "mx", "support", "status", "docs", "www"
]

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 443, 3000, 3306, 5432, 6379, 8080, 8443,
    8888, 9200, 9300, 27017
]

WAF_SIGNATURES = {
    "cloudflare": ["cloudflare", "__cfduid", "cf-ray"],
    "akamai": ["akamai", "akamaighost"],
    "sucuri": ["sucuri", "x-sucuri-"],
    "imperva": ["imperva", "incapsula", "_incap_"],
}


class ScannerAgent(Agent):
    def __init__(self) -> None:
        super().__init__("Scanner Agent")

    async def run(self, target_url: str, scan_id: int) -> dict[str, Any]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Scanning {target_url}")

        hostname = self._extract_hostname(target_url)

        subdomains, dns_records, dangling_cnames = await self._dns_enum(hostname)
        open_ports = await self._port_scan(hostname)
        tech_stack, waf_detected = await self._fingerprint(target_url)

        self.open_ports = open_ports
        self.dns_records = dns_records
        self.tech_stack = tech_stack
        self.waf_detected = waf_detected
        self.cdn_detected = None
        self.tls_version = None
        self.tls_cipher = None
        self.tls_expiry = None
        self.tls_valid = None

        self.status = "complete"
        await self.log_action("completed", f"Found {len(subdomains)} subdomains, {len(open_ports)} open ports, {len(dangling_cnames)} dangling CNAMEs")

        result = {
            "subdomains": subdomains,
            "open_ports": open_ports,
            "tech_stack": tech_stack,
            "dns_records": dns_records,
            "dangling_cnames": dangling_cnames,
            "waf_detected": waf_detected,
        }

        await self._save_artifacts(result)
        await self.save_scan_artifacts()

        return result

    async def _save_artifacts(self, result: dict[str, Any]) -> None:
        try:
            from app.database import set_scan_artifacts
            await set_scan_artifacts(self.scan_id, scanner_output=result)
        except Exception as exc:
            await self.log_action("save_error", f"Failed to save scan artifacts: {exc}")

    async def save_scan_artifacts(self) -> None:
        try:
            from app.database import get_connection
            technologies = (self.tech_stack or {}).get("technologies", [])
            server_header = (self.tech_stack or {}).get("headers", {}).get("server", "")
            async with get_connection() as conn:
                await conn.execute("INSERT OR IGNORE INTO scan_artifacts (scan_id) VALUES (?)", (self.scan_id,))
                await conn.execute(
                    """
                    UPDATE scan_artifacts SET
                        ports_open = ?,
                        technologies = ?,
                        server_header = ?,
                        waf_detected = ?,
                        cdn_detected = ?,
                        dns_records = ?,
                        tls_version = ?,
                        tls_cipher = ?,
                        tls_expiry = ?,
                        tls_valid = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE scan_id = ?
                    """,
                    (
                        json.dumps(self.open_ports or []) if hasattr(self, 'open_ports') else None,
                        json.dumps(technologies) if technologies else None,
                        server_header or None,
                        self.waf_detected if hasattr(self, 'waf_detected') else None,
                        self.cdn_detected if hasattr(self, 'cdn_detected') else None,
                        json.dumps(self.dns_records or {}) if hasattr(self, 'dns_records') else None,
                        self.tls_version if hasattr(self, 'tls_version') else None,
                        self.tls_cipher if hasattr(self, 'tls_cipher') else None,
                        self.tls_expiry if hasattr(self, 'tls_expiry') else None,
                        1 if getattr(self, 'tls_valid', None) else 0,
                        self.scan_id,
                    ),
                )
                await conn.commit()
        except Exception as exc:
            await self.log_action("save_error", f"Failed to save recon artifacts: {exc}")

    def _extract_hostname(self, target_url: str) -> str:
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        return parsed.hostname or target_url

    async def _dns_enum(self, hostname: str) -> tuple[list[str], dict[str, Any], list[str]]:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 3.0
        resolver.timeout = 2.0

        records: dict[str, Any] = {}
        for rtype in ("A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA"):
            try:
                answers = await resolver.resolve(hostname, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []

        candidates = [f"{prefix}.{hostname}" for prefix in SUBDOOM_WORDLIST]
        if hostname not in candidates:
            candidates.insert(0, hostname)

        async def try_resolve(sub: str) -> tuple[str, bool, str]:
            try:
                answers = await resolver.resolve(sub, "CNAME")
                cname_target = str(answers[0])
                try:
                    await resolver.resolve(sub, "A")
                    return sub, True, ""
                except Exception:
                    return sub, False, cname_target
            except Exception:
                try:
                    await resolver.resolve(sub, "A")
                    return sub, True, ""
                except Exception:
                    return sub, False, ""

        tasks = [try_resolve(sub) for sub in candidates]
        results = await asyncio.gather(*tasks)

        subdomains: list[str] = []
        dangling_cnames: list[str] = []
        for sub, found, cname_target in results:
            if found:
                subdomains.append(sub)
            elif cname_target:
                dangling_cnames.append(f"{sub} -> {cname_target}")

        try:
            zone = await asyncio.to_thread(
                dns.zone.from_xfr, dns.query.xfr(hostname, hostname, lifetime=5)
            )
            for name in zone.nodes:
                subdomains.append(f"{name}.{hostname}")
        except Exception:
            pass

        return sorted(set(subdomains)), records, dangling_cnames

    async def _port_scan(self, hostname: str) -> list[int]:
        async def check(port: int) -> int | None:
            try:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port), timeout=2.0
                )
                w.close()
                await w.wait_closed()
                return port
            except Exception:
                return None

        results = await asyncio.gather(*[check(p) for p in COMMON_PORTS])
        return sorted([p for p in results if p is not None])

    async def _fingerprint(self, target_url: str) -> tuple[dict[str, Any], str]:
        url = target_url if "://" in target_url else f"https://{target_url}"
        headers: dict[str, str] = {}
        body = ""
        waf_detected = "none"

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            try:
                resp = await client.get(url, headers={"User-Agent": "PhantomScan/1.0"})
                headers = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.text[:5000]

                raw = str(resp.headers).lower()
                for waf_name, sigs in WAF_SIGNATURES.items():
                    if any(s in raw or s in body.lower() for s in sigs):
                        waf_detected = waf_name
                        break

                await self._save_evidence(url, "GET", f"Status: {resp.status_code}, Server: {headers.get('server', 'unknown')}, Body length: {len(resp.text)}")
            except Exception as exc:
                await self._save_evidence(url, "GET", f"Error: {exc}")
                pass

        tech_stack: dict[str, Any] = {
            "technologies": [],
            "headers": headers,
            "server": headers.get("server", ""),
            "x_powered_by": headers.get("x-powered-by", ""),
            "framework": self._detect_framework(headers, body),
        }

        for h in ("server", "x-powered-by", "x-generator", "via", "x-aspnet-version"):
            v = headers.get(h)
            if v and v not in tech_stack["technologies"]:
                tech_stack["technologies"].append(v)

        return tech_stack, waf_detected

    async def _save_evidence(self, request_url: str, method: str, summary: str) -> None:
        try:
            from app.database import get_connection
            async with get_connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO evidence_records (
                        request_id, scan_id, request_url, method, evidence_summary,
                        request_timestamp, module
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        self.scan_id,
                        request_url[:1000],
                        method,
                        summary[:500],
                        datetime.now(timezone.utc).isoformat(),
                        "scanner",
                    ),
                )
                await conn.commit()
        except Exception:
            pass

    def _detect_framework(self, headers: dict[str, str], body: str) -> str:
        b = body.lower()
        if "wp-content" in b or "wp-includes" in b:
            return "WordPress"
        if "drupal" in b:
            return "Drupal"
        if "csrf-token" in b and "laravel" in b:
            return "Laravel"
        if "rails" in b or "ruby on rails" in b:
            return "Ruby on Rails"
        if "next.js" in b or "__next" in b or "nextjs" in b:
            return "Next.js"
        if "react" in b or "reactroot" in b:
            return "React"
        if "vue" in b or "vuejs" in b:
            return "Vue.js"
        if "angular" in b:
            return "Angular"
        if "express" in b:
            return "Express"
        if "django" in b:
            return "Django"
        if "flask" in b:
            return "Flask"
        if "spring" in b:
            return "Spring"
        if "asp.net" in b or "aspx" in b:
            return "ASP.NET"
        if "nginx" in headers.get("server", "").lower():
            return "Nginx"
        if "apache" in headers.get("server", "").lower():
            return "Apache"
        return "unknown"
