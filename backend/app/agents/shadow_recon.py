import asyncio
import json
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
import whois

from app.agents import Agent


SENSITIVE_PATHS = [
    "/.git/HEAD", "/.env", "/config.php", "/wp-config.php",
    "/database.yml", "/.DS_Store", "/robots.txt", "/sitemap.xml",
]

DORK_QUERIES = [
    "site:{domain} ext:env OR ext:sql OR ext:log OR ext:bak",
    "site:{domain} inurl:admin OR inurl:login OR inurl:dashboard",
    'site:{domain} "index of /" OR "parent directory"',
    '"{domain}" filetype:pdf OR filetype:xlsx OR filetype:docx',
    'site:{domain} intitle:"phpinfo" OR intitle:"phpmyadmin"',
    'site:{domain} inurl:api OR inurl:rest OR inurl:graphql',
]


class ShadowReconAgent(Agent):
    def __init__(self) -> None:
        super().__init__("Shadow Recon Agent")

    async def run(self, target_url: str, scan_id: int) -> dict[str, Any]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Shadow recon for {target_url}")

        domain = self._extract_domain(target_url)
        base = target_url if "://" in target_url else f"https://{target_url}"

        whois_data = await self._lookup_whois(domain)
        dork_urls = self._build_dorks(domain)
        robots = await self._fetch_path(base, "/robots.txt")
        sitemap = await self._fetch_path(base, "/sitemap.xml")

        disallowed = self._parse_robots(robots.get("body", ""))
        sitemap_urls = self._parse_sitemap(sitemap.get("body", ""))

        homepage = await self._fetch_path(base, "/")
        leaked_emails = self._extract_emails(homepage.get("body", ""))
        js_sourcemaps = self._extract_sourcemaps(homepage.get("body", ""), base)
        internal_ips = self._extract_internal_ips(homepage.get("body", ""))
        comments = self._extract_html_comments(homepage.get("body", ""))

        exposed_files = await self._check_sensitive_paths(base)

        self.discovered_emails = leaked_emails
        self.internal_ips = internal_ips
        self.js_source_maps = js_sourcemaps
        self.html_comments = comments
        self.sensitive_files_found = {f["path"]: True for f in exposed_files} if exposed_files else {}
        self.robots_txt_content = robots.get("body", "")
        self.sitemap_urls = [u["url"] for u in sitemap_urls] if sitemap_urls else []

        self.status = "complete"
        await self.log_action(
            "completed",
            f"WHOIS: {'yes' if whois_data else 'no'}, "
            f"Dorks: {len(dork_urls)}, "
            f"Disallowed: {len(disallowed)}, "
            f"Sitemap: {len(sitemap_urls)}, "
            f"Emails: {len(leaked_emails)}, "
            f"Sourcemaps: {len(js_sourcemaps)}, "
            f"Exposed: {len(exposed_files)}"
        )

        result = {
            "whois": whois_data,
            "dork_urls": dork_urls,
            "disallowed_paths": disallowed,
            "sitemap_urls": sitemap_urls,
            "exposed_files": exposed_files,
            "leaked_emails": leaked_emails,
            "js_sourcemaps": js_sourcemaps,
            "robots_txt": robots.get("body", "")[:2000],
            "sitemap_xml": sitemap.get("body", "")[:2000],
            "internal_ips": internal_ips,
            "html_comments": comments,
        }

        await self._save_artifacts(result)
        await self.save_shadow_recon_results()

        return result

    async def _save_artifacts(self, result: dict[str, Any]) -> None:
        try:
            from app.database import set_scan_artifacts
            await set_scan_artifacts(self.scan_id, shadow_recon_output=result)
        except Exception as exc:
            await self.log_action("save_error", f"Failed to save shadow recon artifacts: {exc}")

    async def save_shadow_recon_results(self) -> None:
        try:
            from app.database import get_connection
            async with get_connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO shadow_recon_results (
                        scan_id, emails, internal_ips, js_source_maps,
                        html_comments, sensitive_files, robots_txt_content, sitemap_urls
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scan_id) DO UPDATE SET
                        emails = excluded.emails,
                        internal_ips = excluded.internal_ips,
                        js_source_maps = excluded.js_source_maps,
                        html_comments = excluded.html_comments,
                        sensitive_files = excluded.sensitive_files,
                        robots_txt_content = excluded.robots_txt_content,
                        sitemap_urls = excluded.sitemap_urls
                    """,
                    (
                        self.scan_id,
                        json.dumps(self.discovered_emails or []) if hasattr(self, 'discovered_emails') else None,
                        json.dumps(self.internal_ips or []) if hasattr(self, 'internal_ips') else None,
                        json.dumps(self.js_source_maps or []) if hasattr(self, 'js_source_maps') else None,
                        json.dumps(self.html_comments or []) if hasattr(self, 'html_comments') else None,
                        json.dumps(self.sensitive_files_found or {}) if hasattr(self, 'sensitive_files_found') else None,
                        self.robots_txt_content if hasattr(self, 'robots_txt_content') else None,
                        json.dumps(self.sitemap_urls or []) if hasattr(self, 'sitemap_urls') else None,
                    ),
                )
                await conn.commit()
        except Exception as exc:
            await self.log_action("save_error", f"Failed to save shadow recon results: {exc}")

    def _extract_domain(self, target_url: str) -> str:
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        return parsed.hostname or target_url

    async def _lookup_whois(self, domain: str) -> dict[str, Any]:
        try:
            result = await asyncio.to_thread(whois.whois, domain)
            data = {}
            for k, v in dict(result).items():
                if v is not None:
                    data[k] = str(v)
            return {
                "registrar": data.get("registrar", ""),
                "creation_date": str(data.get("creation_date", "")),
                "expiration_date": str(data.get("expiration_date", "")),
                "name_servers": data.get("name_servers", ""),
                "registrant_org": data.get("org", "") or data.get("name", ""),
                "raw": {k: v for k, v in data.items() if k in ("dnssec", "status", "emails", "country")},
            }
        except Exception as exc:
            await self.log_action("whois_error", str(exc))
            return {}

    def _build_dorks(self, domain: str) -> list[str]:
        return [q.format(domain=domain) for q in DORK_QUERIES]

    async def _fetch_path(self, base: str, path: str) -> dict[str, Any]:
        url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as c:
            try:
                r = await c.get(url, headers={"User-Agent": "PhantomScan/1.0"})
                return {"url": url, "status_code": r.status_code, "body": r.text[:50000]}
            except Exception as exc:
                return {"url": url, "status_code": None, "body": ""}

    def _parse_robots(self, body: str) -> list[str]:
        paths: list[str] = []
        for line in body.split("\n"):
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    paths.append(path)
        return paths

    def _parse_sitemap(self, body: str) -> list[dict[str, Any]]:
        urls: list[dict[str, Any]] = []
        for match in re.finditer(r"<loc>(.*?)</loc>", body, re.IGNORECASE):
            loc = match.group(1).strip()
            is_https = loc.startswith("https://")
            urls.append({"url": loc, "https": is_https})
        return urls

    def _extract_emails(self, body: str) -> list[str]:
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", body)
        return list(set(emails))

    def _extract_sourcemaps(self, body: str, base: str) -> list[str]:
        maps: list[str] = []
        for m in re.finditer(r'sourceMappingURL=([^\s"\'<>]+)', body, re.IGNORECASE):
            url = m.group(1).strip()
            if not url.startswith("http"):
                url = urljoin(base + "/", url)
            maps.append(url)
        for m in re.finditer(r'//# sourceMappingURL=([^\s"\']+)', body):
            url = m.group(1).strip()
            if not url.startswith("http"):
                url = urljoin(base + "/", url)
            maps.append(url)
        return list(set(maps))

    def _extract_internal_ips(self, body: str) -> list[str]:
        ips = re.findall(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", body)
        return list(set(ips))

    def _extract_html_comments(self, body: str) -> list[str]:
        return re.findall(r"<!--(.*?)-->", body, re.DOTALL)

    async def _check_sensitive_paths(self, base: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        async def check(path: str) -> None:
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=False, verify=False) as c:
                try:
                    r = await c.get(url, headers={"User-Agent": "PhantomScan/1.0"})
                    if r.status_code == 200:
                        body = r.text[:200]
                        results.append({
                            "path": path,
                            "url": url,
                            "status_code": r.status_code,
                            "snippet": body[:200],
                        })
                except Exception:
                    pass

        await asyncio.gather(*[check(p) for p in SENSITIVE_PATHS])
        return results
