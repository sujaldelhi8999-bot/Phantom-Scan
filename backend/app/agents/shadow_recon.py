import asyncio
from typing import Any
from urllib.parse import urlparse

import httpx
import whois

from app.agents import Agent


class ShadowReconAgent(Agent):
    def __init__(self) -> None:
        super().__init__("Shadow Recon Agent")

    async def run(self, target_url: str, scan_id: int) -> dict[str, Any]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Running passive recon for {target_url}")
        domain = await self.extract_domain(target_url)
        whois_data, robots_txt, sitemap_xml = await asyncio.gather(
            self.lookup_whois(domain),
            self.fetch_path(target_url, "/robots.txt"),
            self.fetch_path(target_url, "/sitemap.xml"),
        )
        google_dorks = await self.build_google_dorks(domain)
        self.status = "complete"
        await self.log_action("completed", "Completed passive WHOIS, dork, robots.txt, and sitemap.xml recon")
        return {"whois": whois_data, "google_dorks": google_dorks, "robots_txt": robots_txt, "sitemap_xml": sitemap_xml}

    async def extract_domain(self, target_url: str) -> str:
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        return parsed.hostname or target_url

    async def lookup_whois(self, domain: str) -> dict[str, Any]:
        try:
            result = await asyncio.to_thread(whois.whois, domain)
            return {key: str(value) for key, value in dict(result).items() if value is not None}
        except Exception as exc:
            await self.log_action("whois_error", f"WHOIS lookup failed for {domain}: {exc}")
            return {}

    async def build_google_dorks(self, domain: str) -> list[str]:
        return [
            f"site:{domain} filetype:pdf",
            f"site:{domain} intitle:index.of",
            f"site:{domain} inurl:admin",
            f"site:{domain} inurl:login",
            f"site:{domain} ext:env OR ext:bak OR ext:old",
            f"site:{domain} \"password\" OR \"secret\" OR \"api_key\"",
        ]

    async def fetch_path(self, target_url: str, path: str) -> dict[str, Any]:
        base_url = target_url if "://" in target_url else f"https://{target_url}"
        parsed = urlparse(base_url)
        url = f"{parsed.scheme}://{parsed.netloc}{path}"
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            try:
                response = await client.get(url)
                return {"url": url, "status_code": response.status_code, "body": response.text[:10000]}
            except httpx.HTTPError as exc:
                await self.log_action("fetch_error", f"Could not fetch {url}: {exc}")
                return {"url": url, "status_code": None, "body": ""}
