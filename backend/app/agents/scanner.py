import asyncio
import socket
from typing import Any
from urllib.parse import urlparse

import dns.asyncresolver
import httpx

from app.agents import Agent


class ScannerAgent(Agent):
    def __init__(self) -> None:
        super().__init__("Scanner Agent")
        self.common_subdomains = ["www", "api", "app", "dev", "stage", "staging", "admin", "cdn", "mail"]
        self.common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3000, 5000, 5432, 6379, 8000, 8080, 8443]

    async def run(self, target_url: str, scan_id: int) -> dict[str, Any]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Scanning {target_url}")
        hostname = await self.extract_hostname(target_url)
        subdomains = await self.enumerate_subdomains(hostname)
        open_ports = await self.scan_ports(hostname, self.common_ports)
        tech_stack = await self.detect_tech_stack(target_url)
        self.status = "complete"
        await self.log_action("completed", f"Found {len(subdomains)} subdomains and {len(open_ports)} open ports")
        return {"subdomains": subdomains, "open_ports": open_ports, "tech_stack": tech_stack}

    async def extract_hostname(self, target_url: str) -> str:
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        return parsed.hostname or target_url

    async def enumerate_subdomains(self, hostname: str) -> list[str]:
        candidates = [hostname, *[f"{prefix}.{hostname}" for prefix in self.common_subdomains]]
        tasks = [self.resolve_host(candidate) for candidate in candidates]
        resolved = await asyncio.gather(*tasks)
        return [candidate for candidate, found in zip(candidates, resolved) if found]

    async def resolve_host(self, hostname: str) -> bool:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 3.0
        resolver.timeout = 2.0
        try:
            await resolver.resolve(hostname, "A")
            return True
        except Exception:
            return False

    async def scan_ports(self, hostname: str, ports: list[int]) -> list[int]:
        tasks = [self.check_port(hostname, port) for port in ports]
        results = await asyncio.gather(*tasks)
        return [port for port, is_open in zip(ports, results) if is_open]

    async def check_port(self, hostname: str, port: int) -> bool:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(hostname, port), timeout=2.0)
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, OSError, socket.gaierror):
            return False

    async def detect_tech_stack(self, target_url: str) -> dict[str, Any]:
        url = target_url if "://" in target_url else f"https://{target_url}"
        headers: dict[str, str] = {}
        technologies: list[str] = []
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            try:
                response = await client.head(url)
                if response.status_code >= 400 or not response.headers:
                    response = await client.get(url)
                headers = {key.lower(): value for key, value in response.headers.items()}
            except httpx.HTTPError as exc:
                await self.log_action("http_error", f"Header detection failed: {exc}")

        for header_name in ("server", "x-powered-by", "x-generator", "via"):
            header_value = headers.get(header_name)
            if header_value:
                technologies.append(header_value)

        return {
            "technologies": sorted(set(technologies)),
            "headers": headers,
            "server": headers.get("server", ""),
            "x_powered_by": headers.get("x-powered-by", ""),
        }
