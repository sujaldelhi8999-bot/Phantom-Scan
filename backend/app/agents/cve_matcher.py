from typing import Any
from urllib.parse import quote_plus

import httpx

from app.agents import Agent
from app.config import get_settings


class CVEMatcherAgent(Agent):
    def __init__(self) -> None:
        super().__init__("CVE Matcher Agent")
        self.settings = get_settings()

    async def run(self, tech_stack: dict[str, Any], scan_id: int) -> dict[str, list[dict[str, Any]]]:
        self.scan_id = scan_id
        self.status = "active"
        technologies = await self.extract_technologies(tech_stack)
        await self.log_action("started", f"Matching CVEs for {len(technologies)} technologies")
        matches: list[dict[str, Any]] = []
        for technology in technologies:
            matches.extend(await self.search_nvd(technology))
        self.status = "complete"
        await self.log_action("completed", f"Matched {len(matches)} CVEs")
        return {"cve_matches": matches}

    async def extract_technologies(self, tech_stack: dict[str, Any]) -> list[str]:
        technologies: set[str] = set()
        for value in tech_stack.get("technologies", []):
            if isinstance(value, str) and value.strip():
                technologies.add(value.strip())
        for key in ("server", "x_powered_by"):
            value = tech_stack.get(key)
            if isinstance(value, str) and value.strip():
                technologies.add(value.strip())
        return sorted(technologies)

    async def search_nvd(self, technology: str) -> list[dict[str, Any]]:
        if not self.settings.nvd_api_key:
            await self.log_action("skipped", "NVD_API_KEY is not configured")
            return []
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote_plus(technology)}"
        headers = {"apiKey": self.settings.nvd_api_key}
        async with httpx.AsyncClient(timeout=15.0, trust_env=False) as client:
            try:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
            except httpx.HTTPError as exc:
                await self.log_action("nvd_error", f"NVD lookup failed for {technology}: {exc}")
                return []

        data = response.json()
        results: list[dict[str, Any]] = []
        for item in data.get("vulnerabilities", [])[:10]:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            description = next((entry.get("value", "") for entry in descriptions if entry.get("lang") == "en"), "")
            cvss_score = await self.extract_cvss_score(cve.get("metrics", {}))
            results.append({"technology": technology, "cve_id": cve_id, "cvss_score": cvss_score, "description": description})
        return results

    async def extract_cvss_score(self, metrics: dict[str, Any]) -> float | None:
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                return float(score) if score is not None else None
        return None
