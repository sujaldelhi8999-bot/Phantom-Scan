import asyncio
import re
from typing import Any
from urllib.parse import quote_plus

import httpx
from packaging.version import Version

from app.agents import Agent
from app.config import get_settings


JS_VULN_CHECK = {
    "jquery": {"min_fixed": Version("3.5.0"), "cve": "CVE-2020-11023"},
    "lodash": {"min_fixed": Version("4.17.21"), "cve": "CVE-2020-28502"},
    "moment": {"min_fixed": Version("2.29.4"), "cve": "CVE-2022-24785"},
    "axios": {"min_fixed": Version("1.6.0"), "cve": "CVE-2023-45857"},
    "vue": {"min_fixed": Version("2.7.16"), "cve": "CVE-2024-28184"},
    "react-dom": {"min_fixed": Version("18.2.0"), "cve": "CVE-2023-44270"},
}


class CVEMatcherAgent(Agent):
    def __init__(self) -> None:
        super().__init__("CVE Matcher Agent")
        self.settings = get_settings()

    async def run(
        self, tech_stack: dict[str, Any], scan_id: int
    ) -> dict[str, list[dict[str, Any]]]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", "Matching CVEs")

        technologies = self._extract_technologies(tech_stack)
        matches: list[dict[str, Any]] = []

        tasks = [self._search_nvd(tech) for tech in technologies]
        nvd_results = await asyncio.gather(*tasks)
        for results in nvd_results:
            matches.extend(results)

        body = str(tech_stack.get("headers", {}))
        body += str(tech_stack.get("technologies", []))
        matches.extend(self._check_js_libs(body))

        for m in matches:
            score = m.get("cvss_score")
            m["poc_likely"] = bool(score is not None and float(score) >= 3.0)

        self.status = "complete"
        await self.log_action("completed", f"Matched {len(matches)} CVEs")
        return {"cve_matches": matches}

    def _extract_technologies(self, tech_stack: dict[str, Any]) -> list[str]:
        techs: set[str] = set()
        for val in tech_stack.get("technologies", []):
            if isinstance(val, str) and val.strip():
                techs.add(val.strip())
        for key in ("server", "x_powered_by"):
            v = tech_stack.get(key)
            if isinstance(v, str) and v.strip():
                techs.add(v.strip())
        framework = tech_stack.get("framework", "")
        if isinstance(framework, str) and framework.strip() and framework != "unknown":
            techs.add(framework.strip())
        return sorted(techs)

    async def _search_nvd(self, technology: str) -> list[dict[str, Any]]:
        if not self.settings.nvd_api_key:
            await self.log_action("skipped", "NVD_API_KEY not configured")
            return []

        cpe = self._build_cpe(technology)
        if not cpe:
            return []

        matches: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            for severity in ("CRITICAL", "HIGH"):
                url = (
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                    f"?cpeName={quote_plus(cpe)}&cvssV3Severity={severity}"
                )
                try:
                    r = await client.get(url, headers={"apiKey": self.settings.nvd_api_key})
                    r.raise_for_status()
                except Exception:
                    continue

                data = r.json()
                for item in data.get("vulnerabilities", [])[:5]:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "")
                    descs = cve.get("descriptions", [])
                    desc = next(
                        (e.get("value", "") for e in descs if e.get("lang") == "en"), ""
                    )
                    score = self._extract_cvss(cve.get("metrics", {}))
                    matches.append({
                        "cve_id": cve_id,
                        "cvss_score": score,
                        "severity": severity,
                        "affected_component": technology,
                        "description": desc[:300],
                    })
        return matches

    def _build_cpe(self, tech: str) -> str:
        t = tech.lower().strip()
        t = re.sub(r"[^a-z0-9._-]", "", t)
        if not t:
            return ""
        return f"cpe:2.3:a:{t}:{t}:*:*:*:*:*:*:*"

    def _extract_cvss(self, metrics: dict[str, Any]) -> float | None:
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                data = entries[0].get("cvssData", {})
                s = data.get("baseScore")
                if s is not None:
                    return float(s)
        return None

    def _check_js_libs(self, body: str) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        b = body.lower()
        for lib, info in JS_VULN_CHECK.items():
            if lib in b:
                version_match = re.search(
                    rf'{re.escape(lib)}[\/\-\s]*(\d+\.\d+\.\d+)', body, re.IGNORECASE
                )
                if version_match:
                    try:
                        found_v = Version(version_match.group(1))
                        if found_v < info["min_fixed"]:
                            matches.append({
                                "cve_id": info["cve"],
                                "cvss_score": 7.5,
                                "severity": "HIGH",
                                "affected_component": f"{lib} {found_v}",
                                "description": f"Known vulnerable {lib} version {found_v}. Upgrade to {info['min_fixed']}+",
                                "poc_likely": True,
                            })
                    except Exception:
                        pass
        return matches
