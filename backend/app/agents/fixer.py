from typing import Any

from app.agents import Agent


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_RANGES = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.0, 3.9),
    "info": (None, None),
}

OWNER_MAP: dict[str, str] = {
    "xss": "frontend",
    "csp": "frontend",
    "xfo": "frontend",
    "cors": "backend",
    "csrf": "backend",
    "sqli": "backend",
    "ssrf": "backend",
    "rce": "devops",
    "lfi": "backend",
    "idor": "backend",
    "jwt": "backend",
    "xxe": "backend",
    "ssti": "backend",
    "tls": "devops",
    "hsts": "devops",
    "cookie": "backend",
    "info": "devops",
    "open_redirect": "backend",
    "upload": "backend",
    "auth": "backend",
    "ratelimit": "devops",
}

ETA_MAP: dict[str, str] = {
    "critical": "1h",
    "high": "4h",
    "medium": "1d",
    "low": "1w",
    "info": "1w",
}


class FixerAgent(Agent):
    def __init__(self) -> None:
        super().__init__("Fixer Agent")

    async def run(
        self, findings: list[dict[str, Any]], scan_id: int
    ) -> dict[str, str]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Generating remediation checklist for {len(findings)} findings")

        checklist = self._generate_checklist(findings)
        markdown = self._to_markdown(checklist)

        self.status = "complete"
        await self.log_action("completed", "Remediation checklist generated")
        return {"markdown_report": markdown, "checklist": checklist}

    def _generate_checklist(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped = self._group_by_severity(findings)
        checklist: list[dict[str, Any]] = []
        for sev in SEVERITY_ORDER:
            for f in grouped.get(sev, []):
                title = str(f.get("title", "Unknown finding"))
                component = str(f.get("endpoint", "") or f.get("affected_component", "") or "unknown")
                raw_fix = str(f.get("fix", "") or f.get("recommendation", "") or "Review manually")
                category = str(f.get("category", "")).lower()

                owner = self._assign_owner(title, category)
                eta = ETA_MAP.get(sev, "1d")

                checklist.append({
                    "severity": sev.upper(),
                    "title": title,
                    "affected": component,
                    "fix": raw_fix,
                    "owner": owner,
                    "eta": eta,
                })
        return checklist

    def _group_by_severity(self, findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        grouped: dict[str, list[dict[str, Any]]] = {s: [] for s in SEVERITY_ORDER}
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            if sev not in grouped:
                sev = "info"
            grouped[sev].append(f)
        return grouped

    def _assign_owner(self, title: str, category: str) -> str:
        t = (title + " " + category).lower()
        for keyword, owner in OWNER_MAP.items():
            if keyword in t:
                return owner
        return "backend"

    def _to_markdown(self, checklist: list[dict[str, Any]]) -> str:
        lines = ["# PhantomScan Remediation Checklist", ""]
        current_sev = ""
        for item in checklist:
            if item["severity"] != current_sev:
                current_sev = item["severity"]
                lines.append(f"## {current_sev}")
                lines.append("")
            lines.append(f"- [ ] **[{current_sev}]** {item['title']}")
            lines.append(f"  - Affected: {item['affected']}")
            lines.append(f"  - Fix: `{item['fix']}`")
            lines.append(f"  - Owner: {item['owner']}")
            lines.append(f"  - ETA: {item['eta']}")
            lines.append("")
        return "\n".join(lines)
