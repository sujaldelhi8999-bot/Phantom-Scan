from typing import Any

from app.agents import Agent
from app.services.openrouter_client import call_openrouter


class HindiExplainerAgent(Agent):
    def __init__(self) -> None:
        super().__init__("Hindi Explainer Agent")

    async def run(
        self, findings: list[dict[str, Any]], scan_id: int
    ) -> dict[str, list[dict[str, Any]]]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Creating Hindi explanations for {len(findings)} findings")

        enriched: list[dict[str, Any]] = []
        for f in findings:
            sev = str(f.get("severity", "")).lower()
            if sev not in ("critical", "high"):
                enriched.append(f)
                continue
            e = await self._enrich(f)
            enriched.append(e)

        self.status = "complete"
        await self.log_action("completed", f"Hindi explanation added to {len([e for e in enriched if 'hindi' in str(e.get('hindi_report','')).lower()])} findings")
        return {"findings": enriched}

    async def _enrich(self, finding: dict[str, Any]) -> dict[str, Any]:
        title = str(finding.get("title", ""))
        desc = str(finding.get("evidence", "") or finding.get("description", ""))
        tech = str(finding.get("endpoint", ""))
        fix = str(finding.get("fix", ""))

        system_prompt = "Tum senior security expert ho. Sirf Hindi mein jawab do."
        user_prompt = (
            f"Vulnerability: {title} — {desc}\n"
            f"Stack: {tech}\n"
            f"1. Kya hai yeh? (simple Hindi mein samjhao)\n"
            f"2. Attacker kaise exploit karta hai?\n"
            f"3. Is platform ({tech}) ke liye exact fix kya hai?\n\n"
            f"Technical terms (XSS, SQLi, SSRF) English mein rakhna."
        )

        result = await call_openrouter(
            user_prompt, system_prompt,
            scan_id=self.scan_id, max_tokens=1024
        )

        enriched = dict(finding)
        if result:
            enriched["hindi_report"] = result.strip()
        else:
            fallback = (
                f"**{title}** — Yeh ek security vulnerability hai.\n"
                f"Attacker iska fayda uthakar system ko hack kar sakta hai.\n"
                f"Fix: {fix or 'Vendor documentation check karein.'}"
            )
            enriched["hindi_report"] = fallback

        return enriched
