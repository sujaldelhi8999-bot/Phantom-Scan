from typing import Any

from app.agents import Agent
from app.services.openrouter_client import call_openrouter


class HindiExplainerAgent(Agent):
    def __init__(self) -> None:
        super().__init__("Hindi Explainer Agent")

    async def run(self, findings: list[dict[str, Any]], scan_id: int) -> dict[str, list[dict[str, Any]]]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Enriching {len(findings)} findings with Hindi AI explanations")
        enriched = [await self.enrich_finding(finding) for finding in findings]
        self.status = "complete"
        await self.log_action("completed", f"Enriched {len(enriched)} findings with Hindi explanations")
        return {"findings": enriched}

    async def enrich_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        prompt = (
            f"Given this vulnerability: {finding}, provide:\n\n"
            f"1. English explanation (technical security explanation):\n"
            f"2. Hindi explanation (simple Hindi/Hinglish explanation for beginners):\n\n"
            f"Also include how an attacker would exploit it and the exact fix command or code. "
            f"Keep commands and code unchanged."
        )
        system_prompt = (
            "You are a precise application security remediation assistant. "
            "Respond with both English and Hindi explanations. "
            "For Hindi, use simple Hindi/Hinglish that beginners can understand. "
            "Keep commands and code unchanged."
        )
        explanation = await call_openrouter(
            prompt,
            system_prompt,
            scan_id=self.scan_id,
            max_tokens=800,
        )
        enriched = dict(finding)
        if explanation:
            enriched["hindi_explanation"] = explanation
        return enriched
