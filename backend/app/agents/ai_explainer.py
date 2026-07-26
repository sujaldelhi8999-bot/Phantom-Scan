import json
from typing import Any

from app.agents import Agent
from app.config import get_settings
from app.services.openrouter_client import call_openrouter


class AIExplainerAgent(Agent):
    def __init__(self) -> None:
        super().__init__("AI Explainer Agent")
        self.settings = get_settings()

    async def run(self, findings: list[dict[str, Any]], scan_id: int) -> dict[str, list[dict[str, Any]]]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Enriching {len(findings)} findings with AI explanations")
        enriched = [await self.enrich_finding(finding) for finding in findings]
        self.status = "complete"
        await self.log_action("completed", f"Enriched {len(enriched)} findings")
        return {"findings": enriched}

    async def enrich_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        prompt = f"Given this vulnerability: {json.dumps(finding, ensure_ascii=False)}, explain in 2 sentences: 1) how an attacker would exploit it, 2) exact fix command or code."
        explanation = await call_openrouter(
            prompt,
            "You are a precise application security remediation assistant.",
            scan_id=self.scan_id,
        )
        enriched = dict(finding)
        if explanation:
            how_exploited, fix = await self.split_explanation(explanation)
            enriched["how_exploited"] = how_exploited
            enriched["fix"] = fix
        return enriched

    async def split_explanation(self, explanation: str) -> tuple[str, str]:
        sentences = [part.strip() for part in explanation.replace("\n", " ").split(".") if part.strip()]
        if len(sentences) >= 2:
            return f"{sentences[0]}.", f"{sentences[1]}."
        return explanation, explanation
