from typing import Any

import httpx

from app.agents import Agent
from app.config import get_settings


class NotifierAgent(Agent):
    def __init__(self) -> None:
        super().__init__("Notifier Agent")
        self.settings = get_settings()

    async def run(self, scan_summary: dict[str, Any], scan_id: int, webhook_url: str | None = None) -> dict[str, Any]:
        self.scan_id = scan_id
        self.status = "active"
        destination = webhook_url or self.settings.notification_webhook_url
        await self.log_action("started", "Preparing webhook delivery")
        if not destination:
            self.status = "complete"
            await self.log_action("skipped", "No webhook URL configured")
            return {"delivered": False, "status_code": None, "message": "No webhook URL configured"}

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                response = await client.post(destination, json=scan_summary)
                delivered = 200 <= response.status_code < 300
                self.status = "complete" if delivered else "error"
                await self.log_action("delivered" if delivered else "failed", f"Webhook returned HTTP {response.status_code}")
                return {"delivered": delivered, "status_code": response.status_code, "message": response.text[:500]}
            except httpx.HTTPError as exc:
                self.status = "error"
                await self.log_action("failed", f"Webhook delivery failed: {exc}")
                return {"delivered": False, "status_code": None, "message": str(exc)}
