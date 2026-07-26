import asyncio
from typing import Any

from app.agents import Agent
from app.agents.notifier import NotifierAgent
from app.agents.orchestrator import OrchestratorAgent
from app.config import get_settings
from app.database import (
    add_audit_log,
    create_scan,
    get_findings,
    set_scan_artifacts,
    update_scan_status,
)
from app.models import ScanRequest
from app.services.authorization import canonicalize_target


class SelfAuditAgent(Agent):
    def __init__(self) -> None:
        super().__init__("Self Audit Agent")
        self.settings = get_settings()

    async def run(self, target_url: str = "http://localhost:8000", scan_id: int | None = None) -> dict[str, Any]:
        target = canonicalize_target(target_url)
        if scan_id is None:
            scan_id = await create_scan(
                target_url=target.url,
                mode="defend",
                intensity="low",
                selected_tests="[]",
                user_id=self.settings.local_user_id,
            )
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", "Running PhantomScan self-audit through the defend pipeline")

        request = ScanRequest(target_url=target.url, mode="defend", intensity="low")
        try:
            result = await OrchestratorAgent().run(
                request,
                scan_id,
                user_id=self.settings.local_user_id,
            )
            if result.get("status") == "error":
                self.status = "error"
                await self.log_action("error", str(result.get("error", "Self-audit pipeline failed"))[:2000])
                return result

            findings = await get_findings(scan_id)
            critical_findings = [finding for finding in findings if finding.get("severity") == "CRITICAL"]
            notification_result: dict[str, Any] | None = None
            if critical_findings:
                await add_audit_log(
                    scan_id,
                    self.name,
                    "ALERT",
                    f"Self-audit produced {len(critical_findings)} critical findings",
                )
                notification_result = await NotifierAgent().run(
                    {"scan_id": scan_id, "critical_findings": critical_findings},
                    scan_id,
                    webhook_url=self.settings.self_audit_webhook,
                )
                await set_scan_artifacts(scan_id, notification_result=notification_result)

            self.status = "complete"
            await self.log_action(
                "completed",
                f"Self-audit completed with {len(findings)} findings and {len(critical_findings)} critical findings",
            )
            return {
                "scan_id": scan_id,
                "status": "complete",
                "findings": findings,
                "critical_findings": critical_findings,
                "notification": notification_result,
            }
        except asyncio.CancelledError:
            await update_scan_status(scan_id, "cancelled")
            await self.log_action("cancelled", "Self-audit task cancelled")
            raise
        except Exception as exc:
            self.status = "error"
            await update_scan_status(scan_id, "error", str(exc)[:1000])
            await self.log_action("error", str(exc)[:2000])
            raise
