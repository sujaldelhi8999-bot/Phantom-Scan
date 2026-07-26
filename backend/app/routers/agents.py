from fastapi import APIRouter, HTTPException, Query, status

from app.database import get_audit_logs, get_latest_scan, get_scan
from app.models import AgentStatus
from app.services.jobs import scan_job_manager

router = APIRouter(prefix="/api/agents", tags=["agents"])

AGENT_NAMES = [
    "Orchestrator Agent",
    "Scanner Agent",
    "Shadow Recon Agent",
    "Analyzer Agent",
    "CVE Matcher Agent",
    "Authentication Security Agent",
    "Access Control Agent",
    "API Security Agent",
    "Session Security Agent",
    "Injection Analysis Agent",
    "Infrastructure Agent",
    "WebSocket Security Agent",
    "Dependency Agent",
    "Threat Intelligence Agent",
    "Sandbox Manager Agent",
    "Pentest Agent",
    "AI Explainer Agent",
    "AI Security Analyst Agent",
    "Hindi Explainer Agent",
    "Fixer Agent",
    "Notifier Agent",
    "Self Audit Agent",
]


def known_agents_available() -> bool:
    return bool(AGENT_NAMES) and all(isinstance(name, str) and name.strip() for name in AGENT_NAMES)


@router.get("/status", response_model=list[AgentStatus])
async def agent_statuses(scan_id: int | None = Query(default=None, ge=1)) -> list[AgentStatus]:
    scan = await get_scan(scan_id) if scan_id is not None else await get_latest_scan()
    if scan_id is not None and scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if scan is None:
        return [AgentStatus(name=name, status="idle") for name in AGENT_NAMES]

    logs = await get_audit_logs(int(scan["id"]))
    states = {name: "idle" for name in AGENT_NAMES}
    for log in logs:
        name = str(log["agent_name"])
        if name not in states:
            continue
        action = str(log["action"]).lower()
        if action in {"started", "module_started", "sandbox_created"}:
            states[name] = "active"
        elif action in {"completed", "module_completed", "skipped", "delivered", "sandbox_destroyed"}:
            states[name] = "complete"
        elif action in {"error", "failed"}:
            states[name] = "error"
        elif action == "cancelled":
            states[name] = "idle"

    live_job = await scan_job_manager.is_active(int(scan["id"]))
    if live_job and scan["status"] in {"queued", "running", "cancelling"} and all(
        state == "idle" for state in states.values()
    ):
        states["Orchestrator Agent"] = "active"
    self_audit_active = states["Self Audit Agent"] == "active" and scan["status"] in {"running", "cancelling"}
    for name, agent_state in states.items():
        if agent_state != "active":
            continue
        if scan["status"] == "error":
            states[name] = "error"
        elif scan["status"] in {"cancelled", "complete"}:
            states[name] = "idle"
        elif not live_job and not self_audit_active:
            states[name] = "idle"

    return [AgentStatus(name=name, status=states[name]) for name in AGENT_NAMES]
