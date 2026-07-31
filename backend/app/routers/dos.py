import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.agents.dos import DoSAgent, request_dos_stop
from app.database import get_connection
from app.routers.admin_scope import admin_required
from app.services.active_gate import ActiveTargetGate, canonicalize_hostname

logger = logging.getLogger("phantomscan.dos")

router = APIRouter(prefix="/api/admin/dos", tags=["Denial of Service"])


class DoSStartRequest(BaseModel):
    target_url: str = Field(min_length=4, max_length=2048)
    intensity: str = "low"
    duration: int = 30


INTENSITY_RULES = {
    "low": {"max_duration": 300, "allowed_outside_lab": True},
    "medium": {"max_duration": 120, "allowed_outside_lab": True},
    "high": {"max_duration": 30, "allowed_outside_lab": True},
    "critical": {"max_duration": 10, "allowed_outside_lab": False},
    "nuclear": {"max_duration": 5, "allowed_outside_lab": False},
}


def _is_lab_target(url: str) -> bool:
    lower = url.lower()
    return "phantombank" in lower or "localhost" in lower or "127.0.0.1" in lower


@router.post("/start")
async def start_dos(
    req: DoSStartRequest,
    _admin: dict = Depends(admin_required),
):
    if not req.target_url.startswith(("http://", "https://")):
        req.target_url = "https://" + req.target_url

    if req.intensity not in INTENSITY_RULES:
        req.intensity = "low"

    requested_intensity = req.intensity
    rules = INTENSITY_RULES[req.intensity]

    if not rules["allowed_outside_lab"] and not _is_lab_target(req.target_url):
        req.intensity = "high"
        rules = INTENSITY_RULES["high"]

    if req.duration > rules["max_duration"]:
        req.duration = rules["max_duration"]

    gate = ActiveTargetGate()
    hostname = canonicalize_hostname(req.target_url)
    decision = await gate.admit(
        target_url=req.target_url,
        user_id="admin",
        authorization_id=None,
        user_role="admin",
    )

    if not decision.allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Target not authorized for DoS testing: {decision.reason}",
        )

    agent = DoSAgent(req.target_url, req.intensity, req.duration)
    result = await agent.start()
    if requested_intensity != req.intensity:
        result["warning"] = (
            f"Intensity '{requested_intensity}' is lab-only and was auto-downgraded to "
            f"'high' (50 req/s, max {rules['max_duration']}s) for target {req.target_url}."
        )
    return result


@router.post("/stop/{job_id}")
async def stop_dos(
    job_id: str,
    _admin: dict = Depends(admin_required),
):
    try:
        return await request_dos_stop(job_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Job not found")


@router.get("/status/{job_id}")
async def get_dos_status(
    job_id: str,
    _admin: dict = Depends(admin_required),
):
    async with get_connection() as conn:
        cursor = await conn.execute("SELECT * FROM dos_jobs WHERE job_id = ?", (job_id,))
        row = await cursor.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Job not found")
    return dict(row)


@router.get("/history")
async def get_dos_history(
    _admin: dict = Depends(admin_required),
):
    async with get_connection() as conn:
        cursor = await conn.execute(
            """
            SELECT job_id, target_url, intensity, status,
                   requests_sent, responses_received, errors,
                   baseline_latency, peak_latency, avg_latency_during, recovery_latency,
                   impact_score, effective, website_status, health_score,
                   p95_latency, p99_latency, jitter_ms, error_rate, throughput_mbps,
                   total_requests, status_2xx, status_3xx, status_4xx, status_5xx,
                   total_data_mb, avg_dns_ms, avg_tcp_ms, avg_tls_ms, avg_ttfb_ms,
                   packet_loss, recovery_ratio, recovered,
                   started_at, stopped_at
            FROM dos_jobs
            ORDER BY started_at DESC
            LIMIT 50
            """
        )
        return [dict(row) for row in await cursor.fetchall()]
