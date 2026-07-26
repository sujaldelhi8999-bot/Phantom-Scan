import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.agents.self_audit import SelfAuditAgent
from app.config import get_settings
from app.database import (
    add_audit_log,
    database_is_available,
    get_audit_logs,
    get_findings,
    get_or_create_system_scan,
    get_scan,
    initialize_database,
)
from app.models import HealthResponse
from app.routers import active, agents, ai, authorization, findings, lab, logs, scan, self_audit
from app.services.jobs import scan_job_manager
from app.services.openrouter_client import get_ai_status
from app.websockets import scan_event_broker

settings = get_settings()
TERMINAL_SCAN_STATUSES = {"cancelled", "complete", "error"}


@asynccontextmanager
async def lifespan(application: FastAPI):
    await initialize_database()
    system_scan_id = await get_or_create_system_scan()
    await add_audit_log(system_scan_id, "System", "backend_started", "PhantomScan backend started")

    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(
        SelfAuditAgent().run,
        "cron",
        hour=2,
        minute=0,
        id="phantomscan_self_audit",
        replace_existing=True,
    )
    scheduler.start()
    application.state.scheduler = scheduler
    try:
        yield
    finally:
        if scheduler.running:
            scheduler.shutdown(wait=False)
        await scan_job_manager.shutdown()


app = FastAPI(title=settings.app_name, lifespan=lifespan)
print("CORS ALLOWED:", settings.cors_origins)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router)
app.include_router(active.router)
app.include_router(ai.router)
app.include_router(authorization.router)
app.include_router(agents.router)
app.include_router(logs.router)
app.include_router(findings.router)
app.include_router(self_audit.router)
app.include_router(lab.router)


def scheduler_state() -> str:
    scheduler = getattr(app.state, "scheduler", None)
    if scheduler is None:
        return "unavailable"
    return "running" if scheduler.running else "stopped"


async def health_snapshot() -> HealthResponse:
    database_available = await database_is_available()
    current_scheduler_state = scheduler_state()
    agents_available = agents.known_agents_available()
    ai_status_info = get_ai_status()
    return HealthResponse(
        status=(
            "ok"
            if database_available and current_scheduler_state == "running" and agents_available
            else "degraded"
        ),
        service="phantomscan",
        database="available" if database_available else "unavailable",
        scheduler=current_scheduler_state,
        agents="available" if agents_available else "unavailable",
        ai_provider=ai_status_info["provider"],
        ai_model=ai_status_info["model"],
        ai_status="connected" if ai_status_info["configured"] else "offline",
    )


@app.get("/api/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    return await health_snapshot()


def event_envelope(scan_id: int, event: dict[str, Any]) -> dict[str, Any]:
    event_name = str(event.get("event") or event.get("type") or "message")
    raw_payload = event.get("payload")
    if isinstance(raw_payload, dict):
        payload = dict(raw_payload)
    else:
        payload = {
            key: value
            for key, value in event.items()
            if key not in {"event", "type", "payload", "scan_id"}
        }
    return {
        "event": event_name,
        "type": event_name,
        "scan_id": scan_id,
        "payload": payload,
        **payload,
    }


async def scan_snapshot(scan_id: int, scan_record: dict[str, Any]) -> dict[str, Any]:
    return event_envelope(
        scan_id,
        {
            "event": "snapshot",
            "payload": {
                "status": scan_record["status"],
                "progress": int(scan_record["progress"]),
                "request_count": int(scan_record["request_count"]),
                "findings": await get_findings(scan_id),
                "logs": await get_audit_logs(scan_id),
            },
        },
    )


@app.websocket("/ws/status")
async def global_status(websocket: WebSocket) -> None:
    await websocket.accept()
    event_name = "status"
    try:
        while True:
            health = await health_snapshot()
            payload = {
                "api": "available",
                **health.model_dump(mode="json"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            await websocket.send_json(
                {
                    "event": event_name,
                    "type": event_name,
                    "payload": payload,
                    **payload,
                }
            )
            event_name = "heartbeat"
            await asyncio.sleep(5)
    except (WebSocketDisconnect, RuntimeError):
        return


@app.websocket("/ws/scan/{scan_id}")
async def scan_updates(websocket: WebSocket, scan_id: int) -> None:
    await websocket.accept()
    queue = await scan_event_broker.subscribe(scan_id)
    try:
        scan_record = await get_scan(scan_id)
        if scan_record is None:
            await websocket.send_json(event_envelope(scan_id, {"event": "error", "payload": {"error": "Scan not found"}}))
            await websocket.close(code=1008)
            return

        await websocket.send_json(await scan_snapshot(scan_id, scan_record))
        if scan_record["status"] in TERMINAL_SCAN_STATUSES:
            await websocket.close(code=1000)
            return

        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=2)
                await websocket.send_json(event_envelope(scan_id, event))
            except asyncio.TimeoutError:
                scan_record = await get_scan(scan_id)
                if scan_record is None:
                    await websocket.send_json(
                        event_envelope(scan_id, {"event": "error", "payload": {"error": "Scan not found"}})
                    )
                    await websocket.close(code=1008)
                    return
                await websocket.send_json(await scan_snapshot(scan_id, scan_record))

            scan_record = await get_scan(scan_id)
            if scan_record is None:
                await websocket.close(code=1008)
                return
            if scan_record["status"] in TERMINAL_SCAN_STATUSES:
                await websocket.send_json(await scan_snapshot(scan_id, scan_record))
                await websocket.close(code=1000)
                return
    except (WebSocketDisconnect, RuntimeError):
        return
    finally:
        await scan_event_broker.unsubscribe(scan_id, queue)
