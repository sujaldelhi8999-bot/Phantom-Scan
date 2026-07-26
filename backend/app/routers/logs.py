import json
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.database import add_audit_log, get_audit_logs, get_scan, list_audit_logs
from app.models import AuditLog

router = APIRouter(prefix="/api/logs", tags=["logs"])


class SelfAuditAlert(BaseModel):
    scan_id: int
    critical_findings: list[dict[str, Any]] = Field(default_factory=list)


@router.get("", response_model=list[AuditLog])
async def all_logs(scan_id: int | None = Query(default=None, ge=1)) -> list[AuditLog]:
    rows = await list_audit_logs(scan_id)
    return [AuditLog(**row) for row in rows]


@router.post("/alert", status_code=status.HTTP_202_ACCEPTED)
async def receive_self_audit_alert(alert: SelfAuditAlert) -> dict[str, str]:
    scan = await get_scan(alert.scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    await add_audit_log(
        alert.scan_id,
        "Self Audit Webhook",
        "ALERT_RECEIVED",
        json.dumps(alert.critical_findings, default=str),
    )
    return {"status": "accepted"}


@router.get("/{scan_id}", response_model=list[AuditLog])
async def scan_logs(scan_id: int) -> list[AuditLog]:
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    rows = await get_audit_logs(scan_id)
    return [AuditLog(**row) for row in rows]
