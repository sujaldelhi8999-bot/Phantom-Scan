import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.auth_middleware import get_current_user
from app.database import add_audit_log, get_audit_logs, get_scan, list_audit_logs
from app.models import AuditLog

router = APIRouter(prefix="/api/logs", tags=["logs"])


class SelfAuditAlert(BaseModel):
    scan_id: int
    critical_findings: list[dict[str, Any]] = Field(default_factory=list)


@router.get("", response_model=list[AuditLog])
async def all_logs(
    scan_id: int | None = Query(default=None, ge=1),
    user: dict = Depends(get_current_user),
) -> list[AuditLog]:
    rows = await list_audit_logs(scan_id, user["id"])
    return [AuditLog(**row) for row in rows]


@router.post("/alert", status_code=status.HTTP_202_ACCEPTED)
async def receive_self_audit_alert(
    alert: SelfAuditAlert,
    user: dict = Depends(get_current_user),
) -> dict[str, str]:
    scan = await get_scan(alert.scan_id)
    if scan is None or scan["user_id"] != user["id"]:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    await add_audit_log(
        alert.scan_id,
        "Self Audit Webhook",
        "ALERT_RECEIVED",
        json.dumps(alert.critical_findings, default=str),
        user_id=user["id"],
    )
    return {"status": "accepted"}


@router.get("/{scan_id}", response_model=list[AuditLog])
async def scan_logs(
    scan_id: int,
    user: dict = Depends(get_current_user),
) -> list[AuditLog]:
    scan = await get_scan(scan_id)
    if scan is None or scan["user_id"] != user["id"]:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    rows = await get_audit_logs(scan_id)
    return [AuditLog(**row) for row in rows]