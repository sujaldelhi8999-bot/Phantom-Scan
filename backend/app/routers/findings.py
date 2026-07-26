from datetime import datetime, timezone
from typing import Any, Literal

import httpx
from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel

from app.config import get_settings
from app.database import add_audit_log, get_finding, get_scan, list_findings, set_scan_artifacts, update_finding
from app.models import Finding
from app.services.active_gate import ActiveTargetGate
from app.services.active_security import ActiveSecurityEngine, CANONICAL_MODULES, normalize_module
from app.services.browser_observation import BrowserObservationEngine
from app.services.authorization import TargetAuthorizationService, TargetValidationError
from app.services.execution import SafetyLimits

router = APIRouter(prefix="/api/findings", tags=["findings"])
settings = get_settings()
authorization_service = TargetAuthorizationService()
active_gate = ActiveTargetGate(authorization_service)
BROWSER_VERIFICATION_MODULES = {"browser_console", "csp_analysis", "browser_storage", "javascript_static_analysis", "client_dataflow"}


class RemediationStatusRequest(BaseModel):
    remediation_status: Literal["OPEN", "IN_PROGRESS", "RESOLVED"]


class RiskStatusRequest(BaseModel):
    risk_status: Literal["ACTIVE", "FALSE_POSITIVE", "ACCEPTED_RISK"]


@router.get("", response_model=list[Finding])
async def all_findings(scan_id: int | None = Query(default=None, ge=1)) -> list[Finding]:
    rows = await list_findings(scan_id)
    return [Finding(**row) for row in rows]


@router.post("/{finding_id}/verify")
async def verify_finding_fix(finding_id: int, request: Request) -> dict[str, Any]:
    finding = await get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    scan = await get_scan(int(finding["scan_id"]))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Original scan not found")
    module = infer_module(finding)
    browser_module = infer_browser_module(finding) if module is None else None
    if module is None and browser_module is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Finding does not map to a supported active module")
    try:
        decision = await active_gate.admit(str(scan["target_url"]), str(scan.get("user_id") or settings.local_user_id), scan.get("authorization_id"))
    except TargetValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"code": "TARGET_NOT_VERIFIED", "message": decision.reason})

    if browser_module is not None:
        return await verify_browser_finding_fix(finding_id, finding, scan, decision, browser_module, request)

    limits = SafetyLimits.from_settings()
    transport = httpx.ASGITransport(app=request.app) if decision.is_lab else None
    engine = ActiveSecurityEngine(
        target_url=decision.target_url,
        attack_surface=None,
        selected_modules=[module],
        limits=limits,
        authorization_context=decision.to_context(),
        workflow_rules={},
        scan_id=int(finding["scan_id"]),
        user_id=str(scan.get("user_id") or settings.local_user_id),
        sandbox_id=f"verify-{finding_id}",
        transport=transport,
    )
    result = await engine.run()
    if result.get("status") not in {"complete", "limited"}:
        await update_finding(finding_id, verification_status="VERIFY_FAILED")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Verification check did not complete")
    still_present = any(normalize_module(str(item.get("module") or "")) == module for item in result.get("findings", []))
    verification_status = "ISSUE_STILL_PRESENT" if still_present else "FIX_VERIFIED"
    remediation_status = "OPEN" if still_present else "RESOLVED"
    verification = (
        f"{verification_status} at {datetime.now(timezone.utc).isoformat()} using module {module}. "
        f"Requests used: {result.get('request_count', 0)}."
    )
    await update_finding(
        finding_id,
        verification_status=verification_status,
        remediation_status=remediation_status,
        verification=verification,
    )
    await set_scan_artifacts(int(finding["scan_id"]), ai_analyst_output=None)
    await add_audit_log(
        int(finding["scan_id"]),
        "Active Security Engine",
        "fix_verification_completed",
        verification,
        user_id=str(scan.get("user_id") or settings.local_user_id),
        target=str(scan["target_url"]),
        authorization_status=decision.authorization_status,
        selected_module=module,
        result=verification_status,
        request_count=int(result.get("request_count", 0)),
        sandbox_id=f"verify-{finding_id}",
    )
    return {
        "finding_id": finding_id,
        "module": module,
        "status": verification_status,
        "remediation_status": remediation_status,
        "request_count": int(result.get("request_count", 0)),
    }


async def verify_browser_finding_fix(
    finding_id: int,
    finding: dict[str, Any],
    scan: dict[str, Any],
    decision: Any,
    module: str,
    request: Request,
) -> dict[str, Any]:
    limits = SafetyLimits.from_settings()
    transport = httpx.ASGITransport(app=request.app) if decision.is_lab else None
    engine = BrowserObservationEngine(
        target_url=decision.target_url,
        mode=str(scan.get("mode") or "defend"),
        authorization_context=decision.to_context(),
        limits=limits,
        scan_id=int(finding["scan_id"]),
        transport=transport,
        use_playwright=transport is None,
    )
    result = await engine.run()
    if result.get("status") not in {"complete", "limited"}:
        await update_finding(finding_id, verification_status="VERIFY_FAILED")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Browser verification check did not complete")
    original_title = str(finding.get("title") or "")
    still_present = any(
        str(item.get("module") or "") == module or str(item.get("title") or "") == original_title
        for item in result.get("findings", [])
        if isinstance(item, dict)
    )
    verification_status = "ISSUE_STILL_PRESENT" if still_present else "FIX_VERIFIED"
    remediation_status = "OPEN" if still_present else "RESOLVED"
    verification = (
        f"{verification_status} at {datetime.now(timezone.utc).isoformat()} using browser module {module}. "
        f"Requests used: {result.get('request_count', 0)}."
    )
    await update_finding(
        finding_id,
        verification_status=verification_status,
        remediation_status=remediation_status,
        verification=verification,
    )
    await set_scan_artifacts(int(finding["scan_id"]), ai_analyst_output=None)
    await add_audit_log(
        int(finding["scan_id"]),
        "Browser Security Agent",
        "fix_verification_completed",
        verification,
        user_id=str(scan.get("user_id") or settings.local_user_id),
        target=str(scan["target_url"]),
        authorization_status=decision.authorization_status,
        selected_module=module,
        result=verification_status,
        request_count=int(result.get("request_count", 0)),
        sandbox_id=f"browser-verify-{finding_id}",
    )
    return {
        "finding_id": finding_id,
        "module": module,
        "status": verification_status,
        "remediation_status": remediation_status,
        "request_count": int(result.get("request_count", 0)),
    }


@router.patch("/{finding_id}/remediation", response_model=Finding)
async def update_finding_remediation(finding_id: int, payload: RemediationStatusRequest) -> Finding:
    finding = await get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    await update_finding(finding_id, remediation_status=payload.remediation_status)
    updated = await get_finding(finding_id)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    await set_scan_artifacts(int(updated["scan_id"]), ai_analyst_output=None)
    await add_audit_log(
        int(updated["scan_id"]),
        "Remediation",
        "remediation_status_updated",
        f"Finding {finding_id} marked {payload.remediation_status}",
        target=str(updated.get("target") or ""),
        result=payload.remediation_status,
    )
    return Finding(**updated)


@router.patch("/{finding_id}/risk", response_model=Finding)
async def update_finding_risk_status(finding_id: int, payload: RiskStatusRequest) -> Finding:
    finding = await get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    await update_finding(finding_id, risk_status=payload.risk_status)
    updated = await get_finding(finding_id)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    await set_scan_artifacts(int(updated["scan_id"]), ai_analyst_output=None)
    await add_audit_log(
        int(updated["scan_id"]),
        "Risk Triage",
        "risk_status_updated",
        f"Finding {finding_id} marked {payload.risk_status}",
        target=str(updated.get("target") or ""),
        result=payload.risk_status,
    )
    return Finding(**updated)


def infer_module(finding: dict[str, Any]) -> str | None:
    explicit = normalize_module(str(finding.get("module") or ""))
    if explicit in CANONICAL_MODULES:
        return explicit
    text = " ".join(str(finding.get(name) or "") for name in ["category", "title", "evidence"]).lower()
    rules = [
        ("input_security", ["input", "validation"]),
        ("injection", ["injection", "data-layer", "data layer"]),
        ("xss", ["xss", "output encoding", "html-like"]),
        ("auth_session", ["authentication", "session", "rate-limit", "rate limit"]),
        ("access_control", ["access control", "authorization", "admin"]),
        ("csrf", ["csrf"]),
        ("file_upload", ["file upload"]),
        ("path_handling", ["path"]),
        ("api_security", ["api"]),
        ("graphql", ["graphql"]),
        ("websocket", ["websocket"]),
        ("jwt", ["jwt", "token"]),
        ("redirect", ["redirect"]),
        ("cors", ["cors"]),
        ("security_headers", ["security header", "browser security"]),
        ("tls_https", ["tls", "https"]),
        ("sensitive_exposure", ["sensitive", "debug", "diagnostic"]),
        ("business_logic", ["business logic", "workflow", "transfer"]),
    ]
    for module, needles in rules:
        if any(needle in text for needle in needles):
            return module
    return None


def infer_browser_module(finding: dict[str, Any]) -> str | None:
    explicit = str(finding.get("module") or "").strip().lower()
    if explicit in BROWSER_VERIFICATION_MODULES:
        return explicit
    text = " ".join(str(finding.get(name) or "") for name in ["category", "title", "evidence"]).lower()
    rules = [
        ("browser_console", ["console", "browser warning"]),
        ("csp_analysis", ["csp", "content-security-policy"]),
        ("browser_storage", ["cookie", "storage", "localstorage", "sessionstorage"]),
        ("javascript_static_analysis", ["source map", "javascript", "script"]),
        ("client_dataflow", ["client security surface", "dataflow", "sink"]),
    ]
    for module, needles in rules:
        if any(needle in text for needle in needles):
            return module
    return None
