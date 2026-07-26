from datetime import datetime, timezone
from typing import Any
from app.services.redaction import redaction_service


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def mask_value(value: str) -> str:
    return redaction_service.mask_value(value)


def redact_sensitive(text: str, limit: int = 12000) -> str:
    return redaction_service.redact_text(text, limit)


def redact_url(url: str) -> str:
    return redaction_service.redact_url(url)


def redact_payload(value: Any) -> Any:
    return redaction_service.redact_payload(value)


def build_finding(
    *,
    title: str,
    category: str,
    severity: str,
    confidence: str,
    target: str,
    endpoint: str,
    evidence: str,
    impact: str,
    recommendation: str,
    verification: str,
    agent: str,
    cve_id: str | None = None,
    cvss_score: float | None = None,
    parameter: str | None = None,
    module: str | None = None,
    recommended_fix: str | None = None,
    remediation_status: str = "OPEN",
    verification_status: str = "NOT_VERIFIED",
    risk_status: str = "ACTIVE",
) -> dict[str, Any]:
    return {
        "title": title,
        "category": category,
        "severity": severity.upper(),
        "confidence": confidence.upper(),
        "target": target,
        "endpoint": endpoint,
        "evidence": redact_sensitive(evidence),
        "impact": impact,
        "recommendation": recommendation,
        "verification": verification,
        "agent": agent,
        "timestamp": utc_timestamp(),
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "parameter": parameter,
        "module": module,
        "recommended_fix": recommended_fix,
        "remediation_status": remediation_status,
        "verification_status": verification_status,
        "risk_status": risk_status,
    }
