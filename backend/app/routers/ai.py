from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.database import (
    add_audit_log,
    get_audit_logs,
    get_finding,
    get_findings,
    get_previous_scan_for_target,
    get_scan,
    get_scan_artifacts,
    set_scan_artifacts,
)
from app.services.ai_analyst import AskPhantomScanResponder, create_ai_security_analyst

router = APIRouter(prefix="/api/ai", tags=["ai"])


class AskPhantomScanRequest(BaseModel):
    question: str = Field(min_length=1, max_length=1000)


async def build_scan_analysis(scan_id: int, *, refresh: bool = False) -> dict[str, Any]:
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    artifacts = await get_scan_artifacts(scan_id)
    if artifacts and artifacts.get("ai_analyst_output") and not refresh:
        return {"scan_id": scan_id, **artifacts["ai_analyst_output"]}

    findings = await get_findings(scan_id)
    previous_scan = await get_previous_scan_for_target(str(scan["target_url"]), scan_id)
    previous_findings = await get_findings(int(previous_scan["id"])) if previous_scan else []
    previous_artifacts = await get_scan_artifacts(int(previous_scan["id"])) if previous_scan else None
    logs = await get_audit_logs(scan_id)
    analysis = await create_ai_security_analyst().analyze(
        scan=scan,
        findings=findings,
        artifacts=artifacts or {},
        previous_scan=previous_scan,
        previous_findings=previous_findings,
        previous_artifacts=previous_artifacts,
        logs=logs,
    )
    await set_scan_artifacts(scan_id, ai_analyst_output=analysis)
    await add_audit_log(
        scan_id,
        "AI Security Analyst Agent",
        "analysis_generated",
        f"Generated AI analyst output with {len(analysis.get('priorities', []))} active priorities",
    )
    return {"scan_id": scan_id, **analysis}


@router.get("/scan/{scan_id}/analysis")
async def scan_analysis(scan_id: int, refresh: bool = Query(default=False)) -> dict[str, Any]:
    return await build_scan_analysis(scan_id, refresh=refresh)


@router.post("/scan/{scan_id}/ask")
async def ask_phantomscan(scan_id: int, payload: AskPhantomScanRequest) -> dict[str, Any]:
    analysis = await build_scan_analysis(scan_id, refresh=False)
    artifacts = await get_scan_artifacts(scan_id)
    findings = await get_findings(scan_id)
    answer = AskPhantomScanResponder().answer(payload.question, analysis, findings, artifacts)
    await add_audit_log(
        scan_id,
        "AI Security Analyst Agent",
        "question_answered",
        f"Answered Ask PhantomScan question: {payload.question[:200]}",
    )
    return {"scan_id": scan_id, "question": payload.question, **answer, "can_start_active_test": False}


@router.get("/findings/{finding_id}/explain")
async def explain_finding(
    finding_id: int,
    language: Literal["en", "hi"] = Query(default="en"),
) -> dict[str, Any]:
    finding = await get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    explanation = await create_ai_security_analyst().explain_finding_cached(finding, language=language)
    return {"finding_id": finding_id, "language": language, **explanation, "can_start_active_test": False}
