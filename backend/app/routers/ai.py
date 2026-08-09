from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.auth_middleware import get_current_user
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
from app.agents.ai_tutor import create_ai_tutor_agent
from app.models import AITutorRequest, AITutorResponse
from app.services.ai_analyst import AskPhantomScanResponder, create_ai_security_analyst

router = APIRouter(prefix="/api/ai", tags=["ai"])


class AskPhantomScanRequest(BaseModel):
    question: str = Field(min_length=1, max_length=1000)


async def _verify_scan_ownership(scan_id: int, user_id: str) -> dict[str, Any]:
    scan = await get_scan(scan_id)
    if not scan or scan["user_id"] != user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


async def build_scan_analysis(scan_id: int, user_id: str, *, refresh: bool = False) -> dict[str, Any]:
    scan = await _verify_scan_ownership(scan_id, user_id)
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
        user_id=user_id,
    )
    return {"scan_id": scan_id, **analysis}


@router.get("/scan/{scan_id}/analysis")
async def scan_analysis(
    scan_id: int,
    refresh: bool = Query(default=False),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    return await build_scan_analysis(scan_id, user["id"], refresh=refresh)


@router.post("/scan/{scan_id}/ask")
async def ask_phantomscan(
    scan_id: int,
    payload: AskPhantomScanRequest,
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    analysis = await build_scan_analysis(scan_id, user["id"], refresh=False)
    artifacts = await get_scan_artifacts(scan_id)
    findings = await get_findings(scan_id)
    answer = AskPhantomScanResponder().answer(payload.question, analysis, findings, artifacts)
    await add_audit_log(
        scan_id,
        "AI Security Analyst Agent",
        "question_answered",
        f"Answered Ask PhantomScan question: {payload.question[:200]}",
        user_id=user["id"],
    )
    return {"scan_id": scan_id, "question": payload.question, **answer, "can_start_active_test": False}


@router.get("/findings/{finding_id}/explain")
async def explain_finding(
    finding_id: int,
    language: Literal["en", "hi"] = Query(default="en"),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    finding = await get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    # Verify ownership via scan
    scan = await get_scan(int(finding["scan_id"]))
    if not scan or scan["user_id"] != user["id"]:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    explanation = await create_ai_security_analyst().explain_finding_cached(finding, language=language)
    return {"finding_id": finding_id, "language": language, **explanation, "can_start_active_test": False}


@router.post("/tutor/chat", response_model=AITutorResponse)
async def tutor_chat(
    request: AITutorRequest,
    user: dict = Depends(get_current_user),
) -> AITutorResponse:
    """Chat with the AI tutor about a finding (or general security question)."""
    finding_context: dict[str, Any] = dict(request.context or {})
    scan_id: int | None = None

    if request.finding_id is not None:
        finding = await get_finding(request.finding_id)
        if finding is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
        scan = await get_scan(int(finding["scan_id"]))
        if not scan or scan["user_id"] != user["id"]:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
        scan_id = finding.get("scan_id")
        finding_context.setdefault("title", finding.get("title", ""))
        finding_context.setdefault("category", finding.get("category", ""))
        finding_context.setdefault("severity", finding.get("severity", ""))
        finding_context.setdefault("evidence", finding.get("evidence", ""))
        finding_context.setdefault("recommendation", finding.get("recommendation", "") or finding.get("fix", ""))
        finding_context.setdefault("file_path", finding.get("file_path", ""))
        finding_context.setdefault("code_snippet", finding.get("code_snippet", ""))

    result = await create_ai_tutor_agent().run(
        finding_id=request.finding_id or 0,
        question=request.question,
        context=finding_context,
        scan_id=scan_id,
        user_level=request.user_level,
    )

    if scan_id is not None:
        await add_audit_log(
            scan_id,
            "AI Tutor Agent",
            "tutor_chat",
            f"Answered tutor question: {request.question[:200]}",
            user_id=user["id"],
        )

    return AITutorResponse(
        answer=result.get("answer", ""),
        explanation=result.get("explanation"),
        code_examples=result.get("code_examples", []),
        references=result.get("references", []),
        follow_up_questions=result.get("follow_up_questions", []),
        confidence=result.get("confidence", 0.0),
    )