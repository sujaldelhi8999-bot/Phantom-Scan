"""
CI/CD Integration Router - SARIF export, GitHub Actions workflows, PR comments, compliance reports.
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from app.auth_middleware import get_current_user
from app.database import (
    add_audit_log,
    get_findings,
    get_scan,
    get_scan_artifacts,
)
from app.models import (
    ComplianceReportRequest,
    ComplianceReportResponse,
    GitHubActionsWorkflowRequest,
    GitHubActionsWorkflowResponse,
)
from app.services.ci_cd import (
    build_github_actions_workflow,
    build_pr_comment,
    build_sarif,
    generate_compliance_report,
    get_pr_comments,
    save_pr_comment,
)

router = APIRouter(prefix="/api/ci", tags=["ci-cd"])
logger = logging.getLogger("phantomscan.ci")


async def _verify_scan_ownership(scan_id: int, user_id: str) -> dict[str, Any]:
    scan = await get_scan(scan_id)
    if not scan or scan["user_id"] != user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.get("/scan/{scan_id}/sarif")
async def export_sarif(
    scan_id: int,
    download: bool = Query(default=False),
    user: dict = Depends(get_current_user),
) -> Response:
    """Export scan findings as SARIF 2.1.0 for GitHub Code Scanning."""
    await _verify_scan_ownership(scan_id, user["id"])
    try:
        sarif = await build_sarif(scan_id)
    except Exception as exc:
        logger.exception("SARIF export failed for scan %s", scan_id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    await add_audit_log(
        scan_id,
        "CI/CD",
        "sarif_exported",
        f"Exported SARIF with {len(sarif.get('runs', [{}])[0].get('results', []))} results",
        user_id=user["id"],
    )
    return JSONResponse(
        content=sarif,
        media_type="application/sarif+json",
        headers={"Content-Disposition": f'attachment; filename="phantomscan-{scan_id}.sarif"'} if download else {},
    )


@router.post("/workflow", response_model=GitHubActionsWorkflowResponse)
async def generate_workflow(
    request: GitHubActionsWorkflowRequest,
    user: dict = Depends(get_current_user),
) -> GitHubActionsWorkflowResponse:
    """Generate a GitHub Actions workflow template."""
    try:
        return build_github_actions_workflow(request)
    except Exception as exc:
        logger.exception("Workflow generation failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc


@router.get("/workflow/template")
async def workflow_template(user: dict = Depends(get_current_user)) -> PlainTextResponse:
    """Return a ready-to-use PhantomScan GitHub Actions workflow."""
    from app.models import GitHubConfig, LocalCodebaseConfig, MultiSourceScanRequest
    request = GitHubActionsWorkflowRequest(
        repo_url="https://github.com/example/example",
        scan_config=MultiSourceScanRequest(
            name="PR security scan",
            sources=[
                LocalCodebaseConfig(path="${{ github.workspace }}"),
                GitHubConfig(repo_url="https://github.com/example/example", branch="main"),
            ],
        ),
        trigger="pull_request",
        upload_sarif=True,
        comment_on_pr=True,
    )
    response = build_github_actions_workflow(request)
    return PlainTextResponse(response.workflow_yaml, media_type="text/yaml")


@router.post("/reports/compliance", response_model=ComplianceReportResponse, status_code=status.HTTP_201_CREATED)
async def create_compliance_report(
    request: ComplianceReportRequest,
    user: dict = Depends(get_current_user),
) -> ComplianceReportResponse:
    """Generate a compliance report for a scan."""
    await _verify_scan_ownership(request.scan_id, user["id"])
    try:
        report = await generate_compliance_report(request)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Compliance report generation failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    await add_audit_log(
        request.scan_id,
        "CI/CD",
        "compliance_report_generated",
        f"Generated compliance report {report.report_id} for {len(request.frameworks)} frameworks",
        user_id=user["id"],
    )
    return report


@router.get("/reports/{report_id}/download")
async def download_compliance_report(
    report_id: str,
    user: dict = Depends(get_current_user),
) -> Response:
    """Download a generated compliance report."""
    from app.database import get_connection
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT format, content, summary, file_path FROM compliance_reports WHERE report_id = ?",
            (report_id,),
        )
        row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    fmt = str(row["format"] or "markdown")
    content = str(row["content"] or "")
    if not content:
        summary = row["summary"] or "{}"
        content = f"# Compliance Report {report_id}\n\n{summary}"
    if fmt == "json":
        try:
            import json as _json
            content = _json.dumps({"report_id": report_id, "summary": _json.loads(row["summary"]), "content": content}, indent=2)
        except Exception:
            pass
        return Response(content=content, media_type="application/json")
    return Response(content=content, media_type="text/markdown")


@router.get("/scan/{scan_id}/pr-comment")
async def pr_comment_preview(
    scan_id: int,
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Preview the PR comment that would be posted for a scan."""
    await _verify_scan_ownership(scan_id, user["id"])
    comment = await build_pr_comment(scan_id)
    return {"scan_id": scan_id, "comment": comment}


@router.post("/scan/{scan_id}/pr-comment")
async def save_pr_comment_endpoint(
    scan_id: int,
    payload: dict[str, Any],
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Persist a PR comment record (posted by the bot)."""
    await _verify_scan_ownership(scan_id, user["id"])
    pr_number = int(payload.get("pr_number") or 0)
    repo_full_name = str(payload.get("repo_full_name") or "")
    comment = str(payload.get("comment") or "")
    if not pr_number or not repo_full_name or not comment:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="pr_number, repo_full_name and comment are required")
    comment_id = await save_pr_comment(scan_id, pr_number, repo_full_name, comment)
    return {"comment_id": comment_id, "status": "pending"}


@router.get("/scan/{scan_id}/pr-comments")
async def pr_comments_endpoint(
    scan_id: int,
    user: dict = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """List PR comments for a scan."""
    await _verify_scan_ownership(scan_id, user["id"])
    return await get_pr_comments(scan_id)