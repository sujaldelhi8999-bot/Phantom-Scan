"""
SAST (GitHub Code Scan) Router
"""

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth_middleware import require_admin
from app.agents.orchestrator import OrchestratorAgent
from app.config import get_settings
from app.database import add_audit_log, get_findings, get_scan, update_scan_status
from app.models import GitHubConfig, MultiSourceScanRequest
from app.routers.multi_source import build_response
from app.services.jobs import ScanCapacityError, scan_job_manager

router = APIRouter(prefix="/api/sast", tags=["SAST"])
settings = get_settings()
logger = logging.getLogger("phantomscan.sast")


@router.post("/scan-repo", status_code=status.HTTP_202_ACCEPTED)
async def scan_repo(
    repo_url: str = Query(min_length=8, max_length=2048),
    branch: str = Query(default="main", max_length=100),
    admin: dict = Depends(require_admin),
) -> dict[str, Any]:
    """Clone a public GitHub repository and scan it for secrets, insecure
    patterns, vulnerable dependencies, and IaC misconfigurations."""
    repo_url = repo_url.strip()
    if not repo_url.startswith("https://github.com/"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only public GitHub repository URLs are supported (https://github.com/owner/repo).",
        )

    try:
        reservation = await scan_job_manager.reserve_slot()
    except ScanCapacityError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc

    scan_id: int | None = None
    try:
        request = MultiSourceScanRequest(
            name=f"GitHub code scan: {repo_url}",
            mode="multi_agent",
            intensity="medium",
            sources=[GitHubConfig(repo_url=repo_url, branch=branch, include_dependabot=False)],
            correlate_findings=True,
            data_flow_tracing=False,
            generate_sarif=False,
            generate_pdf=False,
        )
        orchestrator = OrchestratorAgent(limits=scan_job_manager.limits)
        scan_id = await _create_sast_scan(repo_url, branch, admin["id"])
        await add_audit_log(
            scan_id,
            "System",
            "sast_scan_created",
            f"Created GitHub code scan for {repo_url} (branch: {branch})",
            user_id=admin["id"],
            target=repo_url,
        )
        await _submit(request, scan_id, admin["id"])
    except Exception as exc:
        logger.exception("Failed to start SAST scan")
        if scan_id is not None:
            await update_scan_status(scan_id, "error", str(exc)[:1000])
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    finally:
        await asyncio.shield(scan_job_manager.release_slot(reservation))

    return {"scan_id": scan_id, "status": "queued", "repo_url": repo_url, "branch": branch}


async def _create_sast_scan(repo_url: str, branch: str, user_id: str) -> int:
    from app.database import create_scan
    return await create_scan(
        target_url=repo_url,
        mode="multi_agent",
        intensity="medium",
        selected_tests=json.dumps(["github"], separators=(",", ":")),
        user_id=user_id,
        authorization_id=None,
        authorization_confirmed=False,
    )


async def _submit(request: MultiSourceScanRequest, scan_id: int, user_id: str) -> None:
    loop = asyncio.get_running_loop()
    task = loop.create_task(
        OrchestratorAgent(limits=scan_job_manager.limits).run_multi_source(
            request,
            scan_id,
            user_id=user_id,
            user_role="admin",
            authorization_context={},
        ),
        name=f"phantomscan-sast-{scan_id}",
    )
    await scan_job_manager.register_task(scan_id, task)


@router.get("/{scan_id}")
async def sast_scan_status(
    scan_id: int,
    admin: dict = Depends(require_admin),
) -> dict[str, Any]:
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if scan["user_id"] != admin["id"] and admin.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    base = (await build_response(scan_id)).model_dump(mode="json")
    findings = await get_findings(scan_id)
    base["findings"] = findings
    base["repo_url"] = scan.get("target_url")
    return base
