"""
Multi-Source Scanning Router
"""

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth_middleware import get_current_user
from app.agents.orchestrator import OrchestratorAgent
from app.config import get_settings
from app.database import (
    add_audit_log,
    get_findings,
    get_scan,
    list_multi_source_scans,
    list_scan_sources,
    list_source_correlations,
    update_scan_status,
)
from app.models import (
    CorrelatedFindingGroup,
    MultiSourceScanHistoryItem,
    MultiSourceScanRequest,
    MultiSourceScanResponse,
    SourceCorrelationSummary,
    SourceScanResult,
)
from app.services.authorization import TargetAuthorizationService, TargetValidationError
from app.services.jobs import ScanCapacityError, ScanNotRunningError, scan_job_manager
from app.services.policy import ScanPolicy, ScanPolicyError

router = APIRouter(prefix="/api/multi-source", tags=["multi-source"])
settings = get_settings()
authorization_service = TargetAuthorizationService()
scan_policy = ScanPolicy(authorization_service)
logger = logging.getLogger("phantomscan.multi_source")


async def _load_scan(scan_id: int, user_id: str) -> dict[str, Any]:
    scan = await get_scan(scan_id)
    if scan is None or scan["user_id"] != user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


async def _fetch_sources(scan_id: int) -> list[dict[str, Any]]:
    try:
        return await list_scan_sources(scan_id)
    except Exception:
        return []


async def _fetch_findings(scan_id: int) -> list[dict[str, Any]]:
    try:
        return await get_findings(scan_id)
    except Exception:
        return []


async def _fetch_correlations(scan_id: int) -> list[dict[str, Any]]:
    try:
        return await list_source_correlations(scan_id)
    except Exception:
        return []


async def build_response(scan_id: int) -> MultiSourceScanResponse:
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    sources = await _fetch_sources(scan_id)
    findings = await _fetch_findings(scan_id)
    correlations = await _fetch_correlations(scan_id)

    source_results: list[SourceScanResult] = []
    for source in sources:
        sev_counts: dict[str, int] = {}
        for finding in findings:
            if finding.get("_source_type", "") == source.get("source_type"):
                sev = str(finding.get("severity", "INFO")).upper()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
        source_results.append(
            SourceScanResult(
                source_type=source["source_type"],
                source_identifier=str(source.get("source_identifier") or ""),
                status=str(source.get("status") or "pending"),
                findings_count=int(source.get("findings_count") or 0),
                findings_by_severity=sev_counts,
                scan_duration_seconds=float(source.get("scan_duration_seconds") or 0),
                error_message=source.get("error_message"),
                artifacts=source.get("artifacts") or {},
            )
        )

    severity_totals: dict[str, int] = {}
    for finding in findings:
        sev = str(finding.get("severity", "INFO")).upper()
        severity_totals[sev] = severity_totals.get(sev, 0) + 1

    return MultiSourceScanResponse(
        scan_id=scan_id,
        name=str(scan.get("target_url") or f"Multi-source scan #{scan_id}"),
        mode=str(scan.get("mode") or "multi_agent"),
        overall_status=str(scan.get("status") or "queued"),
        overall_progress=int(scan.get("progress") or 0),
        sources=source_results,
        total_findings=len(findings),
        findings_by_severity=severity_totals,
        correlated_findings_count=len(correlations),
        created_at=str(scan.get("created_at") or ""),
        started_at=scan.get("started_at"),
        completed_at=scan.get("completed_at"),
        total_duration_seconds=0.0,
        sarif_export_url=None,
        pdf_report_url=None,
    )


@router.post("/scan", response_model=MultiSourceScanResponse, status_code=status.HTTP_201_CREATED)
async def start_multi_source_scan(
    request: MultiSourceScanRequest,
    user: dict = Depends(get_current_user),
) -> MultiSourceScanResponse:
    """Start a coordinated multi-source security scan."""
    logger.info("Multi-source scan request: name=%s sources=%s user=%s", request.name, [s.type for s in request.sources], user["id"])
    try:
        reservation = await scan_job_manager.reserve_slot()
    except ScanCapacityError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc

    scan_id: int | None = None
    try:
        orchestrator = OrchestratorAgent(limits=scan_job_manager.limits)
        scan_id = await _create_multi_source_scan(request, user["id"])
        await add_audit_log(
            scan_id,
            "System",
            "multi_source_scan_created",
            f"Created multi-source scan '{request.name or scan_id}' with sources: {', '.join(s.type for s in request.sources)}",
            user_id=user["id"],
            target="multi-source://scan",
        )
        await _submit(request, scan_id, user["id"], user["role"])
    except ScanCapacityError as exc:
        if scan_id is not None:
            await update_scan_status(scan_id, "error", str(exc))
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to start multi-source scan")
        if scan_id is not None:
            await update_scan_status(scan_id, "error", str(exc)[:1000])
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    finally:
        await asyncio.shield(scan_job_manager.release_slot(reservation))

    return await build_response(scan_id)


async def _create_multi_source_scan(request: MultiSourceScanRequest, user_id: str) -> int:
    from app.database import create_scan
    target_url = "multi-source://scan"
    for source in request.sources:
        if source.type == "live":
            target_url = str(source.target_url)
            break
        if source.type == "github":
            target_url = str(source.repo_url)
            break
        if source.type == "local":
            target_url = f"local://{source.path}"
            break
    return await create_scan(
        target_url=target_url,
        mode="multi_agent",
        intensity=request.intensity,
        selected_tests=json.dumps([s.type for s in request.sources], separators=(",", ":")),
        user_id=user_id,
        authorization_id=None,
        authorization_confirmed=False,
    )


async def _submit(request: MultiSourceScanRequest, scan_id: int, user_id: str, user_role: str) -> None:
    """Submit multi-source scan to the job manager."""
    loop = asyncio.get_running_loop()
    task = loop.create_task(
        OrchestratorAgent(limits=scan_job_manager.limits).run_multi_source(
            request,
            scan_id,
            user_id=user_id,
            user_role=user_role,
            authorization_context={},
        ),
        name=f"phantomscan-multi-{scan_id}",
    )
    scan_job_manager._tasks[scan_id] = task


@router.get("/history", response_model=list[MultiSourceScanHistoryItem])
async def multi_source_history(user: dict = Depends(get_current_user)) -> list[MultiSourceScanHistoryItem]:
    rows = await list_multi_source_scans(user["id"])
    items: list[MultiSourceScanHistoryItem] = []
    for row in rows:
        sources = await _fetch_sources(int(row["id"]))
        findings = await _fetch_findings(int(row["id"]))
        correlations = await _fetch_correlations(int(row["id"]))
        items.append(
            MultiSourceScanHistoryItem(
                scan_id=int(row["id"]),
                name=str(row.get("target_url") or f"Multi-source scan #{row['id']}"),
                mode=str(row.get("mode") or "multi_agent"),
                overall_status=str(row.get("status") or "queued"),
                sources=[str(s.get("source_type")) for s in sources],
                total_findings=len(findings),
                correlated_findings=len(correlations),
                created_at=str(row.get("created_at") or ""),
                completed_at=row.get("completed_at"),
            )
        )
    return items


@router.get("/{scan_id}", response_model=MultiSourceScanResponse)
async def multi_source_status(
    scan_id: int,
    user: dict = Depends(get_current_user),
) -> MultiSourceScanResponse:
    await _load_scan(scan_id, user["id"])
    return await build_response(scan_id)


@router.get("/{scan_id}/correlations", response_model=dict[str, Any])
async def multi_source_correlations(
    scan_id: int,
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Return cross-source correlations with linked findings."""
    await _load_scan(scan_id, user["id"])
    correlations = await _fetch_correlations(scan_id)
    findings = await _fetch_findings(scan_id)
    findings_by_id = {int(f["id"]): f for f in findings}

    groups: list[dict[str, Any]] = []
    for corr in correlations:
        finding_ids = [int(fid) for fid in corr.get("finding_ids", [])]
        related = [findings_by_id[fid] for fid in finding_ids if fid in findings_by_id]
        if not related:
            continue
        primary = related[0]
        group: dict[str, Any] = {
            "unified_id": str(corr.get("unified_id") or ""),
            "title": str(primary.get("title") or "Correlated findings"),
            "severity": str(primary.get("severity") or "INFO").upper(),
            "confidence": float(corr.get("confidence") or 0),
            "sources": corr.get("source_types", []),
            "correlation_type": str(corr.get("correlation_type") or "exact_match"),
            "related_findings": related,
            "evidence": corr.get("evidence") or {},
        }
        groups.append(group)

    summary = SourceCorrelationSummary(
        total_correlations=len(correlations),
        by_type={},
        by_source_pair={},
        high_confidence=sum(1 for c in correlations if float(c.get("confidence") or 0) > 0.8),
        data_flow_traces=sum(1 for c in correlations if c.get("correlation_type") == "data_flow"),
        vulnerability_chains=sum(1 for c in correlations if c.get("correlation_type") == "vulnerability_chain"),
    )
    for corr in correlations:
        ctype = str(corr.get("correlation_type") or "exact_match")
        summary.by_type[ctype] = summary.by_type.get(ctype, 0) + 1
        source_types = corr.get("source_types", [])
        if len(source_types) >= 2:
            pair = "+".join(sorted(source_types[:2]))
            summary.by_source_pair[pair] = summary.by_source_pair.get(pair, 0) + 1

    return {
        "scan_id": scan_id,
        "summary": summary.model_dump(),
        "groups": groups,
    }


@router.post("/{scan_id}/stop", response_model=dict[str, str])
async def stop_multi_source_scan(
    scan_id: int,
    user: dict = Depends(get_current_user),
) -> dict[str, str]:
    await _load_scan(scan_id, user["id"])
    try:
        scan_status = await scan_job_manager.stop(scan_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found") from exc
    except ScanNotRunningError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return {"scan_id": str(scan_id), "status": scan_status}