import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, status

logger = logging.getLogger("phantomscan.scan")

from app.config import get_settings
from app.database import (
    add_audit_log,
    create_scan,
    get_findings,
    get_scan,
    get_scan_artifacts,
    list_scans,
    update_scan_status,
)
from app.models import (
    ScanArtifactsResponse,
    ScanHistoryItem,
    ScanRequest,
    ScanResponse,
    StopScanResponse,
)
from app.services.authorization import TargetAuthorizationService, TargetValidationError
from app.services.jobs import ScanCapacityError, ScanNotRunningError, scan_job_manager
from app.services.policy import ScanPolicy, ScanPolicyError

router = APIRouter(prefix="/api/scan", tags=["scan"])
settings = get_settings()
authorization_service = TargetAuthorizationService()
scan_policy = ScanPolicy(authorization_service)


def _selected_tests(value: Any) -> list[str]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _scan_response(row: dict[str, Any], findings: list[dict[str, Any]]) -> ScanResponse:
    return ScanResponse(
        scan_id=int(row["id"]),
        target_url=str(row["target_url"]),
        mode=row["mode"],
        intensity=row["intensity"],
        selected_tests=_selected_tests(row.get("selected_tests")),
        user_id=str(row["user_id"]),
        authorization_id=row.get("authorization_id"),
        authorization_confirmed=bool(row.get("authorization_confirmed")),
        status=row["status"],
        progress=int(row["progress"]),
        request_count=int(row["request_count"]),
        sandbox_id=row.get("sandbox_id"),
        error_message=row.get("error_message"),
        created_at=row["created_at"],
        started_at=row.get("started_at"),
        completed_at=row.get("completed_at"),
        findings=findings,
    )


@router.post("/start", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def start_scan(scan_request: ScanRequest) -> ScanResponse:
    print("[SCAN] REQUEST RECEIVED")
    logger.info("Scan request received for target=%s mode=%s", scan_request.target_url, scan_request.mode)
    try:
        admission = await scan_policy.admit(scan_request, settings.local_user_id)
    except ScanPolicyError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc
    except TargetValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    try:
        reservation = await scan_job_manager.reserve_slot()
    except ScanCapacityError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc

    canonical_request = scan_request.model_copy(update={"target_url": admission.target_url})
    authorization_id = admission.verified_target.id if admission.verified_target is not None else None
    scan_id: int | None = None
    try:
        scan_id = await create_scan(
            target_url=admission.target_url,
            mode=canonical_request.mode,
            intensity=canonical_request.intensity,
            selected_tests=json.dumps(canonical_request.selected_tests, separators=(",", ":")),
            user_id=settings.local_user_id,
            authorization_id=authorization_id,
            authorization_confirmed=canonical_request.authorization_confirmed,
        )
        await add_audit_log(
            scan_id,
            "System",
            "scan_created",
            (
                f"Created {canonical_request.mode} scan for {admission.target_url} with "
                f"{canonical_request.intensity} intensity and modules: "
                f"{', '.join(canonical_request.selected_tests) or 'none'}"
            ),
            user_id=settings.local_user_id,
            target=admission.target_url,
            authorization_status=str(admission.authorization_context.get("authorization_status") or "NOT_REQUIRED"),
        )
        await scan_job_manager.submit(
            reservation,
            scan_id,
            canonical_request,
            admission.verified_target,
            settings.local_user_id,
            admission.authorization_context,
            user_role=settings.local_user_role,
        )
    except ScanCapacityError as exc:
        if scan_id is not None:
            await update_scan_status(scan_id, "error", str(exc))
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc
    except Exception as exc:
        if scan_id is not None:
            await update_scan_status(scan_id, "error", str(exc)[:1000])
        raise
    finally:
        await asyncio.shield(scan_job_manager.release_slot(reservation))

    row = await get_scan(scan_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Created scan could not be loaded")
    return _scan_response(row, await get_findings(scan_id))


@router.get("/history", response_model=list[ScanHistoryItem])
async def scan_history() -> list[ScanHistoryItem]:
    rows = await list_scans()
    return [ScanHistoryItem(**row) for row in rows]


@router.post("/{scan_id}/stop", response_model=StopScanResponse)
async def stop_scan(scan_id: int) -> StopScanResponse:
    try:
        scan_status = await scan_job_manager.stop(scan_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found") from exc
    except ScanNotRunningError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return StopScanResponse(scan_id=scan_id, status=scan_status)


@router.get("/{scan_id}/artifacts", response_model=ScanArtifactsResponse)
async def scan_artifacts(scan_id: int) -> ScanArtifactsResponse:
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    artifacts = await get_scan_artifacts(scan_id)
    return ScanArtifactsResponse(**{"scan_id": scan_id, **(artifacts or {})})


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_status(scan_id: int) -> ScanResponse:
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return _scan_response(scan, await get_findings(scan_id))
