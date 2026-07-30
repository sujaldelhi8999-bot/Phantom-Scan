from fastapi import APIRouter, Depends, HTTPException, Query

from app.routers.admin_scope import admin_required
from app.services.intelligence_service import IntelligenceService

router = APIRouter(prefix="/api/admin/intelligence", tags=["Private Intelligence"])


@router.get("/")
async def get_intelligence(
    target: str = Query(min_length=4, max_length=2048),
    scan_id: int | None = Query(default=None, ge=1),
    _admin: dict = Depends(admin_required),
) -> dict:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    service = IntelligenceService(target_url=target, scan_id=scan_id)
    try:
        result = await service.get_complete_intelligence()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Intelligence aggregation failed: {exc}",
        ) from exc

    return result
