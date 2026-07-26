from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from app.config import get_settings
from app.services.active_gate import ActiveTargetGate
from app.services.active_security import AttackSurfaceMapper, SecurityTestPlanner, normalize_modules
from app.services.authorization import TargetAuthorizationService, TargetValidationError
from app.services.execution import SafetyLimits

router = APIRouter(prefix="/api/active", tags=["active-security"])
settings = get_settings()
authorization_service = TargetAuthorizationService()
active_gate = ActiveTargetGate(authorization_service)


class ActiveMapRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: str = Field(min_length=4, max_length=2048)
    selected_modules: list[str] = Field(default_factory=list, max_length=25)
    authorization_id: int | None = Field(default=None, ge=1)
    authorization_confirmed: bool = False


@router.post("/map")
async def active_map(map_request: ActiveMapRequest, request: Request) -> dict[str, Any]:
    decision = await admit_or_raise(map_request)
    transport = httpx.ASGITransport(app=request.app) if decision.is_lab else None
    attack_surface = await AttackSurfaceMapper(transport=transport).map(decision.target_url)
    plan = SecurityTestPlanner().create_plan(attack_surface, map_request.selected_modules)
    return {
        "gate": decision.to_context(),
        "surfaces": attack_surface.get("surfaces", []),
        "plan": plan,
        "score": passive_plan_score(plan),
        "limits": active_limits(),
    }


@router.post("/score")
async def active_score(score_request: ActiveMapRequest, request: Request) -> dict[str, Any]:
    decision = await admit_or_raise(score_request)
    transport = httpx.ASGITransport(app=request.app) if decision.is_lab else None
    attack_surface = await AttackSurfaceMapper(transport=transport).map(decision.target_url)
    plan = SecurityTestPlanner().create_plan(attack_surface, score_request.selected_modules)
    return {"gate": decision.to_context(), "score": passive_plan_score(plan), "module_count": len(plan.get("modules", [])), "limits": active_limits()}


async def admit_or_raise(request: ActiveMapRequest):
    try:
        decision = await active_gate.admit(request.target_url, settings.local_user_id, request.authorization_id)
    except TargetValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"code": "TARGET_NOT_VERIFIED", "message": decision.reason})
    if decision.authorization_status == "VERIFIED" and not request.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "AUTHORIZATION_CONFIRMATION_REQUIRED", "message": "Confirmed authorization is required before active mapping."},
        )
    return decision


def passive_plan_score(plan: dict[str, Any]) -> dict[str, Any]:
    selected = set(normalize_modules(plan.get("selected_modules") or []))
    vulnerable_surfaces = 0
    total_surfaces = 0
    for module in plan.get("modules", []):
        if selected and module.get("module") not in selected:
            continue
        for surface in module.get("surfaces") or []:
            total_surfaces += 1
            if surface.get("vulnerable") is True:
                vulnerable_surfaces += 1
    penalty = min(80, vulnerable_surfaces * 5)
    return {"score": max(0, 100 - penalty), "surface_count": total_surfaces, "vulnerable_surface_count": vulnerable_surfaces}


def active_limits() -> dict[str, Any]:
    limits = SafetyLimits.from_settings()
    return {
        "max_requests": limits.max_total_requests,
        "requests_per_second": limits.max_requests_per_second,
        "timeout_seconds": limits.max_scan_duration,
        "max_response_size": limits.max_response_size,
        "max_redirects": limits.max_redirect_depth,
        "max_concurrency": limits.max_concurrent_scans,
    }
