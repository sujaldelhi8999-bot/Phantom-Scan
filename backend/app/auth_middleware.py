from datetime import datetime, timezone
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Header, status

from app.config import get_settings
from app.database import get_user_by_id

settings = get_settings()


async def get_current_user(authorization: Annotated[str, Header()]) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.replace("Bearer ", "")
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing subject",
            )
        exp = payload.get("exp")
        if exp and datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
            )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
        ) from exc

    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    if user.get("subscription_status") == "canceled":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Subscription canceled",
        )
    return user


def require_tier(required_tier: str):
    tier_order = {"FREE": 0, "PRO": 1}

    async def dependency(user: dict = Depends(get_current_user)) -> dict:
        user_tier = user.get("subscription_tier", "FREE")
        if tier_order.get(user_tier, 0) < tier_order.get(required_tier, 0):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {required_tier} tier or higher",
            )
        return user

    return Depends(dependency)


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return user