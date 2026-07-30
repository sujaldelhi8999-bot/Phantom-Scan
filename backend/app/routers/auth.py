import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.config import get_settings

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    role: str
    username: str


@router.post("/login", response_model=LoginResponse)
async def login(req: LoginRequest):
    settings = get_settings()
    if req.username == settings.admin_username and req.password == settings.admin_password:
        payload = {
            "sub": req.username,
            "role": "admin",
            "exp": datetime.now(timezone.utc) + timedelta(hours=24),
        }
        token = jwt.encode(payload, settings.secret_key, algorithm="HS256")
        return LoginResponse(token=token, role="admin", username=req.username)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
    )
