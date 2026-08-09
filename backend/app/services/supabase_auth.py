"""
Supabase Auth token verification.

Primary path: decode the Supabase access token (HS256) locally with the
project JWT secret. Fallback: call the Supabase /auth/v1/user endpoint with
the Bearer token when the JWT secret is not configured or decoding fails.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx
import jwt

from app.config import get_settings

logger = logging.getLogger("phantomscan.supabase_auth")


@dataclass
class SupabaseUser:
    user_id: str
    email: str
    name: str


class SupabaseAuthError(Exception):
    pass


def _decode_jwt(access_token: str, jwt_secret: str) -> dict:
    """Decode a Supabase HS256 access token."""
    return jwt.decode(
        access_token,
        jwt_secret,
        algorithms=["HS256"],
        audience="authenticated",
    )


async def _verify_via_api(access_token: str, supabase_url: str) -> dict:
    """Validate the token against Supabase's /auth/v1/user endpoint."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{supabase_url.rstrip('/')}/auth/v1/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "apikey": access_token,
            },
        )
        if response.status_code != 200:
            raise SupabaseAuthError(f"Supabase rejected the token (HTTP {response.status_code})")
        return response.json()


async def verify_supabase_token(access_token: str) -> SupabaseUser:
    """Verify a Supabase access token and return the authenticated user.

    Raises SupabaseAuthError when the token is invalid, expired, or missing.
    """
    if not access_token:
        raise SupabaseAuthError("Missing access token")

    settings = get_settings()
    claims: dict = {}

    if settings.supabase_jwt_secret:
        try:
            claims = _decode_jwt(access_token, settings.supabase_jwt_secret)
        except jwt.InvalidTokenError as exc:
            logger.warning("Supabase JWT decode failed, falling back to API: %s", exc)
            if settings.supabase_url:
                claims = await _verify_via_api(access_token, settings.supabase_url)
            else:
                raise SupabaseAuthError("Invalid Supabase token") from exc
    elif settings.supabase_url:
        claims = await _verify_via_api(access_token, settings.supabase_url)
    else:
        raise SupabaseAuthError("Supabase is not configured (SUPABASE_URL / SUPABASE_JWT_SECRET)")

    if not claims:
        raise SupabaseAuthError("Supabase returned no user claims")

    user_id = str(claims.get("sub") or claims.get("id") or "")
    email = str(claims.get("email") or "").lower()
    if not user_id or not email:
        raise SupabaseAuthError("Supabase token is missing user identity")

    # Parse optional expires claim
    exp = claims.get("exp")
    if isinstance(exp, (int, float)) and datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
        raise SupabaseAuthError("Supabase token has expired")

    return SupabaseUser(
        user_id=user_id,
        email=email,
        name=str(claims.get("user_metadata", {}).get("name") or claims.get("name") or email),
    )
