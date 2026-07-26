import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.config import get_settings
from app.services.authorization import TargetAuthorizationService, VerifiedTarget, canonicalize_target


@dataclass(frozen=True)
class ActiveTargetDecision:
    allowed: bool
    target_url: str
    target_origin: str
    authorization_status: str
    reason: str
    authorization_id: int | None = None
    verified_target: VerifiedTarget | None = None
    is_lab: bool = False

    def to_context(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "target_url": self.target_url,
            "target_origin": self.target_origin,
            "authorization_status": self.authorization_status,
            "reason": self.reason,
            "authorization_id": self.authorization_id,
            "is_lab": self.is_lab,
        }


class ActiveTargetGate:
    def __init__(self, authorization_service: TargetAuthorizationService | None = None) -> None:
        self.authorization_service = authorization_service or TargetAuthorizationService()

    async def admit(
        self,
        target_url: str,
        user_id: str,
        authorization_id: int | None = None,
    ) -> ActiveTargetDecision:
        target = canonicalize_target(target_url)
        parsed = urlsplit(target.url)
        if self.is_builtin_lab_target(target.url):
            return ActiveTargetDecision(
                allowed=True,
                target_url=target.url,
                target_origin=target.origin,
                authorization_status="TRAINING",
                reason="Built-in PhantomBank lab target",
                is_lab=True,
            )
        if self.is_loopback_host(parsed.hostname or ""):
            return ActiveTargetDecision(
                allowed=True,
                target_url=target.url,
                target_origin=target.origin,
                authorization_status="ALLOWLIST",
                reason="Local development target",
            )
        if target.origin in self.allowlisted_origins():
            return ActiveTargetDecision(
                allowed=True,
                target_url=target.url,
                target_origin=target.origin,
                authorization_status="ALLOWLIST",
                reason="Origin is in ACTIVE_TARGET_ALLOWLIST",
            )
        try:
            verified = await self.authorization_service.require_verified(target.url, user_id, authorization_id)
        except PermissionError:
            return ActiveTargetDecision(
                allowed=False,
                target_url=target.url,
                target_origin=target.origin,
                authorization_status="BLOCKED",
                reason=self.authorization_service.blocked_message(),
            )
        return ActiveTargetDecision(
            allowed=True,
            target_url=target.url,
            target_origin=target.origin,
            authorization_status="VERIFIED",
            reason="Target ownership verification is current",
            authorization_id=verified.id,
            verified_target=verified,
        )

    def allowlisted_origins(self) -> set[str]:
        origins: set[str] = set()
        for item in get_settings().active_target_allowlist.split(","):
            candidate = item.strip()
            if not candidate:
                continue
            try:
                origins.add(canonicalize_target(candidate).origin)
            except ValueError:
                continue
        return origins

    @classmethod
    def is_builtin_lab_target(cls, target_url: str) -> bool:
        parsed = urlsplit(target_url)
        return parsed.path.startswith("/lab/phantombank") and cls.is_loopback_host(parsed.hostname or "")

    @staticmethod
    def is_loopback_host(hostname: str) -> bool:
        hostname = hostname.strip("[]").lower().rstrip(".")
        if hostname in {"localhost", "localhost.localdomain"}:
            return True
        try:
            return ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            return False
