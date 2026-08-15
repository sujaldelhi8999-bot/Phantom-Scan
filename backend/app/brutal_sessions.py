"""In-memory Brutal Mode engagement sessions.

A session tracks one target across the full kill chain: exploitation →
shell → post-exploitation → lateral movement → persistence → exfiltration.
Every event is appended to the session timeline AND persisted to the
``brutal_ops`` table for the audit trail.
"""

import time
import uuid
from dataclasses import dataclass, field

from app.database import create_brutal_op


@dataclass
class BrutalSession:
    """One engagement against one authorized target."""

    session_id: str
    target_url: str
    actor: str
    created_at: float
    status: str = "established"
    timeline: list[dict] = field(default_factory=list)
    loot: list[dict] = field(default_factory=list)
    op_ids: list[int] = field(default_factory=list)
    simulation: bool = False
    sim_intel: dict = field(default_factory=dict)
    sim_findings: list[dict] = field(default_factory=list)

    def add_event(self, action: str, status: str, detail: str, payload: str | None = None) -> None:
        self.timeline.append(
            {
                "ts": time.time(),
                "action": action,
                "status": status,
                "detail": detail,
            }
        )

    async def log_op(
        self,
        action: str,
        status: str,
        detail: str,
        *,
        payload: str | None = None,
        output: str | None = None,
        scan_id: int | None = None,
    ) -> int:
        op_id = await create_brutal_op(
            self.session_id,
            self.target_url,
            self.actor,
            action,
            scan_id=scan_id,
            status=status,
            detail=detail,
            payload=payload,
            output=output,
        )
        self.op_ids.append(op_id)
        self.add_event(action, status, detail)
        return op_id

    def add_loot(self, kind: str, name: str, content: str, source: str) -> None:
        self.loot.append(
            {
                "kind": kind,
                "name": name,
                "content": content[:200_000],
                "source": source,
                "ts": time.time(),
            }
        )

    def serialize(self, with_loot: bool = False) -> dict:
        return {
            "session_id": self.session_id,
            "target_url": self.target_url,
            "actor": self.actor,
            "created_at": self.created_at,
            "status": self.status,
            "simulation": self.simulation,
            "sim_findings": self.sim_findings,
            "timeline": self.timeline,
            "loot_count": len(self.loot),
            "loot": self.loot if with_loot else [{"kind": l["kind"], "name": l["name"], "source": l["source"]} for l in self.loot],
        }


class BrutalSessionManager:
    """Singleton registry of active Brutal Mode sessions."""

    _sessions: dict[str, BrutalSession] = {}

    @classmethod
    def create(cls, target_url: str, actor: str, *, simulation: bool = False) -> BrutalSession:
        session = BrutalSession(
            session_id=uuid.uuid4().hex[:16],
            target_url=target_url,
            actor=actor,
            created_at=time.time(),
            simulation=simulation,
        )
        cls._sessions[session.session_id] = session
        return session

    @classmethod
    def get(cls, session_id: str) -> BrutalSession | None:
        return cls._sessions.get(session_id)

    @classmethod
    def list(cls) -> list[BrutalSession]:
        return sorted(cls._sessions.values(), key=lambda s: s.created_at, reverse=True)

    @classmethod
    def require(cls, session_id: str) -> BrutalSession:
        session = cls.get(session_id)
        if session is None:
            raise KeyError(f"Brutal session {session_id} not found")
        return session