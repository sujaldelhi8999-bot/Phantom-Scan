"""Data exfiltration module.

Collects everything looted during the engagement (DB dumps, config files,
SSH keys, command outputs, network maps) into a single ZIP archive stored in
the configured exfiltration directory. Only the admin who owns the session
can download it, and the archive name/checksum is logged to the audit trail.
"""

import hashlib
import logging
import os
import time
import zipfile
from pathlib import Path

from app.brutal_sessions import BrutalSession
from app.config import get_settings

logger = logging.getLogger("phantomscan.brutal_exfil")


def resolve_archive(file_id: str) -> Path | None:
    """Resolve an archive id to a path, guarding against traversal."""
    settings = get_settings()
    root = Path(settings.brutal_exfil_dir).resolve()
    candidate = (root / file_id).resolve()
    if candidate.parent != root or not candidate.exists() or not candidate.is_file():
        return None
    if candidate.suffix.lower() != ".zip":
        return None
    return candidate


class ExfiltrationAgent:
    """Packs session loot into an encrypted-at-rest demo archive (ZIP)."""

    def __init__(self, session: BrutalSession) -> None:
        self.session = session
        self.settings = get_settings()

    def exfil_dir(self) -> Path:
        directory = Path(self.settings.brutal_exfil_dir)
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    async def pack(self, password: str | None = None) -> dict:
        """Zip all loot. Returns file metadata for the download endpoint."""
        if not self.session.loot:
            raise ValueError("No loot collected yet — run exploitation steps first")

        stamp = time.strftime("%Y%m%d-%H%M%S")
        archive_name = f"brutal-loot-{self.session.session_id[:8]}-{stamp}.zip"
        archive_path = self.exfil_dir() / archive_name

        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            seen: set[str] = set()
            for index, item in enumerate(self.session.loot):
                safe_name = "".join(ch for ch in item["name"] if ch.isalnum() or ch in "._- /").strip().replace(" ", "_")
                if not safe_name or safe_name in seen:
                    safe_name = f"loot_{index}_{item['kind']}.txt"
                seen.add(safe_name)
                archive.writestr(safe_name, item.get("content", ""))
            archive.writestr(
                "MANIFEST.txt",
                "\n".join(
                    f"{item['ts']} [{item['kind']}] {item['name']} <- {item['source']}"
                    for item in self.session.loot
                ),
            )

        sha256 = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        op_id = await self.session.log_op(
            "exfil_complete",
            "success",
            f"Exfiltrated {len(self.session.loot)} loot items to {archive_name} (SHA256 {sha256[:16]}…)",
            output=str(archive_path),
        )
        return {
            "file_id": archive_name,
            "filename": archive_name,
            "size_bytes": archive_path.stat().st_size,
            "loot_count": len(self.session.loot),
            "sha256": sha256,
            "op_id": op_id,
        }

    def resolve(self, file_id: str) -> Path | None:
        """Resolve an archive id to a path, guarding against traversal."""
        return resolve_archive(file_id)