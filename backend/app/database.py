import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

import aiosqlite

from app.config import BASE_DIR, get_settings
from app.models import FindingCreate
from app.security import redact_payload, redact_sensitive

SYSTEM_TARGET_URL = "system://phantomscan"
LATEST_SCHEMA_VERSION = 7
_UNSET = object()


def resolve_database_path() -> Path:
    database_url = get_settings().database_url
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        raise ValueError("DATABASE_URL must use the sqlite:/// URL format")
    configured_path = Path(database_url[len(prefix) :])
    if not configured_path.is_absolute():
        configured_path = BASE_DIR / configured_path
    return configured_path.resolve()


DATABASE_PATH = resolve_database_path()


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS authorized_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    target_origin TEXT NOT NULL,
    verification_method TEXT NOT NULL CHECK (verification_method IN ('dns', 'http')),
    verification_token_hash TEXT NOT NULL,
    challenge_expires_at TEXT NOT NULL,
    verified_at TEXT,
    expires_at TEXT,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'VERIFIED', 'EXPIRED', 'REVOKED')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('defend', 'pentest')),
    intensity TEXT NOT NULL DEFAULT 'medium' CHECK (intensity IN ('low', 'medium', 'high')),
    selected_tests TEXT NOT NULL DEFAULT '[]',
    user_id TEXT NOT NULL DEFAULT 'local-user',
    authorization_id INTEGER,
    authorization_confirmed INTEGER NOT NULL DEFAULT 0 CHECK (authorization_confirmed IN (0, 1)),
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'cancelling', 'cancelled', 'complete', 'error')),
    progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    request_count INTEGER NOT NULL DEFAULT 0,
    sandbox_id TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TEXT,
    completed_at TEXT,
    FOREIGN KEY (authorization_id) REFERENCES authorized_targets (id)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    confidence TEXT NOT NULL CHECK (confidence IN ('CONFIRMED', 'HIGH', 'MEDIUM', 'LOW', 'POTENTIAL')),
    target TEXT NOT NULL,
    endpoint TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    impact TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '',
    verification TEXT NOT NULL DEFAULT '',
    agent TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description TEXT NOT NULL DEFAULT '',
    how_exploited TEXT NOT NULL DEFAULT '',
    fix TEXT NOT NULL DEFAULT '',
    cve_id TEXT,
    cvss_score REAL CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)),
    parameter TEXT,
    module TEXT,
    recommended_fix TEXT,
    remediation_status TEXT NOT NULL DEFAULT 'OPEN' CHECK (remediation_status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED')),
    verification_status TEXT NOT NULL DEFAULT 'NOT_VERIFIED' CHECK (verification_status IN ('NOT_VERIFIED', 'FIX_VERIFIED', 'ISSUE_STILL_PRESENT', 'VERIFY_FAILED')),
    risk_status TEXT NOT NULL DEFAULT 'ACTIVE',
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    agent_name TEXT NOT NULL,
    action TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    details TEXT NOT NULL,
    user_id TEXT,
    target TEXT,
    authorization_status TEXT,
    selected_module TEXT,
    start_time TEXT,
    end_time TEXT,
    result TEXT,
    request_count INTEGER,
    sandbox_id TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

CREATE TABLE IF NOT EXISTS scan_artifacts (
    scan_id INTEGER PRIMARY KEY,
    scanner_output TEXT,
    shadow_recon_output TEXT,
    hindi_findings TEXT,
    markdown_report TEXT,
    notification_result TEXT,
    active_security_output TEXT,
    browser_security_output TEXT,
    ai_analyst_output TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ai_cache (
    cache_key TEXT PRIMARY KEY,
    finding_id INTEGER,
    evidence_hash TEXT NOT NULL,
    language TEXT NOT NULL,
    model TEXT NOT NULL,
    response TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_scan_id ON audit_logs (scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_agent_name ON audit_logs (agent_name, id);
CREATE INDEX IF NOT EXISTS idx_authorized_targets_lookup ON authorized_targets (user_id, target_origin, status);

CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete
BEFORE DELETE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'audit_logs are append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_logs_no_update
BEFORE UPDATE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'audit_logs are append-only');
END;
"""


@asynccontextmanager
async def get_connection() -> AsyncIterator[aiosqlite.Connection]:
    connection = await aiosqlite.connect(DATABASE_PATH)
    connection.row_factory = aiosqlite.Row
    await connection.execute("PRAGMA foreign_keys = ON")
    await connection.execute("PRAGMA journal_mode = WAL")
    await connection.execute("PRAGMA busy_timeout = 5000")
    try:
        yield connection
    finally:
        await connection.close()


def serialize_row(row: Any | None) -> dict[str, Any] | None:
    return None if row is None else dict(row)


async def _table_exists(connection: aiosqlite.Connection, table: str) -> bool:
    cursor = await connection.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,))
    return await cursor.fetchone() is not None


async def _column_exists(connection: aiosqlite.Connection, table: str, column: str) -> bool:
    cursor = await connection.execute(f"PRAGMA table_info({table})")
    return any(row["name"] == column for row in await cursor.fetchall())


async def initialize_database() -> None:
    async with get_connection() as connection:
        if not await _table_exists(connection, "scans"):
            await connection.executescript(SCHEMA_SQL)
            await connection.execute(f"PRAGMA user_version = {LATEST_SCHEMA_VERSION}")
            await connection.commit()
            return

        if not await _column_exists(connection, "findings", "confidence"):
            await _migrate_legacy_schema(connection)
            return

        await connection.executescript(SCHEMA_SQL)
        await _migrate_active_finding_columns(connection)
        await _migrate_active_artifact_columns(connection)
        await _migrate_browser_artifact_columns(connection)
        await _migrate_ai_columns(connection)
        await connection.execute(f"PRAGMA user_version = {LATEST_SCHEMA_VERSION}")
        await connection.commit()


async def _migrate_legacy_schema(connection: aiosqlite.Connection) -> None:
    await connection.execute("PRAGMA foreign_keys = OFF")
    await connection.executescript(
        """
        DROP TRIGGER IF EXISTS audit_logs_no_delete;
        DROP TRIGGER IF EXISTS audit_logs_no_update;
        ALTER TABLE scans RENAME TO scans_legacy;
        ALTER TABLE findings RENAME TO findings_legacy;
        ALTER TABLE audit_logs RENAME TO audit_logs_legacy;
        """
    )
    await connection.executescript(SCHEMA_SQL)
    await connection.executescript(
        """
        INSERT INTO scans (
            id, target_url, mode, intensity, selected_tests, user_id, authorization_confirmed,
            status, progress, request_count, created_at, started_at, completed_at
        )
        SELECT
            id, target_url, mode, 'medium', '[]', 'local-user', 0,
            status, CASE WHEN status = 'complete' THEN 100 ELSE 0 END, 0,
            created_at, created_at, completed_at
        FROM scans_legacy;

        INSERT INTO findings (
            id, scan_id, title, category, severity, confidence, target, endpoint, evidence,
            impact, recommendation, verification, agent, timestamp, description,
            how_exploited, fix, cve_id, cvss_score
        )
        SELECT
            f.id,
            f.scan_id,
            f.title,
            f.category,
            CASE UPPER(f.severity)
                WHEN 'CRITICAL' THEN 'CRITICAL'
                WHEN 'HIGH' THEN 'HIGH'
                WHEN 'MEDIUM' THEN 'MEDIUM'
                WHEN 'LOW' THEN 'LOW'
                ELSE 'INFO'
            END,
            'MEDIUM',
            COALESCE((SELECT target_url FROM scans_legacy WHERE id = f.scan_id), 'unknown'),
            COALESCE((SELECT target_url FROM scans_legacy WHERE id = f.scan_id), ''),
            f.description,
            f.how_exploited,
            f.fix,
            'Deploy the recommended fix and rerun the relevant PhantomScan check.',
            'Legacy Agent',
            COALESCE((SELECT created_at FROM scans_legacy WHERE id = f.scan_id), CURRENT_TIMESTAMP),
            f.description,
            f.how_exploited,
            f.fix,
            f.cve_id,
            f.cvss_score
        FROM findings_legacy AS f;

        INSERT INTO audit_logs (id, scan_id, agent_name, action, timestamp, details)
        SELECT id, scan_id, agent_name, action, timestamp, details FROM audit_logs_legacy;

        DROP TABLE findings_legacy;
        DROP TABLE audit_logs_legacy;
        DROP TABLE scans_legacy;
        """
    )
    # Renamed legacy indexes retain their old names until the legacy tables are dropped.
    await connection.executescript(SCHEMA_SQL)
    await connection.execute(f"PRAGMA user_version = {LATEST_SCHEMA_VERSION}")
    await connection.commit()
    await connection.execute("PRAGMA foreign_keys = ON")


async def _migrate_active_finding_columns(connection: aiosqlite.Connection) -> None:
    columns = [
        ("parameter", "TEXT"),
        ("module", "TEXT"),
        ("recommended_fix", "TEXT"),
        ("remediation_status", "TEXT NOT NULL DEFAULT 'OPEN'"),
        ("verification_status", "TEXT NOT NULL DEFAULT 'NOT_VERIFIED'"),
    ]
    for column, definition in columns:
        if not await _column_exists(connection, "findings", column):
            await connection.execute(f"ALTER TABLE findings ADD COLUMN {column} {definition}")


async def _migrate_active_artifact_columns(connection: aiosqlite.Connection) -> None:
    if not await _column_exists(connection, "scan_artifacts", "active_security_output"):
        await connection.execute("ALTER TABLE scan_artifacts ADD COLUMN active_security_output TEXT")


async def _migrate_browser_artifact_columns(connection: aiosqlite.Connection) -> None:
    if not await _column_exists(connection, "scan_artifacts", "browser_security_output"):
        await connection.execute("ALTER TABLE scan_artifacts ADD COLUMN browser_security_output TEXT")


async def _migrate_ai_columns(connection: aiosqlite.Connection) -> None:
    if not await _column_exists(connection, "findings", "risk_status"):
        await connection.execute("ALTER TABLE findings ADD COLUMN risk_status TEXT NOT NULL DEFAULT 'ACTIVE'")
    if not await _column_exists(connection, "scan_artifacts", "ai_analyst_output"):
        await connection.execute("ALTER TABLE scan_artifacts ADD COLUMN ai_analyst_output TEXT")
    await connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS ai_cache (
            cache_key TEXT PRIMARY KEY,
            finding_id INTEGER,
            evidence_hash TEXT NOT NULL,
            language TEXT NOT NULL,
            model TEXT NOT NULL,
            response TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )


async def create_scan(
    target_url: str,
    mode: str,
    intensity: str = "medium",
    selected_tests: str = "[]",
    user_id: str = "local-user",
    authorization_id: int | None = None,
    authorization_confirmed: bool = False,
) -> int:
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            INSERT INTO scans (
                target_url, mode, intensity, selected_tests, user_id, authorization_id, authorization_confirmed, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'queued')
            """,
            (target_url, mode, intensity, selected_tests, user_id, authorization_id, int(authorization_confirmed)),
        )
        await connection.commit()
        return int(cursor.lastrowid)


async def get_or_create_system_scan() -> int:
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT id FROM scans WHERE target_url = ? ORDER BY id ASC LIMIT 1",
            (SYSTEM_TARGET_URL,),
        )
        row = await cursor.fetchone()
        if row is not None:
            return int(row["id"])
        cursor = await connection.execute(
            """
            INSERT INTO scans (target_url, mode, intensity, status, progress, completed_at)
            VALUES (?, 'defend', 'low', 'complete', 100, CURRENT_TIMESTAMP)
            """,
            (SYSTEM_TARGET_URL,),
        )
        await connection.commit()
        return int(cursor.lastrowid)


async def get_scan(scan_id: int) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        return serialize_row(await cursor.fetchone())


async def list_scans() -> list[dict[str, Any]]:
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT * FROM scans WHERE target_url != ? ORDER BY created_at DESC, id DESC",
            (SYSTEM_TARGET_URL,),
        )
        return [dict(row) for row in await cursor.fetchall()]


async def get_latest_scan() -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT * FROM scans WHERE target_url != ? ORDER BY created_at DESC, id DESC LIMIT 1",
            (SYSTEM_TARGET_URL,),
        )
        return serialize_row(await cursor.fetchone())


async def get_previous_scan_for_target(target_url: str, scan_id: int) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            SELECT * FROM scans
            WHERE target_url = ? AND target_url != ? AND id < ? AND status = 'complete'
            ORDER BY id DESC
            LIMIT 1
            """,
            (target_url, SYSTEM_TARGET_URL, scan_id),
        )
        return serialize_row(await cursor.fetchone())


async def get_latest_scan_for_agent(agent_name: str) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            SELECT scans.*
            FROM scans
            JOIN audit_logs ON audit_logs.scan_id = scans.id
            WHERE audit_logs.agent_name = ?
            ORDER BY audit_logs.id DESC
            LIMIT 1
            """,
            (agent_name,),
        )
        return serialize_row(await cursor.fetchone())


async def update_scan_status(scan_id: int, status: str, error_message: str | None = None) -> None:
    started_sql = ", started_at = COALESCE(started_at, CURRENT_TIMESTAMP)" if status == "running" else ""
    terminal_sql = ", completed_at = CURRENT_TIMESTAMP" if status in {"cancelled", "complete", "error"} else ""
    complete_sql = ", progress = 100" if status == "complete" else ""
    async with get_connection() as connection:
        await connection.execute(
            f"UPDATE scans SET status = ?, error_message = ?{started_sql}{terminal_sql}{complete_sql} WHERE id = ?",
            (status, error_message, scan_id),
        )
        await connection.commit()


async def update_scan_progress(
    scan_id: int,
    progress: int,
    request_count: int | None = None,
    sandbox_id: str | None = None,
) -> None:
    assignments = ["progress = ?"]
    values: list[Any] = [max(0, min(progress, 100))]
    if request_count is not None:
        assignments.append("request_count = ?")
        values.append(request_count)
    if sandbox_id is not None:
        assignments.append("sandbox_id = ?")
        values.append(sandbox_id)
    values.append(scan_id)
    async with get_connection() as connection:
        await connection.execute(f"UPDATE scans SET {', '.join(assignments)} WHERE id = ?", values)
        await connection.commit()


async def create_finding(scan_id: int, finding: FindingCreate | dict[str, Any]) -> int:
    data = finding.model_dump(mode="json") if isinstance(finding, FindingCreate) else FindingCreate(**finding).model_dump(mode="json")
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            INSERT INTO findings (
                scan_id, title, category, severity, confidence, target, endpoint, evidence,
                impact, recommendation, verification, agent, timestamp, description,
                how_exploited, fix, cve_id, cvss_score, parameter, module, recommended_fix,
                remediation_status, verification_status, risk_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                data["title"],
                data["category"],
                data["severity"],
                data["confidence"],
                data["target"],
                data["endpoint"],
                data["evidence"],
                data["impact"],
                data["recommendation"],
                data["verification"],
                data["agent"],
                data["timestamp"],
                data["evidence"],
                data["impact"],
                data["recommendation"],
                data.get("cve_id"),
                data.get("cvss_score"),
                data.get("parameter"),
                data.get("module"),
                data.get("recommended_fix"),
                data.get("remediation_status", "OPEN"),
                data.get("verification_status", "NOT_VERIFIED"),
                data.get("risk_status", "ACTIVE"),
            ),
        )
        await connection.commit()
        return int(cursor.lastrowid)


async def get_findings(scan_id: int) -> list[dict[str, Any]]:
    async with get_connection() as connection:
        cursor = await connection.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY id ASC", (scan_id,))
        return [dict(row) for row in await cursor.fetchall()]


async def get_finding(finding_id: int) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        return serialize_row(await cursor.fetchone())


async def update_finding(finding_id: int, **fields: Any) -> None:
    allowed = {
        "title",
        "category",
        "severity",
        "confidence",
        "target",
        "endpoint",
        "evidence",
        "impact",
        "recommendation",
        "verification",
        "description",
        "how_exploited",
        "fix",
        "parameter",
        "module",
        "recommended_fix",
        "remediation_status",
        "verification_status",
        "risk_status",
    }
    updates = [(name, value) for name, value in fields.items() if name in allowed]
    if not updates:
        return
    assignments = ", ".join(f"{name} = ?" for name, _ in updates)
    values = [value for _, value in updates]
    values.append(finding_id)
    async with get_connection() as connection:
        await connection.execute(f"UPDATE findings SET {assignments} WHERE id = ?", values)
        await connection.commit()


async def list_findings(scan_id: int | None = None) -> list[dict[str, Any]]:
    async with get_connection() as connection:
        if scan_id is None:
            cursor = await connection.execute("SELECT * FROM findings ORDER BY id ASC")
        else:
            cursor = await connection.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY id ASC",
                (scan_id,),
            )
        return [dict(row) for row in await cursor.fetchall()]


async def add_audit_log(
    scan_id: int,
    agent_name: str,
    action: str,
    details: str,
    *,
    user_id: str | None = None,
    target: str | None = None,
    authorization_status: str | None = None,
    selected_module: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    result: str | None = None,
    request_count: int | None = None,
    sandbox_id: str | None = None,
) -> int:
    safe_details = redact_sensitive(details[:2000])
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            INSERT INTO audit_logs (
                scan_id, agent_name, action, details, user_id, target, authorization_status,
                selected_module, start_time, end_time, result, request_count, sandbox_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                agent_name,
                action,
                safe_details,
                user_id,
                target,
                authorization_status,
                selected_module,
                start_time,
                end_time,
                result,
                request_count,
                sandbox_id,
            ),
        )
        await connection.commit()
        return int(cursor.lastrowid)


async def get_audit_logs(scan_id: int) -> list[dict[str, Any]]:
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT * FROM audit_logs WHERE scan_id = ? ORDER BY timestamp ASC, id ASC",
            (scan_id,),
        )
        return [dict(row) for row in await cursor.fetchall()]


async def list_audit_logs(scan_id: int | None = None) -> list[dict[str, Any]]:
    async with get_connection() as connection:
        if scan_id is None:
            cursor = await connection.execute("SELECT * FROM audit_logs ORDER BY timestamp ASC, id ASC")
        else:
            cursor = await connection.execute(
                "SELECT * FROM audit_logs WHERE scan_id = ? ORDER BY timestamp ASC, id ASC",
                (scan_id,),
            )
        return [dict(row) for row in await cursor.fetchall()]


async def set_scan_artifacts(
    scan_id: int,
    *,
    scanner_output: Any = _UNSET,
    shadow_recon_output: Any = _UNSET,
    hindi_findings: Any = _UNSET,
    markdown_report: Any = _UNSET,
    notification_result: Any = _UNSET,
    active_security_output: Any = _UNSET,
    browser_security_output: Any = _UNSET,
    ai_analyst_output: Any = _UNSET,
) -> None:
    values = {
        "scanner_output": scanner_output,
        "shadow_recon_output": shadow_recon_output,
        "hindi_findings": hindi_findings,
        "markdown_report": markdown_report,
        "notification_result": notification_result,
        "active_security_output": active_security_output,
        "browser_security_output": browser_security_output,
        "ai_analyst_output": ai_analyst_output,
    }
    updates: list[str] = []
    parameters: list[Any] = []
    for column, value in values.items():
        if value is _UNSET:
            continue
        updates.append(f"{column} = ?")
        if column == "markdown_report" or value is None:
            parameters.append(redact_sensitive(value) if isinstance(value, str) else value)
        else:
            parameters.append(json.dumps(redact_payload(value), ensure_ascii=True, default=str))
    if not updates:
        return

    async with get_connection() as connection:
        await connection.execute("INSERT OR IGNORE INTO scan_artifacts (scan_id) VALUES (?)", (scan_id,))
        parameters.append(scan_id)
        await connection.execute(
            f"UPDATE scan_artifacts SET {', '.join(updates)}, updated_at = CURRENT_TIMESTAMP WHERE scan_id = ?",
            parameters,
        )
        await connection.commit()


def deserialize_artifact_row(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    for column in ("scanner_output", "shadow_recon_output", "hindi_findings", "notification_result", "active_security_output", "browser_security_output", "ai_analyst_output"):
        value = row.get(column)
        if value is not None:
            try:
                row[column] = json.loads(value)
            except (TypeError, json.JSONDecodeError):
                row[column] = None
    return row


async def get_scan_artifacts(scan_id: int) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute("SELECT * FROM scan_artifacts WHERE scan_id = ?", (scan_id,))
        row = serialize_row(await cursor.fetchone())
    return deserialize_artifact_row(row)


async def list_scan_artifacts(scan_id: int | None = None) -> list[dict[str, Any]]:
    async with get_connection() as connection:
        if scan_id is None:
            cursor = await connection.execute("SELECT * FROM scan_artifacts ORDER BY updated_at DESC, scan_id DESC")
        else:
            cursor = await connection.execute(
                "SELECT * FROM scan_artifacts WHERE scan_id = ? ORDER BY updated_at DESC, scan_id DESC",
                (scan_id,),
            )
        rows = [dict(row) for row in await cursor.fetchall()]
    return [artifact for artifact in (deserialize_artifact_row(row) for row in rows) if artifact is not None]


async def get_ai_cache(cache_key: str) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute("SELECT * FROM ai_cache WHERE cache_key = ?", (cache_key,))
        row = serialize_row(await cursor.fetchone())
    if row is None:
        return None
    try:
        row["response"] = json.loads(row["response"])
    except (TypeError, json.JSONDecodeError):
        row["response"] = None
    return row


async def set_ai_cache(
    cache_key: str,
    *,
    finding_id: int | None,
    evidence_hash: str,
    language: str,
    model: str,
    response: Any,
) -> None:
    safe_response = json.dumps(redact_payload(response), ensure_ascii=True, default=str)
    async with get_connection() as connection:
        await connection.execute(
            """
            INSERT INTO ai_cache (cache_key, finding_id, evidence_hash, language, model, response)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                finding_id = excluded.finding_id,
                evidence_hash = excluded.evidence_hash,
                language = excluded.language,
                model = excluded.model,
                response = excluded.response,
                updated_at = CURRENT_TIMESTAMP
            """,
            (cache_key, finding_id, evidence_hash, language, model, safe_response),
        )
        await connection.commit()


async def database_is_available() -> bool:
    try:
        async with get_connection() as connection:
            cursor = await connection.execute("SELECT 1")
            row = await cursor.fetchone()
            return row is not None and int(row[0]) == 1
    except (aiosqlite.Error, OSError, ValueError):
        return False


async def create_authorized_target(
    user_id: str,
    domain: str,
    target_origin: str,
    verification_method: str,
    token_hash: str,
    challenge_expires_at: str,
) -> int:
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            INSERT INTO authorized_targets (
                user_id, domain, target_origin, verification_method, verification_token_hash,
                challenge_expires_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING')
            """,
            (user_id, domain, target_origin, verification_method, token_hash, challenge_expires_at),
        )
        await connection.commit()
        return int(cursor.lastrowid)


async def get_authorized_target(authorization_id: int) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute("SELECT * FROM authorized_targets WHERE id = ?", (authorization_id,))
        return serialize_row(await cursor.fetchone())


async def find_authorized_target(user_id: str, target_origin: str) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            SELECT * FROM authorized_targets
            WHERE user_id = ? AND target_origin = ?
            ORDER BY CASE status WHEN 'VERIFIED' THEN 0 WHEN 'PENDING' THEN 1 ELSE 2 END, id DESC
            LIMIT 1
            """,
            (user_id, target_origin),
        )
        return serialize_row(await cursor.fetchone())


async def update_authorized_target(
    authorization_id: int,
    status: str,
    verified_at: str | None = None,
    expires_at: str | None = None,
) -> None:
    async with get_connection() as connection:
        await connection.execute(
            "UPDATE authorized_targets SET status = ?, verified_at = ?, expires_at = ? WHERE id = ?",
            (status, verified_at, expires_at, authorization_id),
        )
        await connection.commit()
