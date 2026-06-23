"""SQLite persistence layer for findings and session records.

Usage::

    from shared.db import init_db, upsert_finding, upsert_session

    init_db()  # creates tables if they don't exist
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

from shared.models import Finding, FindingType, SessionRecord, SessionStatus

DEFAULT_DB_PATH = os.getenv("REMEDIATION_DB_PATH", "remediation.db")

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS findings (
    finding_id    TEXT PRIMARY KEY,
    finding_type  TEXT NOT NULL,
    identifier    TEXT NOT NULL,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    source_issue_url TEXT NOT NULL,
    raw_details   TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS sessions (
    devin_session_id  TEXT PRIMARY KEY,
    finding_id        TEXT NOT NULL REFERENCES findings(finding_id),
    devin_url         TEXT NOT NULL,
    status            TEXT NOT NULL,
    action_taken      TEXT,
    pr_url            TEXT,
    acus_consumed     REAL NOT NULL DEFAULT 0.0,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    structured_output TEXT NOT NULL DEFAULT '{}'
);
"""


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

def _connect(db_path: str | None = None) -> sqlite3.Connection:
    path = db_path or DEFAULT_DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: str | None = None) -> None:
    """Create the schema (idempotent)."""
    with _connect(db_path) as conn:
        conn.executescript(_SCHEMA_SQL)


# ---------------------------------------------------------------------------
# Finding CRUD
# ---------------------------------------------------------------------------

def upsert_finding(finding: Finding, db_path: str | None = None) -> None:
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO findings
                (finding_id, finding_type, identifier, title, severity,
                 source_issue_url, raw_details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(finding_id) DO UPDATE SET
                finding_type     = excluded.finding_type,
                identifier       = excluded.identifier,
                title            = excluded.title,
                severity         = excluded.severity,
                source_issue_url = excluded.source_issue_url,
                raw_details      = excluded.raw_details
            """,
            (
                finding.finding_id,
                finding.finding_type.value if isinstance(finding.finding_type, FindingType) else finding.finding_type,
                finding.identifier,
                finding.title,
                finding.severity,
                finding.source_issue_url,
                json.dumps(finding.raw_details),
            ),
        )


def list_findings(db_path: str | None = None) -> list[Finding]:
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM findings").fetchall()
    return [_row_to_finding(r) for r in rows]


def _row_to_finding(row: sqlite3.Row) -> Finding:
    return Finding(
        finding_id=row["finding_id"],
        finding_type=FindingType(row["finding_type"]),
        identifier=row["identifier"],
        title=row["title"],
        severity=row["severity"],
        source_issue_url=row["source_issue_url"],
        raw_details=json.loads(row["raw_details"]),
    )


# ---------------------------------------------------------------------------
# Session CRUD
# ---------------------------------------------------------------------------

def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def upsert_session(record: SessionRecord, db_path: str | None = None) -> None:
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO sessions
                (devin_session_id, finding_id, devin_url, status,
                 action_taken, pr_url, acus_consumed,
                 created_at, updated_at, structured_output)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(devin_session_id) DO UPDATE SET
                status            = excluded.status,
                action_taken      = excluded.action_taken,
                pr_url            = excluded.pr_url,
                acus_consumed     = excluded.acus_consumed,
                updated_at        = excluded.updated_at,
                structured_output = excluded.structured_output
            """,
            (
                record.devin_session_id,
                record.finding_id,
                record.devin_url,
                record.status.value if isinstance(record.status, SessionStatus) else record.status,
                record.action_taken,
                record.pr_url,
                record.acus_consumed,
                record.created_at.isoformat() if isinstance(record.created_at, datetime) else record.created_at,
                record.updated_at.isoformat() if isinstance(record.updated_at, datetime) else record.updated_at,
                json.dumps(record.structured_output),
            ),
        )


def get_session(devin_session_id: str, db_path: str | None = None) -> SessionRecord | None:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE devin_session_id = ?",
            (devin_session_id,),
        ).fetchone()
    return _row_to_session(row) if row else None


def list_sessions(
    finding_id: str | None = None,
    db_path: str | None = None,
) -> list[SessionRecord]:
    with _connect(db_path) as conn:
        if finding_id:
            rows = conn.execute(
                "SELECT * FROM sessions WHERE finding_id = ? ORDER BY created_at",
                (finding_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY created_at",
            ).fetchall()
    return [_row_to_session(r) for r in rows]


def _parse_dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value)


def _row_to_session(row: sqlite3.Row) -> SessionRecord:
    return SessionRecord(
        finding_id=row["finding_id"],
        devin_session_id=row["devin_session_id"],
        devin_url=row["devin_url"],
        status=SessionStatus(row["status"]),
        action_taken=row["action_taken"],
        pr_url=row["pr_url"],
        acus_consumed=row["acus_consumed"],
        created_at=_parse_dt(row["created_at"]),
        updated_at=_parse_dt(row["updated_at"]),
        structured_output=json.loads(row["structured_output"]),
    )
