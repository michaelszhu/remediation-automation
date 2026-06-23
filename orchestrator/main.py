"""FastAPI application — webhook receiver, batch trigger, and health check.

This is a DUMB dispatcher. All remediation logic lives in the Devin Playbook.
"""

from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from fastapi import BackgroundTasks, FastAPI, Request, Response

from shared import config
from shared.db import DEFAULT_DB_PATH, init_db, list_findings, list_sessions, upsert_finding
from shared.models import Finding, FindingType, SessionRecord

from orchestrator.dispatch import dispatch_batch, dispatch_finding

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")


# ---------------------------------------------------------------------------
# Lifespan — initialize DB on startup
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("Database initialized")
    replay = os.getenv("DEVIN_REPLAY", "0").strip()
    record = os.getenv("DEVIN_RECORD", "0").strip()
    if replay == "1":
        logger.info("Mode: REPLAY (DEVIN_REPLAY=1) — using ReplayDevinClient with built-in fixtures")
    elif record == "1":
        logger.info("Mode: RECORD (DEVIN_RECORD=1) — using real DevinClient, recording sessions")
    else:
        logger.info("Mode: LIVE (DEVIN_REPLAY=%s) — using real DevinClient against Devin API", replay)
    yield


app = FastAPI(
    title="Remediation Orchestrator",
    description="Dispatches security findings to Devin for automated remediation.",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# GET /healthz
# ---------------------------------------------------------------------------


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# POST /webhook — GitHub "issues.labeled" events
# ---------------------------------------------------------------------------


@app.post("/webhook")
async def webhook(request: Request, background_tasks: BackgroundTasks) -> dict[str, Any]:
    """Receive GitHub webhook for issues.labeled events.

    When the label is "devin-remediate", parse the issue into a Finding and
    dispatch a Devin session in the background.
    """
    payload = await request.json()

    # Validate event type
    action = payload.get("action")
    label_name = payload.get("label", {}).get("name", "")
    if action != "labeled" or label_name != "devin-remediate":
        return {"status": "ignored", "reason": "not a devin-remediate label event"}

    # Parse issue into a Finding
    issue = payload.get("issue", {})
    finding = _parse_issue_to_finding(issue)

    # Persist and dispatch in background
    upsert_finding(finding)
    background_tasks.add_task(_dispatch_and_log, finding)

    return {
        "status": "dispatched",
        "finding_id": finding.finding_id,
        "identifier": finding.identifier,
    }


async def _dispatch_and_log(finding: Finding) -> None:
    """Background task wrapper for dispatch."""
    try:
        record = await dispatch_finding(finding)
        logger.info(
            "Dispatch complete: finding=%s session=%s status=%s",
            finding.finding_id,
            record.devin_session_id,
            record.status.value,
        )
    except Exception as exc:
        logger.exception("Dispatch failed for %s: %s", finding.finding_id, exc)


# ---------------------------------------------------------------------------
# POST /run-batch — manual trigger for all unprocessed findings
# ---------------------------------------------------------------------------


@app.post("/run-batch")
async def run_batch(background_tasks: BackgroundTasks) -> dict[str, Any]:
    """Load all open 'devin-remediate' findings from the DB and dispatch each.

    Runs dispatch in the background so the endpoint returns immediately.
    """
    findings = list_findings()
    if not findings:
        return {"status": "no_findings", "count": 0}

    background_tasks.add_task(_run_batch_task, findings)
    return {"status": "dispatching", "count": len(findings)}


async def _run_batch_task(findings: list[Finding]) -> None:
    """Background task for batch dispatch."""
    try:
        records = await dispatch_batch(findings)
        logger.info("Batch complete: %d findings processed", len(records))
    except Exception as exc:
        logger.exception("Batch dispatch failed: %s", exc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_issue_to_finding(issue: dict[str, Any]) -> Finding:
    """Parse a GitHub issue payload into a Finding.

    Heuristic:
    - If the issue title contains "CVE-" or issue labels include "sca", it's SCA.
    - Otherwise treat as SAST.
    - The identifier is extracted from the title (first word/token after the type
      indicator, or the whole title if no clear pattern).
    """
    title = issue.get("title", "")
    body = issue.get("body", "") or ""
    labels = [lbl.get("name", "") for lbl in issue.get("labels", [])]
    issue_url = issue.get("html_url", "")

    # Determine finding type
    is_sca = any(
        indicator in title.upper() or indicator in body.upper()
        for indicator in ("CVE-", "GHSA-", "OSV-")
    ) or "sca" in labels
    finding_type = FindingType.SCA if is_sca else FindingType.SAST

    # Extract identifier from title
    identifier = _extract_identifier(title)

    # Determine severity from labels
    severity = "medium"
    for lbl in labels:
        if lbl in ("critical", "high", "medium", "low"):
            severity = lbl
            break

    # Stable finding_id derived from issue URL
    finding_id = f"finding-{hashlib.sha256(issue_url.encode()).hexdigest()[:12]}"

    return Finding(
        finding_id=finding_id,
        finding_type=finding_type,
        identifier=identifier,
        title=title,
        severity=severity,
        source_issue_url=issue_url,
        raw_details={"body": body, "labels": labels},
    )


def _extract_identifier(title: str) -> str:
    """Best-effort extraction of the package/rule identifier from issue title."""
    # Common patterns: "CVE-XXXX-YYYY in package_name" or "rule-id: description"
    parts = title.split()
    if len(parts) >= 3 and parts[1].lower() == "in":
        return parts[2].rstrip(":")
    if ":" in title:
        return title.split(":")[0].strip()
    # Fall back to first meaningful token
    return parts[0] if parts else title


# ---------------------------------------------------------------------------
# Utility endpoints — dev / demo / test
# ---------------------------------------------------------------------------

_DEMO_SEED_FINDINGS = [
    Finding(
        finding_id="finding-paramiko-001",
        finding_type=FindingType.SCA,
        identifier="paramiko",
        title="CVE-2023-48795 in paramiko \u2014 Terrapin attack",
        severity="high",
        source_issue_url="https://github.com/michaelszhu/superset/issues/101",
        raw_details={"cve": "CVE-2023-48795", "package": "paramiko", "installed_version": "3.5.1"},
    ),
    Finding(
        finding_id="finding-pyjwt-001",
        finding_type=FindingType.SCA,
        identifier="PyJWT",
        title="CVE-2022-29217 in PyJWT \u2014 algorithm confusion",
        severity="critical",
        source_issue_url="https://github.com/michaelszhu/superset/issues/102",
        raw_details={"cve": "CVE-2022-29217", "package": "PyJWT", "installed_version": "2.12.0"},
    ),
    Finding(
        finding_id="finding-hive-injection-001",
        finding_type=FindingType.SAST,
        identifier="hive-column-injection",
        title="hive-column-injection: SQL injection via unescaped column identifiers",
        severity="high",
        source_issue_url="https://github.com/michaelszhu/superset/issues/103",
        raw_details={"rule_id": "hive-column-injection", "path": "superset/db_engine_specs/hive.py"},
    ),
]


@app.post("/reset")
async def reset() -> dict[str, str]:
    """Clear all findings and sessions \u2014 dev/test utility."""
    conn = sqlite3.connect(DEFAULT_DB_PATH)
    try:
        conn.execute("DELETE FROM sessions")
        conn.execute("DELETE FROM findings")
        conn.commit()
    finally:
        conn.close()
    return {"status": "reset"}


@app.post("/seed-demo")
async def seed_demo() -> dict[str, Any]:
    """Insert the 3 demo findings without dispatching."""
    for f in _DEMO_SEED_FINDINGS:
        upsert_finding(f)
    return {
        "status": "seeded",
        "count": len(_DEMO_SEED_FINDINGS),
        "findings": [
            {"finding_id": f.finding_id, "identifier": f.identifier}
            for f in _DEMO_SEED_FINDINGS
        ],
    }


@app.get("/sessions")
async def sessions_list() -> dict[str, Any]:
    """List all session records with structured output and finding context."""
    sessions = list_sessions()
    findings_map = {f.finding_id: f for f in list_findings()}
    return {
        "sessions": [
            {
                "devin_session_id": s.devin_session_id,
                "finding_id": s.finding_id,
                "devin_url": s.devin_url,
                "status": s.status.value,
                "action_taken": s.action_taken,
                "pr_url": s.pr_url,
                "acus_consumed": s.acus_consumed,
                "created_at": (
                    s.created_at.isoformat()
                    if isinstance(s.created_at, datetime)
                    else str(s.created_at)
                ),
                "updated_at": (
                    s.updated_at.isoformat()
                    if isinstance(s.updated_at, datetime)
                    else str(s.updated_at)
                ),
                "structured_output": s.structured_output,
                "identifier": (
                    findings_map[s.finding_id].identifier
                    if s.finding_id in findings_map
                    else None
                ),
                "finding_type": (
                    findings_map[s.finding_id].finding_type.value
                    if s.finding_id in findings_map
                    else None
                ),
                "source_issue_url": (
                    findings_map[s.finding_id].source_issue_url
                    if s.finding_id in findings_map
                    else None
                ),
            }
            for s in sessions
        ],
    }
