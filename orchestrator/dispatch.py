"""Dispatch logic — builds prompts, creates Devin sessions, polls to completion.

All remediation judgment lives in the Devin Playbook; this module is a dumb
dispatcher that parameterizes a prompt template and tracks session state.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from shared import config
from shared.db import init_db, list_sessions, upsert_finding, upsert_session
from shared.devin import BaseDevinClient, SessionInfo, get_devin_client
from shared.models import (
    REMEDIATION_OUTPUT_SCHEMA,
    Finding,
    SessionRecord,
    SessionStatus,
    TERMINAL_STATUSES,
    remediation_tags,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Parameterized prompt template
# ---------------------------------------------------------------------------

PROMPT_TEMPLATE = """\
Remediate the following security finding by following the Security Finding
Remediation playbook exactly.

finding_id:   {finding_id}
finding_type: {finding_type}        # "sca" or "sast"
identifier:   {identifier}          # package name or scanner rule id
severity:     {severity}
details:
{raw_details}
source issue: {source_issue_url}

Target repository: {repo}  (branch: {base_branch})

Investigate how this finding actually manifests in THIS repository before acting.
Decide the correct action per the playbook \u2014 fix, decline, or false-positive \u2014 and
execute it. Do not suppress scanners or mask tests; a real fix or an honest decline
only. When done, return the structured output exactly as the playbook\u2019s schema
specifies.
"""


def build_prompt(finding: Finding, *, repo: str, base_branch: str = "main") -> str:
    """Fill the parameterized template with finding details."""
    import json

    raw_details = json.dumps(finding.raw_details, indent=2) if finding.raw_details else ""
    return PROMPT_TEMPLATE.format(
        finding_id=finding.finding_id,
        finding_type=finding.finding_type.value
        if hasattr(finding.finding_type, "value")
        else finding.finding_type,
        identifier=finding.identifier,
        severity=finding.severity,
        raw_details=raw_details,
        source_issue_url=finding.source_issue_url,
        repo=repo,
        base_branch=base_branch,
    )


# ---------------------------------------------------------------------------
# Concurrency management
# ---------------------------------------------------------------------------

_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(config.MAX_CONCURRENCY())
    return _semaphore


# ---------------------------------------------------------------------------
# Core dispatch
# ---------------------------------------------------------------------------


async def dispatch_finding(finding: Finding) -> SessionRecord:
    """Dispatch a single finding: create session, persist, poll, update.

    Acquires the concurrency semaphore before creating the session.
    """
    sem = _get_semaphore()
    async with sem:
        return await _dispatch_inner(finding)


async def _dispatch_inner(finding: Finding) -> SessionRecord:
    """Internal dispatch — runs under the semaphore."""
    # Idempotency: skip if a terminal session already exists for this finding
    existing = list_sessions(finding_id=finding.finding_id)
    terminal = [s for s in existing if s.status in TERMINAL_STATUSES]
    if terminal:
        logger.info(
            "Finding %s already has terminal session %s — skipping",
            finding.finding_id,
            terminal[-1].devin_session_id,
        )
        return terminal[-1]

    client = get_devin_client()
    playbook_id = config.PLAYBOOK_ID() or None
    max_acu = config.MAX_ACU_LIMIT()
    repo = config.SUPERSET_FORK_REPO()
    repos = [repo]
    prompt = build_prompt(finding, repo=repo)
    tags = remediation_tags(finding.finding_type)

    # 1. Persist finding
    upsert_finding(finding)

    # 2. Create Devin session
    try:
        result = await asyncio.to_thread(
            client.create_session,
            prompt,
            repos=repos,
            playbook_id=playbook_id,
            tags=tags,
            structured_output_schema=REMEDIATION_OUTPUT_SCHEMA,
            max_acu_limit=max_acu,
            title=f"Remediate: {finding.identifier}",
        )
    except Exception as exc:
        logger.error("Failed to create session for %s: %s", finding.finding_id, exc)
        record = SessionRecord(
            finding_id=finding.finding_id,
            devin_session_id=f"error-{finding.finding_id}",
            devin_url="",
            status=SessionStatus.ERROR,
            structured_output={"error": str(exc)},
        )
        upsert_session(record)
        return record

    # 3. Persist initial SessionRecord (in_progress → RUNNING)
    record = SessionRecord(
        finding_id=finding.finding_id,
        devin_session_id=result.session_id,
        devin_url=result.url,
        status=SessionStatus.RUNNING,
    )
    upsert_session(record)

    # 4. Poll until terminal
    try:
        info: SessionInfo = await asyncio.to_thread(
            client.poll_until_terminal,
            result.session_id,
        )
    except (TimeoutError, Exception) as exc:
        logger.error("Polling failed for %s: %s", result.session_id, exc)
        record.status = SessionStatus.ERROR
        record.updated_at = datetime.now(timezone.utc)
        record.structured_output = {"error": str(exc)}
        upsert_session(record)
        return record

    # 5. Terminate the session if it's still running (e.g. waiting_for_user)
    if info.status not in TERMINAL_STATUSES:
        logger.info(
            "Session %s still %s after collecting output — terminating",
            result.session_id,
            info.status.value,
        )
        await asyncio.to_thread(client.terminate_session, result.session_id)

    # 6. Update record with final state
    record.status = info.status
    record.acus_consumed = info.acus_consumed
    record.updated_at = datetime.now(timezone.utc)

    if info.pull_requests:
        record.pr_url = info.pull_requests[0].get("pr_url")

    if info.structured_output:
        record.structured_output = info.structured_output
        record.action_taken = info.structured_output.get("action_taken")

    upsert_session(record)
    logger.info(
        "Session %s completed: status=%s action=%s",
        result.session_id,
        record.status.value,
        record.action_taken,
    )

    return record


async def dispatch_batch(findings: list[Finding]) -> list[SessionRecord]:
    """Dispatch a batch of findings concurrently (bounded by MAX_CONCURRENCY)."""
    tasks = [asyncio.create_task(dispatch_finding(f)) for f in findings]
    return await asyncio.gather(*tasks)
