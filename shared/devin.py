"""Devin API client (v3) with record/replay support.

Real client: talks to ``https://api.devin.ai/v3/organizations/{org_id}/sessions``.
Replay client: activated when ``DEVIN_REPLAY=1``; replays recorded real session
payloads from ``recordings/*.json``.  Falls back to built-in default recordings
when no file exists for a given identifier.
Recording: when ``DEVIN_RECORD=1``, the real client persists each session's
terminal payload to ``recordings/<identifier>.json`` as a side effect.

Usage::

    from shared.devin import get_devin_client

    client = get_devin_client()
    session_id, url = client.create_session(prompt="fix paramiko", ...)
    result = client.poll_until_terminal(session_id)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from shared.models import TERMINAL_STATUSES, SessionStatus

logger = logging.getLogger(__name__)

DEFAULT_RECORDINGS_DIR = "recordings"

API_BASE = "https://api.devin.ai/v3"

# When True, the ReplayDevinClient ignores recording files and uses
# built-in default recordings only.  Toggled by the orchestrator's
# /replay-config endpoint so that ``verify`` mode is deterministic.
_replay_defaults_only: bool = False


def set_replay_defaults_only(value: bool) -> None:
    global _replay_defaults_only
    _replay_defaults_only = value


# ---------------------------------------------------------------------------
# Response containers
# ---------------------------------------------------------------------------

@dataclass
class CreateSessionResult:
    session_id: str
    url: str


@dataclass
class SessionInfo:
    session_id: str
    status: SessionStatus
    acus_consumed: float
    pull_requests: list[dict[str, Any]]
    structured_output: dict[str, Any] | None
    tags: list[str]
    status_detail: str | None = None


# ---------------------------------------------------------------------------
# Abstract interface
# ---------------------------------------------------------------------------

class BaseDevinClient(ABC):

    @abstractmethod
    def create_session(
        self,
        prompt: str,
        *,
        repos: list[str] | None = None,
        playbook_id: str | None = None,
        tags: list[str] | None = None,
        structured_output_schema: dict[str, Any] | None = None,
        max_acu_limit: int | None = None,
        title: str | None = None,
    ) -> CreateSessionResult:
        ...

    @abstractmethod
    def get_session(self, session_id: str) -> SessionInfo:
        ...

    def terminate_session(self, session_id: str) -> None:
        """Terminate a session. No-op by default (subclasses may override)."""

    def finalize_recording(self, session_id: str) -> None:
        """Re-query and persist recording with final data. No-op by default."""

    def poll_until_terminal(
        self,
        session_id: str,
        interval: float = 30.0,
        timeout: float = 7200.0,
    ) -> SessionInfo:
        """Poll ``get_session`` until a terminal status or timeout.

        A session is considered done when it reaches a terminal status
        (exit, error, suspended) **or** when it is waiting for user input
        and has already produced structured output — meaning the
        remediation task is complete even though the session hasn't
        formally exited.
        """
        deadline = time.monotonic() + timeout
        while True:
            info = self.get_session(session_id)
            if info.status in TERMINAL_STATUSES:
                return info
            if _session_effectively_done(info):
                logger.info(
                    "Session %s is done (status_detail=%s, "
                    "structured_output present) — treating as terminal",
                    session_id,
                    info.status_detail,
                )
                return info
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Session {session_id} did not reach terminal status "
                    f"within {timeout}s (last status: {info.status.value})"
                )
            time.sleep(interval)


# ---------------------------------------------------------------------------
# Real client — Devin v3 API
# ---------------------------------------------------------------------------

class DevinClient(BaseDevinClient):

    def __init__(
        self,
        api_key: str | None = None,
        org_id: str | None = None,
        *,
        record: bool = False,
        recordings_dir: str | None = None,
    ) -> None:
        self._api_key = api_key or os.environ["DEVIN_API_KEY"]
        self._org_id = org_id or os.environ["DEVIN_ORG_ID"]
        self._base = f"{API_BASE}/organizations/{self._org_id}/sessions"
        self._headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        self._record = record
        self._recordings_dir = Path(
            recordings_dir or os.getenv("DEVIN_RECORDINGS_DIR", DEFAULT_RECORDINGS_DIR)
        ).resolve()
        if self._record:
            logger.info("Recording enabled — recordings dir: %s", self._recordings_dir)
        # session_id → identifier, populated by create_session
        self._session_identifiers: dict[str, str] = {}

    # -- create -------------------------------------------------------------

    def create_session(
        self,
        prompt: str,
        *,
        repos: list[str] | None = None,
        playbook_id: str | None = None,
        tags: list[str] | None = None,
        structured_output_schema: dict[str, Any] | None = None,
        max_acu_limit: int | None = None,
        title: str | None = None,
    ) -> CreateSessionResult:
        body: dict[str, Any] = {"prompt": prompt}
        if repos is not None:
            body["repos"] = repos
        if playbook_id is not None:
            body["playbook_id"] = playbook_id
        if tags is not None:
            body["tags"] = tags
        if structured_output_schema is not None:
            body["structured_output_schema"] = structured_output_schema
            body["structured_output_required"] = True
        if max_acu_limit is not None:
            body["max_acu_limit"] = max_acu_limit
        if title is not None:
            body["title"] = title

        resp = httpx.post(self._base, json=body, headers=self._headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        result = CreateSessionResult(
            session_id=data["session_id"],
            url=data["url"],
        )

        if self._record:
            identifier = _extract_identifier(prompt, tags)
            self._session_identifiers[result.session_id] = identifier

        return result

    # -- get ----------------------------------------------------------------

    def get_session(self, session_id: str) -> SessionInfo:
        url = f"{self._base}/{session_id}"
        resp = httpx.get(url, headers=self._headers, timeout=30)
        resp.raise_for_status()
        return _parse_session_response(resp.json())

    # -- terminate ----------------------------------------------------------

    def terminate_session(self, session_id: str) -> None:
        """Terminate a running session via the v3 API."""
        url = f"{self._base}/{session_id}/terminate"
        try:
            resp = httpx.post(url, headers=self._headers, timeout=30)
            resp.raise_for_status()
            logger.info("Terminated session %s", session_id)
        except Exception as exc:
            logger.warning("Failed to terminate session %s: %s", session_id, exc)

    # -- poll (override to add recording side-effect) -----------------------

    def poll_until_terminal(
        self,
        session_id: str,
        interval: float = 30.0,
        timeout: float = 7200.0,
    ) -> SessionInfo:
        info = super().poll_until_terminal(session_id, interval, timeout)
        if self._record:
            self._persist_recording(session_id, info)
        return info

    def finalize_recording(self, session_id: str) -> None:
        """Re-query the session after termination for final ACU data.

        Called by dispatch after terminating a session so the recording
        captures the finalized ``acus_consumed`` value.
        """
        if not self._record:
            return
        try:
            time.sleep(5)  # brief pause for API to finalize billing
            info = self.get_session(session_id)
            self._persist_recording(session_id, info)
            logger.info(
                "Finalized recording for %s (acus=%.1f)",
                session_id,
                info.acus_consumed,
            )
        except Exception as exc:
            logger.warning("Failed to finalize recording for %s: %s", session_id, exc)

    # -- recording ----------------------------------------------------------

    def _persist_recording(self, session_id: str, info: SessionInfo) -> None:
        identifier = self._session_identifiers.get(session_id, session_id)
        payload: dict[str, Any] = {
            "session_id": info.session_id,
            "status": info.status.value,
            "acus_consumed": info.acus_consumed,
            "pull_requests": info.pull_requests,
            "structured_output": info.structured_output,
            "tags": info.tags,
        }
        if info.status_detail:
            payload["status_detail"] = info.status_detail
        self._recordings_dir.mkdir(parents=True, exist_ok=True)
        path = self._recordings_dir / f"{identifier}.json"
        path.write_text(json.dumps(payload, indent=2) + "\n")
        logger.info("Recorded session %s → %s (%d bytes)", session_id, path, path.stat().st_size)


def _session_effectively_done(info: SessionInfo) -> bool:
    """Return True when Devin finished its task but the session is still open.

    The v3 API keeps sessions in ``running (waiting_for_user)`` after the
    agent completes its work.  We treat that as terminal once structured
    output has been produced.
    """
    if info.status_detail == "waiting_for_user" and info.structured_output:
        return True
    return False


def _parse_session_response(data: dict[str, Any]) -> SessionInfo:
    return SessionInfo(
        session_id=data["session_id"],
        status=SessionStatus(data["status"]),
        acus_consumed=data.get("acus_consumed", 0.0),
        pull_requests=data.get("pull_requests", []),
        structured_output=data.get("structured_output"),
        tags=data.get("tags", []),
        status_detail=data.get("status_detail"),
    )


# ---------------------------------------------------------------------------
# Default recordings — built-in real session payloads for demo findings
# ---------------------------------------------------------------------------

# Used as fallbacks when no recorded session file exists for an identifier.
_DEFAULT_RECORDINGS: dict[str, dict[str, Any]] = {
    "paramiko": {
        "finding_id": "finding-paramiko-001",
        "finding_type": "sca",
        "identifier": "paramiko",
        "action_taken": "false_positive",
        "status": "success",
        "pr_url": None,
        "files_changed": [],
        "addressed": [],
        "skipped": [
            {
                "item": "CVE-2023-48795",
                "reason": (
                    "False positive: CVE-2023-48795 affects Paramiko < 3.4.0. "
                    "The repository already uses paramiko==3.5.1 with a floor "
                    "of >=3.4.0, which includes the Terrapin attack fix."
                ),
            },
        ],
        "reasoning": (
            "CVE-2023-48795 (Terrapin Attack) was fixed in paramiko 3.4.0. "
            "This repository pins paramiko==3.5.1 in requirements/base.txt "
            "and declares paramiko>=3.4.0,<4.0 in pyproject.toml. Since "
            "3.5.1 > 3.4.0, the fix is already present. No code changes needed."
        ),
        "tests_passed": None,
        "scan_clean_after": None,
        "risk_flagged": None,
    },
    "PyJWT": {
        "finding_id": "finding-pyjwt-001",
        "finding_type": "sca",
        "identifier": "PyJWT",
        "action_taken": "false_positive",
        "status": "success",
        "pr_url": None,
        "files_changed": [],
        "addressed": [],
        "skipped": [
            {
                "item": "CVE-2022-29217 - PyJWT algorithm confusion",
                "reason": (
                    "False positive: PyJWT is pinned at 2.12.0 (>=2.4.0 "
                    "enforced in pyproject.toml), and all jwt.decode() calls "
                    "already pass algorithms explicitly. The vulnerability "
                    "only affects versions < 2.4.0."
                ),
            },
        ],
        "reasoning": (
            "Investigated PyJWT usage across the codebase. CVE-2022-29217 "
            "affects PyJWT < 2.4.0 when jwt.decode() is called without an "
            "explicit algorithms argument. This repository pins PyJWT at "
            "2.12.0 and passes algorithms explicitly on every jwt.decode() "
            "call. No code change needed — finding is fully mitigated."
        ),
        "tests_passed": None,
        "scan_clean_after": None,
        "risk_flagged": None,
    },
    "hive-column-injection": {
        "finding_id": "finding-hive-injection-001",
        "finding_type": "sast",
        "identifier": "hive-column-injection",
        "action_taken": "fixed",
        "status": "success",
        "pr_url": "https://github.com/michaelszhu/superset/pull/43",
        "files_changed": [
            "superset/db_engine_specs/hive.py",
        ],
        "addressed": [
            "SQL injection via unescaped column identifiers in df_to_sql",
        ],
        "skipped": [],
        "reasoning": (
            "Escaped backticks in column names mirroring the schema-name "
            "escaping already present in the same function. Column identifiers "
            "are now wrapped with backtick-escaped quoting consistent with "
            "HiveEngineSpec.escape_identifier."
        ),
        "tests_passed": True,
        "scan_clean_after": True,
        "risk_flagged": None,
    },
    "apispec-upgrade": {
        "finding_id": "finding-apispec-upgrade-001",
        "finding_type": "sca",
        "identifier": "apispec-upgrade",
        "action_taken": "fixed",
        "status": "success",
        "pr_url": "https://github.com/michaelszhu/superset/pull/44",
        "files_changed": [
            "requirements/base.txt",
            "tests/unit_tests/db_engine_specs/test_base.py",
        ],
        "addressed": [
            "Bumped apispec from 6.6.1 to 6.7.1 and updated test assertion for new JSON-schema output",
        ],
        "skipped": [],
        "reasoning": (
            "Bumped apispec to 6.7.1. The only breaking change was a minor "
            "JSON-schema generation difference in db_engine_specs tests — "
            "updated the expected assertion to match the new output format."
        ),
        "tests_passed": True,
        "scan_clean_after": True,
        "risk_flagged": None,
    },
    "dompurify-upgrade": {
        "finding_id": "finding-dompurify-upgrade-001",
        "finding_type": "sca",
        "identifier": "dompurify-upgrade",
        "action_taken": "fixed",
        "status": "success",
        "pr_url": "https://github.com/michaelszhu/superset/pull/45",
        "files_changed": [
            "superset-frontend/package.json",
            "superset-frontend/package-lock.json",
        ],
        "addressed": [
            "Bumped DOMPurify to 3.1.7 to resolve HTML-sanitization bypass advisory",
        ],
        "skipped": [],
        "reasoning": (
            "Bumped DOMPurify from 3.0.6 to 3.1.7 in superset-frontend. "
            "The advisory allowed crafted HTML to bypass the sanitizer. "
            "Ran frontend build and tests — no breaking changes."
        ),
        "tests_passed": True,
        "scan_clean_after": True,
        "risk_flagged": None,
    },
    "cancel-query-sql-injection": {
        "finding_id": "finding-cancel-query-sqli-001",
        "finding_type": "sast",
        "identifier": "cancel-query-sql-injection",
        "action_taken": "fixed",
        "status": "success",
        "pr_url": "https://github.com/michaelszhu/superset/pull/102",
        "files_changed": [
            "superset/db_engine_specs/postgres.py",
            "superset/db_engine_specs/redshift.py",
            "tests/unit_tests/db_engine_specs/test_cancel_query_validation.py",
        ],
        "addressed": [
            "Replaced f-string SQL interpolation with parameterized queries "
            "in PostgresEngineSpec.cancel_query and RedshiftEngineSpec.cancel_query",
        ],
        "skipped": [],
        "reasoning": (
            "cancel_query_id flows from user API requests through SQLExecutor "
            "into engine spec cancel_query methods, where it was interpolated "
            "directly into SQL via f-strings. Replaced with parameterized "
            "queries and int() casting, matching DB-API 2.0 patterns."
        ),
        "tests_passed": True,
        "scan_clean_after": True,
        "risk_flagged": None,
    },
    "yaml-unsafe-loader": {
        "finding_id": "finding-yaml-unsafe-loader-001",
        "finding_type": "sast",
        "identifier": "yaml-unsafe-loader",
        "action_taken": "fixed",
        "status": "success",
        "pr_url": "https://github.com/michaelszhu/superset/pull/46",
        "files_changed": [
            "superset/examples/utils.py",
        ],
        "addressed": [
            "Replaced yaml.Loader with yaml.SafeLoader in load_configs_from_directory()",
        ],
        "skipped": [],
        "reasoning": (
            "Replaced yaml.Loader with yaml.SafeLoader in "
            "load_configs_from_directory(). The function only reads "
            "simple key-value metadata from bundled YAML files — "
            "SafeLoader handles this without allowing arbitrary code "
            "execution. All example-loading tests pass."
        ),
        "tests_passed": True,
        "scan_clean_after": True,
        "risk_flagged": None,
    },
    "silenced-exceptions": {
        "finding_id": "finding-silenced-exceptions-001",
        "finding_type": "sast",
        "identifier": "silenced-exceptions",
        "action_taken": "fixed",
        "status": "success",
        "pr_url": "https://github.com/michaelszhu/superset/pull/47",
        "files_changed": [
            "superset/charts/client_processing.py",
            "superset/extensions/__init__.py",
            "superset/async_events/async_query_manager.py",
            "superset/utils/log.py",
            "superset/models/core.py",
            "superset/connectors/sqla/utils.py",
        ],
        "addressed": [
            "Added logger.warning with exc_info=True to silenced exception handlers",
            "Narrowed broad except Exception to specific types where safe",
        ],
        "skipped": [],
        "reasoning": (
            "Added logger.warning(..., exc_info=True) to exception handlers "
            "that were silently discarding errors. Narrowed except Exception "
            "to specific types (ValueError, KeyError, IndexError, OSError, "
            "json.JSONDecodeError, TypeError) where the set of expected "
            "exceptions is clear. Kept broad catches where intentional "
            "(e.g. database property extraction) but added logging."
        ),
        "tests_passed": True,
        "scan_clean_after": True,
        "risk_flagged": None,
    },
}


_UNKNOWN_RECORDING: dict[str, Any] = {
    "finding_id": "finding-unknown",
    "finding_type": "sca",
    "identifier": "unknown",
    "action_taken": "declined",
    "status": "needs_review",
    "pr_url": None,
    "files_changed": [],
    "addressed": [],
    "skipped": [],
    "reasoning": "No matching recording found for prompt.",
    "tests_passed": None,
    "scan_clean_after": None,
    "risk_flagged": None,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _estimate_acus(structured_output: dict[str, Any]) -> float:
    """Estimate realistic ACU cost from structured output action.

    Used when recordings have acus_consumed=0 (captured before billing
    finalized).  Values are representative of real session costs.
    """
    action = structured_output.get("action_taken", "")
    if action == "fixed":
        return 8.5  # investigation + code changes + PR + tests
    if action in ("false_positive", "declined"):
        return 3.8  # investigation + analysis only
    return 2.0  # minimal/errored session


def _extract_identifier(prompt: str, tags: list[str] | None = None) -> str:
    """Best-effort identifier extraction from prompt text or tags."""
    for key in _DEFAULT_RECORDINGS:
        if key.lower() in prompt.lower():
            return key
    if tags:
        for tag in tags:
            if tag not in ("devin-remediate", "sca", "sast"):
                return tag
    return hashlib.sha256(prompt.encode()).hexdigest()[:12]


def _load_recording(
    identifier: str,
    recordings_dir: Path,
) -> dict[str, Any] | None:
    """Load a recorded payload for *identifier*, or return ``None``."""
    path = recordings_dir / f"{identifier}.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text())  # type: ignore[no-any-return]
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load recording %s: %s", path, exc)
        return None


class ReplayDevinClient(BaseDevinClient):
    """Replay client: loads recorded real session payloads from ``recordings/*.json``.

    Falls back to the built-in ``_DEFAULT_RECORDINGS`` when no recorded file
    exists for a given identifier, and logs a warning so operators know a real
    recording is missing.
    """

    def __init__(self, recordings_dir: str | None = None) -> None:
        self._sessions: dict[str, dict[str, Any]] = {}
        self._recordings_dir = Path(
            recordings_dir or os.getenv("DEVIN_RECORDINGS_DIR", DEFAULT_RECORDINGS_DIR)
        ).resolve()
        logger.info("ReplayDevinClient recordings dir: %s", self._recordings_dir)

    def create_session(
        self,
        prompt: str,
        *,
        repos: list[str] | None = None,
        playbook_id: str | None = None,
        tags: list[str] | None = None,
        structured_output_schema: dict[str, Any] | None = None,
        max_acu_limit: int | None = None,
        title: str | None = None,
    ) -> CreateSessionResult:
        identifier = _extract_identifier(prompt, tags)
        session_id = f"devin-replay-{identifier}"
        url = f"https://app.devin.ai/sessions/{session_id}"

        recorded = (
            _load_recording(identifier, self._recordings_dir)
            if not _replay_defaults_only
            else None
        )
        if recorded is not None:
            logger.info("Replaying recording for %r", identifier)
            payload = dict(recorded)
            payload["session_id"] = session_id
            if tags is not None:
                payload.setdefault("tags", tags)
            # Recordings captured in waiting_for_user state may lack
            # status_detail.  Infer it so _session_effectively_done works.
            if (
                payload.get("status") == "running"
                and payload.get("structured_output")
                and not payload.get("status_detail")
            ):
                payload["status_detail"] = "waiting_for_user"
            # ACUs are often 0 in recordings captured before billing
            # finalized.  Estimate realistic values for demo display.
            if not payload.get("acus_consumed"):
                payload["acus_consumed"] = _estimate_acus(
                    payload.get("structured_output") or {}
                )
        else:
            default = self._match_default_recording(prompt)
            if default is not _UNKNOWN_RECORDING:
                logger.warning(
                    "No recording found for %r — falling back to default recording",
                    identifier,
                )
            else:
                logger.warning(
                    "No recording or default for %r — using unknown fallback",
                    identifier,
                )
            payload = {
                "session_id": session_id,
                "status": SessionStatus.EXIT.value,
                "acus_consumed": 1.5,
                "pull_requests": (
                    [{"pr_url": default["pr_url"], "pr_state": "open"}]
                    if default.get("pr_url")
                    else []
                ),
                "structured_output": default,
                "tags": tags or [],
            }

        self._sessions[session_id] = payload
        return CreateSessionResult(session_id=session_id, url=url)

    def get_session(self, session_id: str) -> SessionInfo:
        data = self._sessions.get(session_id)
        if data is None:
            raise KeyError(f"Replay session {session_id!r} not found")
        return _parse_session_response(data)

    @staticmethod
    def _match_default_recording(prompt: str) -> dict[str, Any]:
        """Match against built-in default recordings."""
        prompt_lower = prompt.lower()
        for key, recording in _DEFAULT_RECORDINGS.items():
            if key.lower() in prompt_lower:
                return recording
        return _UNKNOWN_RECORDING


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def get_devin_client() -> BaseDevinClient:
    """Return the real or replay client based on ``DEVIN_REPLAY`` / ``DEVIN_RECORD``."""
    if os.getenv("DEVIN_REPLAY", "").strip() == "1":
        return ReplayDevinClient()
    record = os.getenv("DEVIN_RECORD", "").strip() == "1"
    return DevinClient(record=record)
