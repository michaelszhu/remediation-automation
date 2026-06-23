"""Devin API client (v3) with record/replay support.

Real client: talks to ``https://api.devin.ai/v3/organizations/{org_id}/sessions``.
Replay client: activated when ``DEVIN_MOCK=1``; replays recorded real session
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

    def poll_until_terminal(
        self,
        session_id: str,
        interval: float = 30.0,
        timeout: float = 7200.0,
    ) -> SessionInfo:
        """Poll ``get_session`` until a terminal status or timeout."""
        deadline = time.monotonic() + timeout
        while True:
            info = self.get_session(session_id)
            if info.status in TERMINAL_STATUSES:
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
        )
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

    # -- recording ----------------------------------------------------------

    def _persist_recording(self, session_id: str, info: SessionInfo) -> None:
        identifier = self._session_identifiers.get(session_id, session_id)
        payload = {
            "session_id": info.session_id,
            "status": info.status.value,
            "acus_consumed": info.acus_consumed,
            "pull_requests": info.pull_requests,
            "structured_output": info.structured_output,
            "tags": info.tags,
        }
        self._recordings_dir.mkdir(parents=True, exist_ok=True)
        path = self._recordings_dir / f"{identifier}.json"
        path.write_text(json.dumps(payload, indent=2) + "\n")
        logger.info("Recorded session %s → %s", session_id, path)


def _parse_session_response(data: dict[str, Any]) -> SessionInfo:
    return SessionInfo(
        session_id=data["session_id"],
        status=SessionStatus(data["status"]),
        acus_consumed=data.get("acus_consumed", 0.0),
        pull_requests=data.get("pull_requests", []),
        structured_output=data.get("structured_output"),
        tags=data.get("tags", []),
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
        "action_taken": "declined",
        "status": "needs_review",
        "pr_url": None,
        "files_changed": [],
        "addressed": [],
        "skipped": [
            {
                "item": "paramiko >=3.5,<5.0 upgrade",
                "reason": (
                    "upgrading paramiko to 5.x removes DSSKey, which the "
                    "transitive dep sshtunnel still references; existing tests "
                    "paper over this, so a naive bump ships a latent runtime break"
                ),
            },
        ],
        "reasoning": (
            "Investigated the paramiko upgrade path. Version 5.x drops the "
            "deprecated DSSKey class that sshtunnel imports unconditionally. "
            "Until sshtunnel releases a compatible version, upgrading paramiko "
            "would introduce a runtime ImportError masked by the test suite."
        ),
        "tests_passed": None,
        "scan_clean_after": None,
        "risk_flagged": (
            "upgrading paramiko to 5.x removes DSSKey, which the transitive "
            "dep sshtunnel still references; existing tests paper over this, "
            "so a naive bump ships a latent runtime break"
        ),
    },
    "PyJWT": {
        "finding_id": "finding-pyjwt-001",
        "finding_type": "sca",
        "identifier": "PyJWT",
        "action_taken": "fixed",
        "status": "success",
        "pr_url": "https://github.com/michaelszhu/superset/pull/42",
        "files_changed": [
            "requirements/base.txt",
            "superset/utils/core.py",
        ],
        "addressed": [
            "CVE-2022-29217 — algorithm allow-list bypass affecting guest tokens",
        ],
        "skipped": [
            {
                "item": "CVE-2023-33460 — PyJWKClient SSRF",
                "reason": "code path not used by Superset",
            },
            {
                "item": "CVE-2024-33663 — detached JWS signature bypass",
                "reason": "code path not used by Superset",
            },
        ],
        "reasoning": (
            "Bumped PyJWT to 2.8.0+ which enforces the algorithms parameter. "
            "Verified Superset's guest-token validation now rejects tokens "
            "signed with unexpected algorithms. The PyJWKClient and detached-JWS "
            "CVEs don't apply because Superset never uses those code paths."
        ),
        "tests_passed": True,
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
        )

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

        recorded = _load_recording(identifier, self._recordings_dir)
        if recorded is not None:
            logger.info("Replaying recording for %r", identifier)
            payload = dict(recorded)
            payload["session_id"] = session_id
            if tags is not None:
                payload.setdefault("tags", tags)
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

# Keep the old name as an alias for backward compatibility.
MockDevinClient = ReplayDevinClient


def get_devin_client() -> BaseDevinClient:
    """Return the real or replay client based on ``DEVIN_MOCK`` / ``DEVIN_RECORD``."""
    if os.getenv("DEVIN_MOCK", "").strip() == "1":
        return ReplayDevinClient()
    record = os.getenv("DEVIN_RECORD", "").strip() == "1"
    return DevinClient(record=record)
