"""Devin API client (v3) and mock implementation.

Real client: talks to ``https://api.devin.ai/v3/organizations/{org_id}/sessions``.
Mock client: activated when ``DEVIN_MOCK=1``; returns canned structured outputs
for the three demo findings so the full system runs without a Devin key.

Usage::

    from shared.devin import get_devin_client

    client = get_devin_client()
    session_id, url = client.create_session(prompt="fix paramiko", ...)
    result = client.poll_until_terminal(session_id)
"""

from __future__ import annotations

import json
import os
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from shared.models import TERMINAL_STATUSES, SessionStatus

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
    ) -> None:
        self._api_key = api_key or os.environ["DEVIN_API_KEY"]
        self._org_id = org_id or os.environ["DEVIN_ORG_ID"]
        self._base = f"{API_BASE}/organizations/{self._org_id}/sessions"
        self._headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

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
        return CreateSessionResult(
            session_id=data["session_id"],
            url=data["url"],
        )

    # -- get ----------------------------------------------------------------

    def get_session(self, session_id: str) -> SessionInfo:
        url = f"{self._base}/{session_id}"
        resp = httpx.get(url, headers=self._headers, timeout=30)
        resp.raise_for_status()
        return _parse_session_response(resp.json())


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
# Mock client — canned responses for demo findings
# ---------------------------------------------------------------------------

_MOCK_FIXTURES: dict[str, dict[str, Any]] = {
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
                    "mock past this, so a naive bump ships a latent runtime break"
                ),
            },
        ],
        "reasoning": (
            "Investigated the paramiko upgrade path. Version 5.x drops the "
            "deprecated DSSKey class that sshtunnel imports unconditionally. "
            "Until sshtunnel releases a compatible version, upgrading paramiko "
            "would introduce a runtime ImportError masked by test mocks."
        ),
        "tests_passed": None,
        "scan_clean_after": None,
        "risk_flagged": (
            "upgrading paramiko to 5.x removes DSSKey, which the transitive "
            "dep sshtunnel still references; existing tests mock past this, "
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


_UNKNOWN_FIXTURE: dict[str, Any] = {
    "finding_id": "finding-unknown",
    "finding_type": "sca",
    "identifier": "unknown",
    "action_taken": "declined",
    "status": "needs_review",
    "pr_url": None,
    "files_changed": [],
    "addressed": [],
    "skipped": [],
    "reasoning": "No matching fixture found for prompt.",
    "tests_passed": None,
    "scan_clean_after": None,
    "risk_flagged": None,
}


def _load_recording(key: str) -> dict[str, Any] | None:
    """Load a recorded session for replay, if available."""
    path = Path(os.getenv("RECORDINGS_DIR", "recordings")) / f"{key}.json"
    if path.is_file():
        try:
            with open(path) as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None
    return None


class MockDevinClient(BaseDevinClient):
    """Returns canned responses keyed by finding identifier (extracted from prompt).

    When ``recordings/<key>.json`` exists (written by a prior ``DEVIN_RECORD=1``
    run), the recorded structured output, ACUs, and PR list are used instead of
    the hardcoded fixture.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, dict[str, Any]] = {}

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
        session_id = f"devin-mock-{uuid.uuid4().hex[:12]}"
        url = f"https://app.devin.ai/sessions/{session_id}"

        key = self._find_key(prompt)
        recording = _load_recording(key) if key else None

        if recording and "structured_output" in recording:
            fixture = recording["structured_output"]
            acus = recording.get("acus_consumed", 1.5)
            prs = recording.get("pull_requests", [])
            url = recording.get("devin_url", url)
        else:
            fixture = _MOCK_FIXTURES.get(key, _UNKNOWN_FIXTURE) if key else _UNKNOWN_FIXTURE
            acus = 1.5
            prs = (
                [{"pr_url": fixture["pr_url"], "pr_state": "open"}]
                if fixture.get("pr_url")
                else []
            )

        self._sessions[session_id] = {
            "session_id": session_id,
            "status": SessionStatus.EXIT.value,
            "acus_consumed": acus,
            "pull_requests": prs,
            "structured_output": fixture,
            "tags": tags or [],
        }
        return CreateSessionResult(session_id=session_id, url=url)

    def get_session(self, session_id: str) -> SessionInfo:
        data = self._sessions.get(session_id)
        if data is None:
            raise KeyError(f"Mock session {session_id!r} not found")
        return _parse_session_response(data)

    @staticmethod
    def _find_key(prompt: str) -> str | None:
        """Extract the matching fixture key from the prompt."""
        prompt_lower = prompt.lower()
        for key in _MOCK_FIXTURES:
            if key.lower() in prompt_lower:
                return key
        return None

    @staticmethod
    def _match_fixture(prompt: str) -> dict[str, Any]:
        """Match a fixture by finding identifier in prompt (legacy helper)."""
        prompt_lower = prompt.lower()
        for key, fixture in _MOCK_FIXTURES.items():
            if key.lower() in prompt_lower:
                return fixture
        return dict(_UNKNOWN_FIXTURE)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def get_devin_client() -> BaseDevinClient:
    """Return the real or mock client based on the ``DEVIN_MOCK`` env var."""
    if os.getenv("DEVIN_MOCK", "").strip() == "1":
        return MockDevinClient()
    return DevinClient()
