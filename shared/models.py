"""Data contract for the remediation orchestration system.

Defines the canonical data models, the structured-output JSON Schema that
every remediation Devin session must return, and tag conventions.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FindingType(str, enum.Enum):
    SCA = "sca"
    SAST = "sast"


class ActionTaken(str, enum.Enum):
    FIXED = "fixed"
    DECLINED = "declined"
    FALSE_POSITIVE = "false_positive"


class RemediationStatus(str, enum.Enum):
    SUCCESS = "success"
    FAILED = "failed"
    NEEDS_REVIEW = "needs_review"


class SessionStatus(str, enum.Enum):
    """Mirrors the Devin v3 session lifecycle."""
    NEW = "new"
    CLAIMED = "claimed"
    RUNNING = "running"
    EXIT = "exit"
    ERROR = "error"
    SUSPENDED = "suspended"
    RESUMING = "resuming"


TERMINAL_STATUSES = frozenset({
    SessionStatus.EXIT,
    SessionStatus.ERROR,
    SessionStatus.SUSPENDED,
})


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    finding_id: str
    finding_type: FindingType
    identifier: str  # package name (SCA) or scanner rule id (SAST)
    title: str
    severity: str
    source_issue_url: str
    raw_details: dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionRecord:
    finding_id: str
    devin_session_id: str
    devin_url: str
    status: SessionStatus
    action_taken: str | None = None
    pr_url: str | None = None
    acus_consumed: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    structured_output: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Structured-output JSON Schema (Draft 7)
# ---------------------------------------------------------------------------

REMEDIATION_OUTPUT_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "RemediationOutput",
    "description": "Schema that every remediation Devin session must return.",
    "type": "object",
    "required": [
        "finding_id",
        "finding_type",
        "identifier",
        "action_taken",
        "status",
        "files_changed",
        "addressed",
        "skipped",
        "reasoning",
    ],
    "additionalProperties": False,
    "properties": {
        "finding_id": {
            "type": "string",
            "description": "Unique identifier of the finding being remediated.",
        },
        "finding_type": {
            "type": "string",
            "enum": ["sca", "sast"],
        },
        "identifier": {
            "type": "string",
            "description": "Package name (SCA) or scanner rule id (SAST).",
        },
        "action_taken": {
            "type": "string",
            "enum": ["fixed", "declined", "false_positive"],
        },
        "status": {
            "type": "string",
            "enum": ["success", "failed", "needs_review"],
        },
        "pr_url": {
            "type": ["string", "null"],
            "description": "Pull-request URL, if one was created.",
        },
        "files_changed": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of files modified in the remediation.",
        },
        "addressed": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Specific issues/CVEs that were actually fixed.",
        },
        "skipped": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["item", "reason"],
                "additionalProperties": False,
                "properties": {
                    "item": {"type": "string"},
                    "reason": {"type": "string"},
                },
            },
            "description": "Issues deliberately NOT fixed, with reasoning.",
        },
        "reasoning": {
            "type": "string",
            "description": "Free-text explanation of approach and decisions.",
        },
        "tests_passed": {
            "type": ["boolean", "null"],
            "description": "Whether the test suite passed after changes.",
        },
        "scan_clean_after": {
            "type": ["boolean", "null"],
            "description": "Whether a re-scan shows the finding resolved.",
        },
        "risk_flagged": {
            "type": ["string", "null"],
            "description": "Description of residual risk, if any.",
        },
    },
}


# ---------------------------------------------------------------------------
# Tag convention
# ---------------------------------------------------------------------------

BASE_TAG = "devin-remediate"


def remediation_tags(finding_type: FindingType | str) -> list[str]:
    """Return the canonical tag list for a remediation session."""
    ft = finding_type.value if isinstance(finding_type, FindingType) else finding_type
    return [BASE_TAG, ft]
