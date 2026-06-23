"""Central configuration — reads from environment variables."""

from __future__ import annotations

import os


def get(key: str, default: str | None = None) -> str:
    value = os.getenv(key, default)
    if value is None:
        raise RuntimeError(f"Required environment variable {key!r} is not set")
    return value


DEVIN_API_KEY = lambda: get("DEVIN_API_KEY")  # noqa: E731
DEVIN_ORG_ID = lambda: get("DEVIN_ORG_ID")  # noqa: E731
DEVIN_MOCK = lambda: os.getenv("DEVIN_MOCK", "").strip() == "1"  # noqa: E731
PLAYBOOK_ID = lambda: get("PLAYBOOK_ID", "")  # noqa: E731
MAX_CONCURRENCY = lambda: int(get("MAX_CONCURRENCY", "3"))  # noqa: E731
MAX_ACU_LIMIT = lambda: int(get("MAX_ACU_LIMIT", "10"))  # noqa: E731
GITHUB_TOKEN = lambda: get("GITHUB_TOKEN", "")  # noqa: E731
SUPERSET_FORK_REPO = lambda: get("SUPERSET_FORK_REPO", "michaelszhu/superset")  # noqa: E731
DB_PATH = lambda: get("REMEDIATION_DB_PATH", "remediation.db")  # noqa: E731
