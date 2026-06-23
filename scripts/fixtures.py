"""GitHub ``issues.labeled`` webhook payload fixtures for the 3 demo findings.

Each payload is parameterized so that the orchestrator's ``_parse_issue_to_finding``
function extracts the correct ``identifier``, ``finding_type``, and ``severity``.
"""

from __future__ import annotations

from typing import Any


def _webhook_payload(
    title: str,
    body: str,
    html_url: str,
    labels: list[str],
) -> dict[str, Any]:
    """Build a GitHub ``issues.labeled`` payload matching ``/webhook``'s parser."""
    return {
        "action": "labeled",
        "label": {"name": "devin-remediate"},
        "issue": {
            "title": title,
            "body": body,
            "labels": [{"name": n} for n in ["devin-remediate"] + labels],
            "html_url": html_url,
        },
    }


WEBHOOK_PAYLOADS: dict[str, dict[str, Any]] = {
    "paramiko": _webhook_payload(
        title="CVE-2023-48795 in paramiko \u2014 Terrapin attack",
        body=(
            "paramiko 3.5.1 has CVE-2023-48795.  Upgrading to >=3.5.0 is "
            "complicated because sshtunnel depends on the removed DSSKey."
        ),
        html_url="https://github.com/michaelszhu/superset/issues/201",
        labels=["sca", "high"],
    ),
    "PyJWT": _webhook_payload(
        title="CVE-2022-29217 in PyJWT \u2014 algorithm confusion",
        body=(
            "PyJWT before 2.4.0 allows algorithm confusion when the caller "
            "does not pass an explicit algorithms argument to jwt.decode()."
        ),
        html_url="https://github.com/michaelszhu/superset/issues/202",
        labels=["sca", "critical"],
    ),
    "hive-column-injection": _webhook_payload(
        title="hive-column-injection: SQL injection via unescaped column identifiers",
        body=(
            "HiveEngineSpec.where_latest_partition() passes unsanitized "
            "partition column names directly into sqlalchemy.Column()."
        ),
        html_url="https://github.com/michaelszhu/superset/issues/203",
        labels=["high"],
    ),
}
