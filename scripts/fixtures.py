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


# Static webhook payloads with placeholder issue URLs.
# Use ``build_webhook_payloads(issue_urls)`` to substitute real URLs from
# the scanner/issue-filer step.
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


# Metadata for building payloads dynamically when real issue URLs are known.
_WEBHOOK_SPECS: list[dict[str, Any]] = [
    {
        "identifier": "paramiko",
        "title": "CVE-2023-48795 in paramiko \u2014 Terrapin attack",
        "body": (
            "paramiko 3.5.1 has CVE-2023-48795.  Upgrading to >=3.5.0 is "
            "complicated because sshtunnel depends on the removed DSSKey."
        ),
        "labels": ["sca", "high"],
    },
    {
        "identifier": "PyJWT",
        "title": "CVE-2022-29217 in PyJWT \u2014 algorithm confusion",
        "body": (
            "PyJWT before 2.4.0 allows algorithm confusion when the caller "
            "does not pass an explicit algorithms argument to jwt.decode()."
        ),
        "labels": ["sca", "critical"],
    },
    {
        "identifier": "hive-column-injection",
        "title": "hive-column-injection: SQL injection via unescaped column identifiers",
        "body": (
            "HiveEngineSpec.where_latest_partition() passes unsanitized "
            "partition column names directly into sqlalchemy.Column()."
        ),
        "labels": ["high"],
    },
]


def build_webhook_payloads(
    issue_urls: dict[str, str],
) -> dict[str, dict[str, Any]]:
    """Build webhook payloads substituting real issue URLs.

    ``issue_urls`` maps finding identifier → GitHub issue URL.
    Falls back to a placeholder URL if an identifier is missing.
    """
    payloads: dict[str, dict[str, Any]] = {}
    for spec in _WEBHOOK_SPECS:
        ident = spec["identifier"]
        url = issue_urls.get(ident, WEBHOOK_PAYLOADS[ident]["issue"]["html_url"])
        payloads[ident] = _webhook_payload(
            title=spec["title"],
            body=spec["body"],
            html_url=url,
            labels=spec["labels"],
        )
    return payloads
