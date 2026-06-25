"""GitHub ``issues.labeled`` webhook payload fixtures for the 8 demo findings.

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
    "apispec-upgrade": _webhook_payload(
        title="Dependency upgrade: apispec pinned below latest (known test break)",
        body=(
            "apispec is pinned below 6.7 in the Superset requirements. "
            "A newer apispec version changed JSON-schema generation, which "
            "breaks a unit test. Flagged for upgrade."
        ),
        html_url="https://github.com/michaelszhu/superset/issues/204",
        labels=["sca", "low"],
    ),
    "dompurify-upgrade": _webhook_payload(
        title="Frontend dependency: DOMPurify flagged for sanitizer-bypass advisory",
        body=(
            "DOMPurify in superset-frontend is below the patched version "
            "for a published advisory (HTML-sanitization bypass). Flagged "
            "by the frontend SCA scan for a version bump."
        ),
        html_url="https://github.com/michaelszhu/superset/issues/205",
        labels=["sca", "moderate"],
    ),
    "cancel-query-sql-injection": _webhook_payload(
        title="cancel-query-sql-injection: Possible SQL injection in cancel_query",
        body=(
            "The SAST scan flagged an f-string interpolated into a SQL "
            "statement in the cancel_query path of the Postgres and "
            "Redshift engine specs, as a possible SQL injection."
        ),
        html_url="https://github.com/michaelszhu/superset/issues/206",
        labels=["medium"],
    ),
    "yaml-unsafe-loader": _webhook_payload(
        title="yaml-unsafe-loader: Unsafe YAML deserialization in load_configs_from_directory()",
        body=(
            "yaml.Loader allows arbitrary Python object instantiation via "
            "YAML constructor tags. load_configs_from_directory() uses "
            "yaml.Loader to read bundled example metadata. Flagged for "
            "replacement with yaml.SafeLoader."
        ),
        html_url="https://github.com/michaelszhu/superset/issues/207",
        labels=["high"],
    ),
    "silenced-exceptions": _webhook_payload(
        title="silenced-exceptions: Silently swallowed exceptions across core modules",
        body=(
            "Multiple exception handlers across the codebase catch errors "
            "and silently discard them. Flagged for adding "
            "logger.warning(..., exc_info=True) and narrowing broad "
            "except clauses where possible."
        ),
        html_url="https://github.com/michaelszhu/superset/issues/208",
        labels=["low"],
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
    {
        "identifier": "apispec-upgrade",
        "title": "Dependency upgrade: apispec pinned below latest (known test break)",
        "body": (
            "apispec is pinned below 6.7 in the Superset requirements. "
            "A newer apispec version changed JSON-schema generation, which "
            "breaks a unit test. Flagged for upgrade."
        ),
        "labels": ["sca", "low"],
    },
    {
        "identifier": "dompurify-upgrade",
        "title": "Frontend dependency: DOMPurify flagged for sanitizer-bypass advisory",
        "body": (
            "DOMPurify in superset-frontend is below the patched version "
            "for a published advisory (HTML-sanitization bypass). Flagged "
            "by the frontend SCA scan for a version bump."
        ),
        "labels": ["sca", "moderate"],
    },
    {
        "identifier": "cancel-query-sql-injection",
        "title": "cancel-query-sql-injection: Possible SQL injection in cancel_query",
        "body": (
            "The SAST scan flagged an f-string interpolated into a SQL "
            "statement in the cancel_query path of the Postgres and "
            "Redshift engine specs, as a possible SQL injection."
        ),
        "labels": ["medium"],
    },
    {
        "identifier": "yaml-unsafe-loader",
        "title": "yaml-unsafe-loader: Unsafe YAML deserialization in load_configs_from_directory()",
        "body": (
            "yaml.Loader allows arbitrary Python object instantiation via "
            "YAML constructor tags. load_configs_from_directory() uses "
            "yaml.Loader to read bundled example metadata. Flagged for "
            "replacement with yaml.SafeLoader."
        ),
        "labels": ["high"],
    },
    {
        "identifier": "silenced-exceptions",
        "title": "silenced-exceptions: Silently swallowed exceptions across core modules",
        "body": (
            "Multiple exception handlers across the codebase catch errors "
            "and silently discard them. Flagged for adding "
            "logger.warning(..., exc_info=True) and narrowing broad "
            "except clauses where possible."
        ),
        "labels": ["low"],
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
