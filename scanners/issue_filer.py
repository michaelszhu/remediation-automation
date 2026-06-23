"""Idempotent GitHub issue filer for security findings.

Given a list of ``Finding`` objects, creates one labeled GitHub issue per
finding on the target fork repo.  Uses a deterministic fingerprint embedded in
the issue body so that re-running the filer never creates duplicates.

Requires:
    GITHUB_TOKEN  — PAT with ``repo`` scope (or fine-grained issues:write).
    SUPERSET_FORK_REPO — owner/repo slug (default ``michaelszhu/superset``).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.models import Finding, FindingType  # noqa: E402

ISSUE_LABEL = "devin-remediate"

# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------

def fingerprint(finding: Finding) -> str:
    """Stable fingerprint string embedded in every issue body."""
    return f"<!-- remediation-fingerprint:{finding.finding_id} -->"


# ---------------------------------------------------------------------------
# GitHub helpers
# ---------------------------------------------------------------------------

def _github_headers() -> dict[str, str]:
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise RuntimeError("GITHUB_TOKEN environment variable is required")
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _repo_slug() -> str:
    return os.environ.get("SUPERSET_FORK_REPO", "michaelszhu/superset")


def _ensure_label(client: httpx.Client, repo: str) -> None:
    """Create the ``devin-remediate`` label if it doesn't already exist."""
    url = f"https://api.github.com/repos/{repo}/labels"
    resp = client.get(url, params={"per_page": 100})
    existing = {l["name"] for l in resp.json()} if resp.status_code == 200 else set()
    if ISSUE_LABEL not in existing:
        client.post(url, json={
            "name": ISSUE_LABEL,
            "color": "d93f0b",
            "description": "Automated remediation finding",
        })


def _existing_fingerprints(client: httpx.Client, repo: str) -> set[str]:
    """Return the set of fingerprints already present in **open** issues."""
    fps: set[str] = set()
    page = 1
    while True:
        resp = client.get(
            f"https://api.github.com/repos/{repo}/issues",
            params={
                "labels": ISSUE_LABEL,
                "state": "open",
                "per_page": 100,
                "page": page,
            },
        )
        issues = resp.json()
        if not issues:
            break
        for issue in issues:
            body = issue.get("body") or ""
            # Extract fingerprint from body
            for line in body.splitlines():
                if line.strip().startswith("<!-- remediation-fingerprint:"):
                    fps.add(line.strip())
        page += 1
    return fps


def _issue_title(finding: Finding) -> str:
    ft = finding.finding_type.value if isinstance(finding.finding_type, FindingType) else finding.finding_type
    return f"[{ft.upper()}] {finding.title}"


def _issue_body(finding: Finding) -> str:
    ft = finding.finding_type.value if isinstance(finding.finding_type, FindingType) else finding.finding_type
    lines = [
        fingerprint(finding),
        "",
        f"**Finding ID:** `{finding.finding_id}`",
        f"**Type:** {ft.upper()}",
        f"**Identifier:** `{finding.identifier}`",
        f"**Severity:** {finding.severity}",
        "",
    ]

    raw = finding.raw_details
    if ft == "sca":
        lines.extend([
            "## SCA Details",
            f"- **Package:** `{raw.get('package', finding.identifier)}`",
            f"- **Installed version:** `{raw.get('installed_version', 'N/A')}`",
            f"- **Vulnerability:** `{raw.get('vuln_id', 'N/A')}`",
            f"- **Fix versions:** {', '.join(raw.get('fix_versions', [])) or 'N/A'}",
            "",
            raw.get("description", ""),
        ])
    elif ft == "sast":
        lines.extend([
            "## SAST Details",
            f"- **Rule:** `{raw.get('rule_id', finding.identifier)}`",
            f"- **File:** `{raw.get('path', 'N/A')}:{raw.get('start_line', '?')}`",
            "",
            raw.get("message", ""),
        ])
    else:
        lines.append(str(raw))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class IssueResult:
    """Result of filing a single finding as a GitHub issue."""
    finding: Finding
    issue_url: str | None
    status: str  # "created", "skipped", "failed"


def file_issues(findings: list[Finding]) -> tuple[int, int]:
    """File GitHub issues. Returns ``(filed_count, skipped_count)``."""
    results = file_issues_detailed(findings)
    filed = sum(1 for r in results if r.status == "created")
    skipped = sum(1 for r in results if r.status == "skipped")
    return filed, skipped


def file_issues_detailed(findings: list[Finding]) -> list[IssueResult]:
    """File GitHub issues and return detailed results with issue URLs."""
    repo = _repo_slug()
    headers = _github_headers()
    results: list[IssueResult] = []

    with httpx.Client(headers=headers, timeout=30) as client:
        _ensure_label(client, repo)
        existing = _existing_fingerprints(client, repo)

        for finding in findings:
            fp = fingerprint(finding)
            if fp in existing:
                # Try to find the existing issue URL
                url = _find_existing_issue_url(client, repo, fp)
                results.append(IssueResult(finding=finding, issue_url=url, status="skipped"))
                continue

            resp = client.post(
                f"https://api.github.com/repos/{repo}/issues",
                json={
                    "title": _issue_title(finding),
                    "body": _issue_body(finding),
                    "labels": [ISSUE_LABEL],
                },
            )
            if resp.status_code in (201, 200):
                issue_url = resp.json().get("html_url", "")
                print(f"  Created issue: {issue_url}")
                existing.add(fp)
                results.append(IssueResult(finding=finding, issue_url=issue_url, status="created"))
            else:
                print(
                    f"  Failed to create issue for {finding.finding_id}: "
                    f"{resp.status_code} {resp.text}",
                    file=sys.stderr,
                )
                results.append(IssueResult(finding=finding, issue_url=None, status="failed"))

    return results


def _find_existing_issue_url(
    client: httpx.Client, repo: str, fp: str,
) -> str | None:
    """Look up the URL of an existing issue by its fingerprint."""
    page = 1
    while True:
        resp = client.get(
            f"https://api.github.com/repos/{repo}/issues",
            params={
                "labels": ISSUE_LABEL,
                "state": "all",
                "per_page": 100,
                "page": page,
            },
        )
        issues = resp.json()
        if not issues:
            break
        for issue in issues:
            body = issue.get("body") or ""
            if fp in body:
                return issue.get("html_url")
        page += 1
    return None


def close_existing_issues(findings: list[Finding]) -> int:
    """Close all open issues whose body contains a fingerprint for any of
    the given findings.  Returns the number of issues closed."""
    repo = _repo_slug()
    headers = _github_headers()
    fps = {fingerprint(f) for f in findings}
    closed = 0

    with httpx.Client(headers=headers, timeout=30) as client:
        page = 1
        while True:
            resp = client.get(
                f"https://api.github.com/repos/{repo}/issues",
                params={
                    "labels": ISSUE_LABEL,
                    "state": "open",
                    "per_page": 100,
                    "page": page,
                },
            )
            issues = resp.json()
            if not issues:
                break
            for issue in issues:
                body = issue.get("body") or ""
                for fp in fps:
                    if fp in body:
                        number = issue["number"]
                        client.patch(
                            f"https://api.github.com/repos/{repo}/issues/{number}",
                            json={"state": "closed"},
                        )
                        print(f"  Closed issue #{number}: {issue.get('html_url', '')}")
                        closed += 1
                        break
            page += 1

    return closed
