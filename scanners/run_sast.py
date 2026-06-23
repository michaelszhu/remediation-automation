"""SAST scanner — runs Semgrep with security rulesets over the Superset fork.

Usage::

    python -m scanners.run_sast [--superset-path PATH] [--file-issues]

Scans the ``superset/`` backend source, excluding ``tests/``, ``migrations/``,
and ``examples/``.  Normalizes each hit into a Finding (finding_type="sast").
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.models import Finding, FindingType  # noqa: E402
from scanners.issue_filer import file_issues  # noqa: E402


# ---------------------------------------------------------------------------
# Semgrep runner
# ---------------------------------------------------------------------------

_EXCLUDE_DIRS = ["tests", "migrations", "examples"]


def _run_semgrep(target: str) -> list[dict[str, Any]]:
    """Run Semgrep with auto security config and return parsed results."""
    exclude_args: list[str] = []
    for d in _EXCLUDE_DIRS:
        exclude_args.extend(["--exclude", d])

    cmd = [
        "semgrep",
        "--config", "p/python",
        "--config", "p/security-audit",
        "--json",
        *exclude_args,
        target,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode not in (0, 1):
        print(f"semgrep stderr:\n{result.stderr}", file=sys.stderr)
        raise RuntimeError(f"semgrep failed with exit code {result.returncode}")

    if not result.stdout.strip():
        return []

    payload = json.loads(result.stdout)
    return payload.get("results", [])


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def _finding_id(rule_id: str, file_path: str, start_line: int) -> str:
    digest = hashlib.sha256(
        f"sast:{rule_id}:{file_path}:{start_line}".encode()
    ).hexdigest()[:12]
    return f"sast-{digest}"


def normalize(raw_results: list[dict[str, Any]], base_path: str = "") -> list[Finding]:
    """Convert Semgrep JSON results into Finding objects."""
    findings: list[Finding] = []
    for hit in raw_results:
        rule_id = hit.get("check_id", "unknown")
        path = hit.get("path", "")
        if base_path and path.startswith(base_path):
            path = path[len(base_path):].lstrip("/")
        start = hit.get("start", {})
        end = hit.get("end", {})
        line = start.get("line", 0)
        message = hit.get("extra", {}).get("message", "")
        sev_raw = hit.get("extra", {}).get("severity", "WARNING")
        severity = _SEVERITY_MAP.get(sev_raw, "medium")
        metadata = hit.get("extra", {}).get("metadata", {})

        finding = Finding(
            finding_id=_finding_id(rule_id, path, line),
            finding_type=FindingType.SAST,
            identifier=rule_id,
            title=f"{rule_id} in {path}:{line}",
            severity=severity,
            source_issue_url="",
            raw_details={
                "rule_id": rule_id,
                "path": path,
                "start_line": line,
                "end_line": end.get("line", line),
                "message": message,
                "metadata": metadata,
            },
        )
        findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Run SAST scan via Semgrep")
    parser.add_argument(
        "--superset-path",
        default=None,
        help="Path to a local superset clone (default: ./superset)",
    )
    parser.add_argument(
        "--file-issues",
        action="store_true",
        help="File GitHub issues for each finding on the fork",
    )
    args = parser.parse_args()

    superset = Path(args.superset_path) if args.superset_path else Path.cwd() / "superset"
    target = superset / "superset"
    if not target.is_dir():
        print(f"Target directory not found: {target}", file=sys.stderr)
        sys.exit(1)

    print(f"Running Semgrep against {target} ...")
    raw = _run_semgrep(str(target))
    findings = normalize(raw, base_path=str(superset) + "/")
    print(f"Found {len(findings)} SAST finding(s).")

    for f in findings:
        print(f"  [{f.severity.upper()}] {f.title}")

    if args.file_issues:
        filed, skipped = file_issues(findings)
        print(f"Filed {filed} issue(s), skipped {skipped} duplicate(s).")

    out = [
        {
            "finding_id": f.finding_id,
            "finding_type": f.finding_type.value,
            "identifier": f.identifier,
            "title": f.title,
            "severity": f.severity,
            "raw_details": f.raw_details,
        }
        for f in findings
    ]
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
