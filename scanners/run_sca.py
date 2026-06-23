"""SCA scanner — runs pip-audit against the Superset fork's Python requirements.

Usage::

    export SUPERSET_FORK_REPO=michaelszhu/superset   # default
    python -m scanners.run_sca [--requirements PATH] [--file-issues]

Produces Finding objects with finding_type="sca".  When ``--file-issues`` is
passed, each Finding is filed as a GitHub issue on the fork via the shared
issue filer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

# Allow running with ``PYTHONPATH=.``
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.models import Finding, FindingType  # noqa: E402
from scanners.issue_filer import file_issues  # noqa: E402


# ---------------------------------------------------------------------------
# pip-audit runner
# ---------------------------------------------------------------------------

def _run_pip_audit(requirements_path: str) -> list[dict[str, Any]]:
    """Run ``pip-audit -r <path> --format json`` and return parsed results."""
    cmd = [
        sys.executable, "-m", "pip_audit",
        "-r", requirements_path,
        "--format", "json",
        "--desc",
        "--output", "-",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    # pip-audit exits 1 when it finds vulnerabilities — that's expected.
    if result.returncode not in (0, 1):
        print(f"pip-audit stderr:\n{result.stderr}", file=sys.stderr)
        raise RuntimeError(f"pip-audit failed with exit code {result.returncode}")

    if not result.stdout.strip():
        return []

    payload = json.loads(result.stdout)
    # pip-audit JSON output is {"dependencies": [...]}
    return payload.get("dependencies", [])


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

def _finding_id(pkg: str, vuln_id: str) -> str:
    """Deterministic finding ID from package + vulnerability alias."""
    digest = hashlib.sha256(f"sca:{pkg}:{vuln_id}".encode()).hexdigest()[:12]
    return f"sca-{pkg}-{digest}"


def normalize(raw_deps: list[dict[str, Any]]) -> list[Finding]:
    """Convert pip-audit JSON dependencies into Finding objects."""
    findings: list[Finding] = []
    for dep in raw_deps:
        pkg = dep.get("name", "unknown")
        version = dep.get("version", "unknown")
        for vuln in dep.get("vulns", []):
            aliases = vuln.get("aliases", [])
            vuln_id = vuln.get("id") or (aliases[0] if aliases else "unknown")
            fix_versions = vuln.get("fix_versions", [])
            description = vuln.get("description", "")

            title = f"{pkg}=={version}: {vuln_id}"
            severity = _infer_severity(description, vuln_id)
            finding = Finding(
                finding_id=_finding_id(pkg, vuln_id),
                finding_type=FindingType.SCA,
                identifier=pkg,
                title=title,
                severity=severity,
                source_issue_url="",
                raw_details={
                    "package": pkg,
                    "installed_version": version,
                    "vuln_id": vuln_id,
                    "aliases": aliases,
                    "fix_versions": fix_versions,
                    "description": description,
                },
            )
            findings.append(finding)
    return findings


def _infer_severity(description: str, vuln_id: str) -> str:
    """Best-effort severity from description text.  Falls back to 'medium'."""
    lower = description.lower()
    if "critical" in lower:
        return "critical"
    if "high" in lower:
        return "high"
    if "low" in lower:
        return "low"
    return "medium"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Run SCA scan via pip-audit")
    parser.add_argument(
        "--requirements",
        default=None,
        help="Path to requirements file (default: auto-detect in superset clone)",
    )
    parser.add_argument(
        "--superset-path",
        default=None,
        help="Path to a local superset clone",
    )
    parser.add_argument(
        "--file-issues",
        action="store_true",
        help="File GitHub issues for each finding on the fork",
    )
    args = parser.parse_args()

    req_path = args.requirements
    if req_path is None:
        superset = Path(args.superset_path) if args.superset_path else Path.cwd() / "superset"
        candidates = [
            superset / "requirements" / "base.txt",
            superset / "requirements.txt",
            superset / "setup.cfg",
        ]
        for c in candidates:
            if c.exists():
                req_path = str(c)
                break
        if req_path is None:
            print("Could not find a requirements file. Use --requirements.", file=sys.stderr)
            sys.exit(1)

    print(f"Running pip-audit against {req_path} ...")
    raw = _run_pip_audit(req_path)
    findings = normalize(raw)
    print(f"Found {len(findings)} SCA finding(s).")

    for f in findings:
        print(f"  [{f.severity.upper()}] {f.title}")

    if args.file_issues:
        filed, skipped = file_issues(findings)
        print(f"Filed {filed} issue(s), skipped {skipped} duplicate(s).")

    # Dump machine-readable output
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
