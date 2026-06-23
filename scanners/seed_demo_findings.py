"""Seed exactly three deterministic demo findings as GitHub issues.

Usage::

    export GITHUB_TOKEN=ghp_...
    export SUPERSET_FORK_REPO=michaelszhu/superset   # default
    python -m scanners.seed_demo_findings

Creates labelled ``devin-remediate`` issues on the fork for:

1. **paramiko 3.5.1 → 3.5.0** — sshtunnel depends on the removed ``DSSKey``.
2. **PyJWT CVE-2022-29217** — algorithm confusion allowing forged tokens.
3. **Hive column-name SQL injection** — ``where_latest_partition`` passes
   unsanitized column names into ``Column()``.

Idempotent — safe to run repeatedly.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.models import Finding, FindingType  # noqa: E402
from scanners.issue_filer import file_issues  # noqa: E402

# ---------------------------------------------------------------------------
# Known-good demo findings
# ---------------------------------------------------------------------------

DEMO_FINDINGS: list[Finding] = [
    # 1. SCA — paramiko major-version gap
    Finding(
        finding_id="sca-paramiko-demo",
        finding_type=FindingType.SCA,
        identifier="paramiko",
        title="paramiko==3.5.1: dependency risk — sshtunnel relies on removed DSSKey",
        severity="high",
        source_issue_url="",
        raw_details={
            "package": "paramiko",
            "installed_version": "3.5.1",
            "vuln_id": "paramiko-dsskey-removal",
            "aliases": [],
            "fix_versions": ["3.5.0"],
            "description": (
                "paramiko ≥3.0 removed paramiko.DSSKey. The sshtunnel package "
                "still imports it, causing ImportError at runtime when SSH "
                "tunnels are used (e.g. connecting to databases behind "
                "bastion hosts). Pin paramiko<3 or patch sshtunnel."
            ),
        },
    ),
    # 2. SCA — PyJWT CVE
    Finding(
        finding_id="sca-pyjwt-cve-2022-29217",
        finding_type=FindingType.SCA,
        identifier="PyJWT",
        title="PyJWT==2.12.0: CVE-2022-29217 — algorithm confusion",
        severity="high",
        source_issue_url="https://nvd.nist.gov/vuln/detail/CVE-2022-29217",
        raw_details={
            "package": "PyJWT",
            "installed_version": "2.12.0",
            "vuln_id": "CVE-2022-29217",
            "aliases": ["GHSA-ffqj-6fqr-9h24"],
            "fix_versions": ["2.4.0"],
            "description": (
                "PyJWT before 2.4.0 allows algorithm confusion when the "
                "caller does not pass an explicit 'algorithms' argument to "
                "jwt.decode(). An attacker can forge tokens by exploiting "
                "HMAC/RSA confusion."
            ),
        },
    ),
    # 3. SAST — Hive column-name SQL injection
    Finding(
        finding_id="sast-hive-column-injection",
        finding_type=FindingType.SAST,
        identifier="hive-column-injection",
        title="hive-column-injection in superset/db_engine_specs/hive.py:473",
        severity="high",
        source_issue_url="",
        raw_details={
            "rule_id": "hive-column-injection",
            "path": "superset/db_engine_specs/hive.py",
            "start_line": 473,
            "end_line": 473,
            "message": (
                "HiveEngineSpec.where_latest_partition() passes unsanitized "
                "partition column names directly into sqlalchemy.Column(), "
                "which renders them as unquoted identifiers in the SQL text. "
                "A malicious partition column name could inject arbitrary SQL."
            ),
            "metadata": {
                "cwe": ["CWE-89"],
                "confidence": "MEDIUM",
            },
        },
    ),
]


def main() -> None:
    print("Seeding 3 demo findings as GitHub issues ...")
    filed, skipped = file_issues(DEMO_FINDINGS)
    print(f"Done — filed {filed}, skipped {skipped} (already existed).")


if __name__ == "__main__":
    main()
