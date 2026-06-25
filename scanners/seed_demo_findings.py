"""Seed six deterministic demo findings as GitHub issues.

Usage::

    export GITHUB_TOKEN=ghp_...
    export SUPERSET_FORK_REPO=michaelszhu/superset   # default
    python -m scanners.seed_demo_findings          # idempotent
    python -m scanners.seed_demo_findings --reset  # close all, re-seed

Creates labelled ``devin-remediate`` issues on the fork for:

1. **paramiko 3.5.1** — sshtunnel depends on the removed ``DSSKey``.
2. **PyJWT CVE-2022-29217** — algorithm confusion allowing forged tokens.
3. **Hive column-name SQL injection** — unsanitized identifiers in SQL.
4. **apispec pin** — pinned below latest, known test break on upgrade.
5. **DOMPurify advisory** — sanitizer-bypass advisory, frontend SCA.
6. **cancel_query SQL injection** — f-string interpolation in Postgres/Redshift.

Idempotent — safe to run repeatedly.  Use ``--reset`` to close existing
demo issues and create fresh ones.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.models import Finding, FindingType  # noqa: E402
from scanners.issue_filer import close_existing_issues, file_issues  # noqa: E402

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
    # 4. SCA — apispec pinned below latest
    Finding(
        finding_id="sca-apispec-upgrade",
        finding_type=FindingType.SCA,
        identifier="apispec-upgrade",
        title="Dependency upgrade: apispec pinned below latest (known test break)",
        severity="low",
        source_issue_url="",
        raw_details={
            "package": "apispec",
            "installed_version": "6.6.1",
            "vuln_id": "apispec-upgrade-pinned",
            "aliases": [],
            "fix_versions": ["6.7.0"],
            "description": (
                "apispec is pinned below 6.7 in the Superset requirements. "
                "A newer apispec version changed JSON-schema generation, which "
                "breaks a unit test — the pin has a maintainer note "
                "acknowledging it is a known, un-bumped issue. Flagged for "
                "upgrade."
            ),
        },
    ),
    # 5. SCA — DOMPurify frontend advisory
    Finding(
        finding_id="sca-dompurify-upgrade",
        finding_type=FindingType.SCA,
        identifier="dompurify-upgrade",
        title="Frontend dependency: DOMPurify flagged for sanitizer-bypass advisory",
        severity="moderate",
        source_issue_url="",
        raw_details={
            "package": "dompurify",
            "installed_version": "3.0.6",
            "vuln_id": "dompurify-sanitizer-bypass",
            "aliases": [],
            "fix_versions": ["3.1.0"],
            "description": (
                "DOMPurify in superset-frontend is below the patched version "
                "for a published advisory (HTML-sanitization bypass). Flagged "
                "by the frontend SCA scan for a version bump."
            ),
        },
    ),
    # 6. SAST — cancel_query SQL injection
    Finding(
        finding_id="sast-cancel-query-sql-injection",
        finding_type=FindingType.SAST,
        identifier="cancel-query-sql-injection",
        title="Possible SQL injection in cancel_query (Postgres/Redshift)",
        severity="medium",
        source_issue_url="",
        raw_details={
            "rule_id": "cancel-query-sql-injection",
            "path": "superset/db_engine_specs/postgres.py",
            "start_line": 112,
            "end_line": 112,
            "message": (
                "The SAST scan flagged an f-string interpolated into a SQL "
                "statement in the cancel_query path of the Postgres and "
                "Redshift engine specs, as a possible SQL injection."
            ),
            "metadata": {
                "cwe": ["CWE-89"],
                "confidence": "MEDIUM",
                "also_affects": [
                    "superset/db_engine_specs/redshift.py",
                ],
            },
        },
    ),
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Seed demo findings as GitHub issues on the Superset fork.",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Close all existing demo issues before re-seeding.",
    )
    args = parser.parse_args()

    count = len(DEMO_FINDINGS)

    if args.reset:
        print("Closing existing demo issues ...")
        closed = close_existing_issues(DEMO_FINDINGS)
        print(f"  Closed {closed} issue(s).")
        print()

    print(f"Seeding {count} demo findings as GitHub issues ...")
    filed, skipped = file_issues(DEMO_FINDINGS, force=args.reset)
    print(f"\nDone — filed {filed}, skipped {skipped} (already existed).")


if __name__ == "__main__":
    main()
