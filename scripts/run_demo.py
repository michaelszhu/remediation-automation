#!/usr/bin/env python3
"""Three-mode validation and demo script for the remediation automation stack.

Modes
-----
verify   Replay correctness suite (DEVIN_REPLAY=1)
record   Real-API capture run   (DEVIN_REPLAY=0  DEVIN_RECORD=1)
demo     Camera-ready demo      (replay or live — adapts to DEVIN_REPLAY)

Usage
-----
    python -m scripts.run_demo verify
    python -m scripts.run_demo record --yes
    python -m scripts.run_demo demo --pace 5

Environment
-----------
    ORCHESTRATOR_URL   default http://localhost:8000
    DASHBOARD_URL      default http://localhost:8001

Dependencies: stdlib + requests
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from pathlib import Path

import requests

from scripts.fixtures import WEBHOOK_PAYLOADS, build_webhook_payloads

# ---------------------------------------------------------------------------
# Config -- ports derived from docker-compose.yml defaults
# ---------------------------------------------------------------------------

ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://localhost:8000")
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://localhost:8001")
RECORDINGS_DIR = Path(os.getenv("RECORDINGS_DIR", "recordings"))

DEMO_IDENTIFIERS = (
    "paramiko", "PyJWT", "hive-column-injection",
    "apispec-upgrade", "dompurify-upgrade", "cancel-query-sql-injection",
    "yaml-unsafe-loader", "silenced-exceptions",
)

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

_W = 72


def banner(text: str, char: str = "=") -> None:
    print(f"\n{char * _W}")
    print(f"  {text}")
    print(char * _W)


def step(text: str) -> None:
    print(f"\n  >> {text}")


def result_line(label: str, ok: bool) -> None:
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {label}")


# ---------------------------------------------------------------------------
# HTTP helpers -- thin wrappers around requests
# ---------------------------------------------------------------------------


def _get(path: str, base: str | None = None, **kw) -> requests.Response:
    return requests.get(f"{base or ORCHESTRATOR_URL}{path}", timeout=10, **kw)


def _post(path: str, base: str | None = None, **kw) -> requests.Response:
    return requests.post(f"{base or ORCHESTRATOR_URL}{path}", timeout=10, **kw)


def healthz_ok() -> bool:
    try:
        r = _get("/healthz")
        return r.status_code == 200 and r.json().get("status") == "ok"
    except requests.ConnectionError:
        return False


def dashboard_responds() -> bool:
    try:
        r = _get("/", base=DASHBOARD_URL)
        return r.status_code == 200
    except requests.ConnectionError:
        return False


def clean_reset() -> dict:
    r = _post("/reset")
    r.raise_for_status()
    return r.json()


def seed_demo() -> dict:
    r = _post("/seed-demo")
    r.raise_for_status()
    return r.json()


def run_batch() -> dict:
    r = _post("/run-batch")
    r.raise_for_status()
    return r.json()


def post_webhook(payload: dict) -> dict:
    r = _post("/webhook", json=payload)
    r.raise_for_status()
    return r.json()


def get_sessions() -> list[dict]:
    r = _get("/sessions")
    r.raise_for_status()
    return r.json()["sessions"]


def get_dashboard_data() -> dict:
    r = _get("/api/data", base=DASHBOARD_URL)
    r.raise_for_status()
    return r.json()


def poll_terminal(
    expected: int,
    timeout: float = 120.0,
    interval: float = 2.0,
    live: bool = False,
) -> list[dict]:
    """Poll GET /sessions until *expected* sessions reach terminal state."""
    terminal_statuses = {"exit", "error", "suspended"}
    deadline = time.monotonic() + timeout
    seen: set[str] = set()
    while True:
        sessions = get_sessions()
        done = [s for s in sessions if s["status"] in terminal_statuses]
        if live:
            for s in done:
                sid = s["devin_session_id"]
                if sid not in seen:
                    seen.add(sid)
                    ident = s.get("identifier", "?")
                    action = s.get("action_taken", "?")
                    print(f"    {ident}: {s['status']} \u2014 {action}")
        if len(done) >= expected:
            return sessions
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"Only {len(done)}/{expected} sessions terminal after {timeout}s"
            )
        time.sleep(interval)


# ===================================================================
# MODE: verify
# ===================================================================


def _set_replay_config(defaults_only: bool) -> None:
    """Tell the orchestrator to use defaults-only or recordings."""
    try:
        _post("/replay-config", json={"defaults_only": defaults_only})
    except Exception:
        pass  # endpoint may not exist on older builds


def mode_verify() -> int:
    """Replay correctness gates (run with DEVIN_REPLAY=1)."""

    # Pre-flight
    if not healthz_ok():
        print("ERROR: Orchestrator not responding at", ORCHESTRATOR_URL)
        print("Start the stack with DEVIN_REPLAY=1 and retry:")
        print("  DEVIN_REPLAY=1 docker compose up --build")
        return 1

    # Use built-in default recordings for deterministic verification
    _set_replay_config(defaults_only=True)

    gate_count = 0

    # -- GATE 1 -- stack up -------------------------------------------------
    banner("GATE 1 \u2014 Stack Up")
    g1a = healthz_ok()
    result_line("Orchestrator /healthz", g1a)
    g1b = dashboard_responds()
    result_line(f"Dashboard responds at {DASHBOARD_URL}", g1b)
    if not (g1a and g1b):
        print("\n  GATE 1: FAIL \u2014 likely layer: docker-compose / networking")
        return 1
    print("\n  GATE 1: PASS")
    gate_count += 1

    # -- GATE 2 -- dispatch + classify --------------------------------------
    banner("GATE 2 \u2014 Dispatch + Classify")
    step("Clean-reset")
    clean_reset()
    step("Seed 3 demo findings")
    seed_demo()
    step("POST /run-batch")
    batch_resp = run_batch()
    print(f"    \u2192 {batch_resp}")
    step("Polling for 3 terminal sessions \u2026")
    sessions = poll_terminal(3)

    by_ident: dict[str, dict] = {
        s["identifier"]: s for s in sessions if s.get("identifier")
    }
    gate2_ok = True

    # --- hive-column-injection ---
    print("\n  \u2500\u2500 hive-column-injection \u2500\u2500")
    h = by_ident.get("hive-column-injection", {})
    so = h.get("structured_output") or {}
    for label, ok in [
        ("action_taken='fixed'", h.get("action_taken") == "fixed"),
        ("finding_type='sast'", h.get("finding_type") == "sast"),
        ("pr_url is set", bool(h.get("pr_url"))),
        ("scan_clean_after=true", so.get("scan_clean_after") is True),
        ("tests_passed=true", so.get("tests_passed") is True),
    ]:
        result_line(label, ok)
        gate2_ok = gate2_ok and ok

    # --- PyJWT ---
    print("\n  \u2500\u2500 PyJWT \u2500\u2500")
    p = by_ident.get("PyJWT", {})
    so = p.get("structured_output") or {}
    for label, ok in [
        ("action_taken='fixed'", p.get("action_taken") == "fixed"),
        ("pr_url is set", bool(p.get("pr_url"))),
        ("skipped is non-empty", bool(so.get("skipped"))),
    ]:
        result_line(label, ok)
        gate2_ok = gate2_ok and ok

    # --- paramiko ---
    print("\n  \u2500\u2500 paramiko \u2500\u2500")
    k = by_ident.get("paramiko", {})
    so = k.get("structured_output") or {}
    for label, ok in [
        ("action_taken='declined'", k.get("action_taken") == "declined"),
        ("pr_url is null", not k.get("pr_url")),
        ("risk_flagged is non-empty", bool(so.get("risk_flagged"))),
    ]:
        result_line(label, ok)
        gate2_ok = gate2_ok and ok

    # --- dashboard aggregates ---
    print("\n  \u2500\u2500 Dashboard Aggregates \u2500\u2500")
    dash = get_dashboard_data()
    m = dash["metrics"]
    for label, ok in [
        (f"total={m['total']} (expected 3)", m["total"] == 3),
        (f"fixed={m['fixed']} (expected 2)", m["fixed"] == 2),
        (f"declined={m['declined']} (expected 1)", m["declined"] == 1),
        (
            f"acus_per_fix={m['acus_per_fix']} (finite >0)",
            isinstance(m["acus_per_fix"], (int, float))
            and math.isfinite(m["acus_per_fix"])
            and m["acus_per_fix"] > 0,
        ),
    ]:
        result_line(label, ok)
        gate2_ok = gate2_ok and ok

    if not gate2_ok:
        print("\n  GATE 2: FAIL \u2014 likely layer: dispatch / classify / ReplayDevinClient")
        return 1
    print("\n  GATE 2: PASS")
    gate_count += 1

    # -- GATE 3 -- webhook path ---------------------------------------------
    banner("GATE 3 \u2014 Webhook Path")
    step("Clean-reset")
    clean_reset()
    webhook_count = len(WEBHOOK_PAYLOADS)
    for ident, payload in WEBHOOK_PAYLOADS.items():
        step(f"POST /webhook for {ident}")
        resp = post_webhook(payload)
        print(f"    \u2192 {resp}")

    step(f"Polling for {webhook_count} terminal sessions \u2026")
    sessions = poll_terminal(webhook_count)

    gate3_ok = True
    count = len(sessions)
    result_line(f"{count} sessions created (expected {webhook_count})", count == webhook_count)
    gate3_ok = gate3_ok and (count == webhook_count)

    fids = [s["finding_id"] for s in sessions]
    no_dups = len(fids) == len(set(fids))
    result_line("One event \u2192 one session \u2192 one row", no_dups)
    gate3_ok = gate3_ok and no_dups

    if not gate3_ok:
        print("\n  GATE 3: FAIL \u2014 likely layer: webhook handler / issue parser")
        return 1
    print("\n  GATE 3: PASS")
    gate_count += 1

    # -- GATE 4 -- idempotency + reset --------------------------------------
    banner("GATE 4 \u2014 Idempotency + Reset")
    step("Fire same paramiko webhook again (duplicate)")
    dup_payload = WEBHOOK_PAYLOADS["paramiko"]
    resp2 = post_webhook(dup_payload)
    print(f"    \u2192 duplicate fire: {resp2}")
    time.sleep(5)  # let background task settle

    sessions_after = get_sessions()
    paramiko_fid = resp2.get("finding_id")
    dup_count = sum(1 for s in sessions_after if s["finding_id"] == paramiko_fid)

    gate4_ok = True
    result_line(
        f"No duplicate sessions for paramiko (count={dup_count})",
        dup_count == 1,
    )
    gate4_ok = gate4_ok and (dup_count == 1)

    step("Clean-reset")
    clean_reset()
    sessions_zero = get_sessions()
    dash_zero = get_dashboard_data()["metrics"]
    zero_ok = len(sessions_zero) == 0 and dash_zero["total"] == 0
    result_line("System at zero after reset", zero_ok)
    gate4_ok = gate4_ok and zero_ok

    if not gate4_ok:
        print("\n  GATE 4: FAIL \u2014 likely layer: idempotency guard / reset endpoint")
        return 1
    print("\n  GATE 4: PASS")
    gate_count += 1

    # -- summary ------------------------------------------------------------
    banner(f"ALL {gate_count} GATES PASSED", char="*")
    return 0


# ===================================================================
# MODE: record
# ===================================================================


def mode_record(yes: bool) -> int:
    """Real-API capture run (DEVIN_REPLAY=0  DEVIN_RECORD=1)."""

    if not healthz_ok():
        print("ERROR: Orchestrator not responding at", ORCHESTRATOR_URL)
        print("Start the stack with DEVIN_REPLAY=0 DEVIN_RECORD=1:")
        print("  DEVIN_REPLAY=0 DEVIN_RECORD=1 docker compose up --build")
        return 1

    banner("MODE: record")
    print("  WARNING: This mode consumes REAL ACUs and hits the live Devin API.")
    print("  Ensure DEVIN_REPLAY=0 and DEVIN_RECORD=1 are set in your .env / env.")
    if not yes:
        print("\n  Aborted \u2014 pass --yes to confirm.")
        print("  Usage:  python -m scripts.run_demo record --yes")
        return 1

    step("Clean-reset")
    clean_reset()

    # -- Step 1: Scanner files issues on GitHub -----------------------------
    issue_urls = _run_scanner_step(pace=1, fresh=True)
    payloads = build_webhook_payloads(issue_urls) if issue_urls else WEBHOOK_PAYLOADS

    # -- Step 2: Dispatch via webhooks (real Devin sessions) ----------------
    banner("Step 2 \u2014 Webhook triggers real Devin sessions")
    dispatched_count = 0
    for ident in DEMO_IDENTIFIERS:
        if ident not in payloads:
            continue
        payload = payloads[ident]
        step(f"Webhook for {ident}")
        resp = post_webhook(payload)
        print(f"    \u2192 {resp}")
        dispatched_count += 1

    step(f"Polling until all {dispatched_count} sessions reach terminal state \u2026")
    sessions = poll_terminal(dispatched_count, timeout=7200, interval=30, live=True)

    # -- confirm recordings -------------------------------------------------
    banner("Recording Check")
    by_ident: dict[str, dict] = {
        s["identifier"]: s for s in sessions if s.get("identifier")
    }
    all_recorded = True
    for ident in DEMO_IDENTIFIERS:
        path = RECORDINGS_DIR / f"{ident}.json"
        found = path.is_file()
        result_line(f"recordings/{ident}.json exists", found)
        if not found:
            all_recorded = False

    if not all_recorded:
        print("\n  FAIL: Some recordings are missing.")
        print("  Check that DEVIN_RECORD=1 is set and the recordings/ volume is mounted.")
        return 1

    # -- capture checklist --------------------------------------------------
    banner("CAPTURE CHECKLIST")
    for ident in DEMO_IDENTIFIERS:
        s = by_ident.get(ident, {})
        action = s.get("action_taken", "?")
        devin_url = s.get("devin_url", "\u2014")
        pr_url = s.get("pr_url")
        source_url = s.get("source_issue_url", "\u2014")
        github_issue = issue_urls.get(ident, source_url)

        print(f"\n  \u2500\u2500 {ident} ({action}) \u2500\u2500")
        print(f"    GitHub issue  : {github_issue}")
        print(f"    Devin session : {devin_url}")
        if pr_url:
            print(f"    PR URL        : {pr_url}")
        else:
            print("    PR URL        : declined \u2014 no PR")
        if action == "declined":
            print(f"    Decline issue : {source_url}")

    print(f"\n  Dashboard URL   : {DASHBOARD_URL}")
    print()
    return 0


# ===================================================================
# Scanner / issue-filing step (shared by demo + record)
# ===================================================================


def _run_scanner_step(pace: int = 2, fresh: bool = False) -> dict[str, str]:
    """Run the scanner and file GitHub issues for the 8 demo findings.

    Returns a mapping of identifier \u2192 issue URL.  If ``GITHUB_TOKEN``
    is not set, prints a simulated scanner and falls back to placeholder
    URLs from the static fixtures.

    When *fresh* is True, close existing demo issues first so new ones
    are always created.
    """
    banner("Step 1 \u2014 Security Scanner")

    github_token = os.environ.get("GITHUB_TOKEN", "")
    if not github_token:
        step("GITHUB_TOKEN not set \u2014 simulating scanner output")
        print("    (set GITHUB_TOKEN to file real issues on the fork)")
        for ident in DEMO_IDENTIFIERS:
            payload = WEBHOOK_PAYLOADS[ident]
            title = payload["issue"]["title"]
            print(f"\n    \u26a0  {title}")
            print(f"       issue: {payload['issue']['html_url']} (placeholder)")
            time.sleep(1)
        return {}  # empty \u2192 build_webhook_payloads falls back to static URLs

    # Real scanner: import and run the issue filer
    from scanners.seed_demo_findings import DEMO_FINDINGS
    from scanners.issue_filer import file_issues_detailed, close_existing_issues

    if fresh:
        step("Closing previous demo issues\u2026")
        closed = close_existing_issues(DEMO_FINDINGS)
        if closed:
            print(f"    Closed {closed} existing issue(s)")
        else:
            print("    No existing issues to close")

    step("Running scanner against target repository\u2026")
    issue_urls: dict[str, str] = {}

    results = file_issues_detailed(DEMO_FINDINGS, force=fresh)
    for r in results:
        ident = r.finding.identifier
        title = r.finding.title
        if r.status == "created":
            print(f"\n    \u26a0  {title}")
            print(f"       \u2192 Filed issue: {r.issue_url}")
        elif r.status == "skipped":
            print(f"\n    \u26a0  {title}")
            print(f"       \u2192 Issue already exists: {r.issue_url or '(url unknown)'}")
        else:
            print(f"\n    \u26a0  {title}")
            print(f"       \u2192 Failed to file issue")
        if r.issue_url:
            issue_urls[ident] = r.issue_url
        if pace > 0:
            time.sleep(pace)

    filed = sum(1 for r in results if r.status == "created")
    skipped = sum(1 for r in results if r.status == "skipped")
    print(f"\n    Scanner complete: {filed} new issues filed, {skipped} already existed")
    return issue_urls


# ===================================================================
# MODE: demo
# ===================================================================


def mode_demo(pace: int, fresh: bool = False) -> int:
    """Camera-ready demo — works in both replay and live mode.

    Replay (DEVIN_REPLAY=1): instant results from pre-recorded outcomes.
    Live   (DEVIN_REPLAY=0): real Devin sessions, dashboard populates
    as sessions complete.
    """

    if not healthz_ok():
        print("ERROR: Orchestrator not responding at", ORCHESTRATOR_URL)
        print("Start the stack first:")
        print("  docker compose up --build -d")
        return 1

    is_replay = os.getenv("DEVIN_REPLAY", "0").strip() == "1"

    if is_replay:
        banner("MODE: demo (camera-ready \u2014 replay)")
        _set_replay_config(defaults_only=False)
    else:
        banner("MODE: demo (live \u2014 real Devin sessions)")
        print("  WARNING: Live mode creates real Devin sessions and consumes ACUs.")

    step("Clean-reset \u2014 dashboard starts EMPTY")
    clean_reset()

    # -- Step 1: Scanner files issues on GitHub -----------------------------
    issue_urls = _run_scanner_step(pace=pace, fresh=fresh)
    payloads = build_webhook_payloads(issue_urls) if issue_urls else WEBHOOK_PAYLOADS

    # -- Step 2: Labeled issues trigger webhook \u2192 Devin sessions -----------
    banner("Step 2 \u2014 Webhook triggers Devin remediation")
    print("  GitHub sends issues.labeled webhook to orchestrator")

    dispatched_count = 0
    for i, ident in enumerate(DEMO_IDENTIFIERS):
        if ident not in payloads:
            continue
        payload = payloads[ident]
        issue_url = payload["issue"]["html_url"]

        step(f"Webhook received for {ident}")
        print(f"    issue: {issue_url}")
        resp = post_webhook(payload)
        print(f"    \u2192 Devin session dispatched: {resp.get('finding_id', '')}")
        dispatched_count += 1

        if is_replay:
            # Replay is instant — show results immediately
            time.sleep(2)
            sessions = get_sessions()
            latest = [s for s in sessions if s.get("identifier") == ident]
            if latest:
                s = latest[-1]
                _print_session_result(ident, s)

        if i < len(DEMO_IDENTIFIERS) - 1:
            print(f"\n    (pausing {pace}s \u2026)")
            time.sleep(pace)

    # -- In live mode, poll until all sessions reach terminal state ----------
    if not is_replay and dispatched_count > 0:
        banner("Waiting for Devin sessions to complete")
        step(f"Polling until all {dispatched_count} sessions finish \u2026")
        print(f"    Dashboard ({DASHBOARD_URL}) updates live as sessions complete")
        sessions = poll_terminal(
            dispatched_count, timeout=7200, interval=30, live=True,
        )
        print(f"\n    All {dispatched_count} sessions complete.")

    # -- Step 3: Dashboard + final tally ------------------------------------
    banner("Step 3 \u2014 Dashboard & Results")
    dash = get_dashboard_data()
    m = dash["metrics"]
    print(f"  Fixed          : {m['fixed']}")
    print(f"  Declined       : {m['declined']}")
    print(f"  False Positive : {m.get('false_positive', 0)}")
    print(f"  Total Findings : {m['total']}")
    print(f"  Total ACUs     : {m['total_acus']}")
    print(f"  ACUs per Fix   : {m['acus_per_fix']}")
    print(f"\n  Dashboard: {DASHBOARD_URL}")
    return 0


def _print_session_result(ident: str, session: dict) -> None:
    """Print a single session's outcome."""
    action = session.get("action_taken") or "\u2026"
    label = {
        "fixed": "FIXED \u2014 PR opened",
        "declined": "DECLINED \u2014 risk flagged",
        "false_positive": "FALSE POSITIVE \u2014 no action needed",
    }.get(action, action.upper())
    pr = session.get("pr_url")
    print(f"    \u2192 {ident}: {label}")
    if pr:
        print(f"       PR: {pr}")


# ===================================================================
# CLI
# ===================================================================


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validation & demo script for the remediation automation stack.",
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    sub.add_parser("verify", help="Replay correctness gates (DEVIN_REPLAY=1)")

    rec = sub.add_parser(
        "record",
        help="Real-API capture run (DEVIN_REPLAY=0 DEVIN_RECORD=1)",
    )
    rec.add_argument(
        "--yes",
        action="store_true",
        help="Confirm you accept real ACU spend",
    )

    dem = sub.add_parser(
        "demo",
        help="Camera-ready demo (replay or live)",
    )
    dem.add_argument(
        "--pace",
        type=int,
        default=3,
        help="Seconds between dispatches (default 3)",
    )
    dem.add_argument(
        "--fresh",
        action="store_true",
        help="Close existing demo issues and create new ones",
    )

    args = parser.parse_args()

    if args.mode == "verify":
        return mode_verify()
    if args.mode == "record":
        return mode_record(args.yes)
    if args.mode == "demo":
        return mode_demo(args.pace, fresh=args.fresh)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
