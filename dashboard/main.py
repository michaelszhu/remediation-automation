"""Read-only observability dashboard for remediation automation.

Serves a single HTML page showing all findings, session outcomes,
and aggregate ROI metrics. Auto-refreshes every 5 seconds.

When DEVIN_MOCK=1, seeds the database with realistic demo data on startup.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DB_PATH = os.getenv("REMEDIATION_DB_PATH", "remediation.db")
IS_MOCK = os.getenv("DEVIN_MOCK", "").strip() == "1"

app = FastAPI(title="Remediation Dashboard", docs_url=None, redoc_url=None)

# ---------------------------------------------------------------------------
# DB helpers (read-only, uses shared schema directly)
# ---------------------------------------------------------------------------


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init_schema() -> None:
    """Ensure tables exist (same DDL as shared/db.py)."""
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id    TEXT PRIMARY KEY,
                finding_type  TEXT NOT NULL,
                identifier    TEXT NOT NULL,
                title         TEXT NOT NULL,
                severity      TEXT NOT NULL,
                source_issue_url TEXT NOT NULL,
                raw_details   TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS sessions (
                devin_session_id  TEXT PRIMARY KEY,
                finding_id        TEXT NOT NULL REFERENCES findings(finding_id),
                devin_url         TEXT NOT NULL,
                status            TEXT NOT NULL,
                action_taken      TEXT,
                pr_url            TEXT,
                acus_consumed     REAL NOT NULL DEFAULT 0.0,
                created_at        TEXT NOT NULL,
                updated_at        TEXT NOT NULL,
                structured_output TEXT NOT NULL DEFAULT '{}'
            );
        """)


def _query_dashboard_data() -> list[dict]:
    """Join findings + sessions into a flat list for display."""
    with _connect() as conn:
        rows = conn.execute("""
            SELECT
                f.finding_id,
                f.identifier,
                f.finding_type,
                f.title,
                f.severity,
                s.devin_session_id,
                s.status AS session_status,
                s.action_taken,
                s.pr_url,
                s.devin_url,
                s.acus_consumed,
                s.created_at,
                s.updated_at
            FROM findings f
            LEFT JOIN sessions s ON f.finding_id = s.finding_id
            ORDER BY s.created_at DESC
        """).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Mock data seeding
# ---------------------------------------------------------------------------

_MOCK_FINDINGS = [
    {
        "finding_id": "finding-sca-paramiko-001",
        "finding_type": "sca",
        "identifier": "paramiko",
        "title": "CVE-2023-48795 — Terrapin attack on paramiko",
        "severity": "high",
        "source_issue_url": "https://github.com/michaelszhu/superset/security/dependabot/1",
        "raw_details": json.dumps({"cve": "CVE-2023-48795"}),
    },
    {
        "finding_id": "finding-sca-pyjwt-002",
        "finding_type": "sca",
        "identifier": "PyJWT",
        "title": "CVE-2022-29217 — Key confusion in PyJWT",
        "severity": "critical",
        "source_issue_url": "https://github.com/michaelszhu/superset/security/dependabot/2",
        "raw_details": json.dumps({"cve": "CVE-2022-29217"}),
    },
    {
        "finding_id": "finding-sast-hive-003",
        "finding_type": "sast",
        "identifier": "hive-column-injection",
        "title": "SQL injection via unescaped column identifiers in Hive connector",
        "severity": "high",
        "source_issue_url": "https://github.com/michaelszhu/superset/issues/99",
        "raw_details": json.dumps({"rule": "hive-column-injection"}),
    },
    {
        "finding_id": "finding-sca-requests-004",
        "finding_type": "sca",
        "identifier": "requests",
        "title": "CVE-2024-35195 — Session fixation in requests",
        "severity": "medium",
        "source_issue_url": "https://github.com/michaelszhu/superset/security/dependabot/4",
        "raw_details": json.dumps({"cve": "CVE-2024-35195"}),
    },
    {
        "finding_id": "finding-sast-xss-005",
        "finding_type": "sast",
        "identifier": "react-dangerouslySetInnerHTML",
        "title": "XSS via unescaped user input in dashboard title render",
        "severity": "medium",
        "source_issue_url": "https://github.com/michaelszhu/superset/issues/100",
        "raw_details": json.dumps({"rule": "react-dangerouslySetInnerHTML"}),
    },
]

_MOCK_SESSIONS = [
    {
        "devin_session_id": "session-aaa-111",
        "finding_id": "finding-sca-paramiko-001",
        "devin_url": "https://app.devin.ai/sessions/aaa111",
        "status": "exit",
        "action_taken": "declined",
        "pr_url": None,
        "acus_consumed": 4.2,
        "created_at": "2026-06-22T10:00:00+00:00",
        "updated_at": "2026-06-22T10:12:00+00:00",
        "structured_output": json.dumps({
            "reasoning": "sshtunnel depends on removed DSSKey — upgrade breaks transitive dep",
            "risk_flagged": "sshtunnel depends on removed DSSKey",
        }),
    },
    {
        "devin_session_id": "session-bbb-222",
        "finding_id": "finding-sca-pyjwt-002",
        "devin_url": "https://app.devin.ai/sessions/bbb222",
        "status": "exit",
        "action_taken": "fixed",
        "pr_url": "https://github.com/michaelszhu/superset/pull/42",
        "acus_consumed": 6.8,
        "created_at": "2026-06-22T10:05:00+00:00",
        "updated_at": "2026-06-22T10:25:00+00:00",
        "structured_output": json.dumps({
            "reasoning": "Bumped PyJWT >=2.4.0, ran tests, all green.",
        }),
    },
    {
        "devin_session_id": "session-ccc-333",
        "finding_id": "finding-sast-hive-003",
        "devin_url": "https://app.devin.ai/sessions/ccc333",
        "status": "exit",
        "action_taken": "fixed",
        "pr_url": "https://github.com/michaelszhu/superset/pull/43",
        "acus_consumed": 8.1,
        "created_at": "2026-06-22T11:00:00+00:00",
        "updated_at": "2026-06-22T11:30:00+00:00",
        "structured_output": json.dumps({
            "reasoning": "Escaped column identifiers using backtick quoting in Hive connector.",
        }),
    },
    {
        "devin_session_id": "session-ddd-444",
        "finding_id": "finding-sca-requests-004",
        "devin_url": "https://app.devin.ai/sessions/ddd444",
        "status": "exit",
        "action_taken": "false_positive",
        "pr_url": None,
        "acus_consumed": 2.5,
        "created_at": "2026-06-22T12:00:00+00:00",
        "updated_at": "2026-06-22T12:08:00+00:00",
        "structured_output": json.dumps({
            "reasoning": "Session fixation CVE only applies to cookies with verify=False — this codebase always uses verify=True.",
        }),
    },
    {
        "devin_session_id": "session-eee-555",
        "finding_id": "finding-sast-xss-005",
        "devin_url": "https://app.devin.ai/sessions/eee555",
        "status": "error",
        "action_taken": None,
        "pr_url": None,
        "acus_consumed": 3.0,
        "created_at": "2026-06-22T13:00:00+00:00",
        "updated_at": "2026-06-22T13:10:00+00:00",
        "structured_output": json.dumps({
            "reasoning": "Session errored before completing analysis.",
        }),
    },
]


def _seed_mock_data() -> None:
    """Insert mock data if the DB is empty (idempotent)."""
    with _connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        if count > 0:
            return
        for f in _MOCK_FINDINGS:
            conn.execute(
                """INSERT OR IGNORE INTO findings
                   (finding_id, finding_type, identifier, title, severity, source_issue_url, raw_details)
                   VALUES (:finding_id, :finding_type, :identifier, :title, :severity, :source_issue_url, :raw_details)""",
                f,
            )
        for s in _MOCK_SESSIONS:
            conn.execute(
                """INSERT OR IGNORE INTO sessions
                   (devin_session_id, finding_id, devin_url, status, action_taken, pr_url,
                    acus_consumed, created_at, updated_at, structured_output)
                   VALUES (:devin_session_id, :finding_id, :devin_url, :status, :action_taken, :pr_url,
                    :acus_consumed, :created_at, :updated_at, :structured_output)""",
                s,
            )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

@app.on_event("startup")
def _on_startup() -> None:
    _init_schema()
    if IS_MOCK:
        _seed_mock_data()


# ---------------------------------------------------------------------------
# API: JSON endpoint for programmatic access
# ---------------------------------------------------------------------------

@app.get("/api/data")
def api_data() -> dict:
    rows = _query_dashboard_data()
    return _compute_view(rows)


# ---------------------------------------------------------------------------
# Main HTML page
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    rows = _query_dashboard_data()
    view = _compute_view(rows)
    html = _render_html(view)
    return HTMLResponse(content=html)


def _compute_view(rows: list[dict]) -> dict:
    total = len(rows)
    fixed = sum(1 for r in rows if r["action_taken"] == "fixed")
    declined = sum(1 for r in rows if r["action_taken"] == "declined")
    false_positive = sum(1 for r in rows if r["action_taken"] == "false_positive")
    failed = sum(1 for r in rows if r["session_status"] == "error" or (r["action_taken"] is None and r["session_status"] in ("exit",)))
    in_progress = sum(1 for r in rows if r["session_status"] in ("new", "claimed", "running", "resuming"))
    total_acus = sum(r["acus_consumed"] or 0 for r in rows)
    acus_per_fix = (total_acus / fixed) if fixed > 0 else 0.0
    completed = fixed + declined + false_positive
    success_rate = (fixed / completed * 100) if completed > 0 else 0.0

    return {
        "rows": rows,
        "metrics": {
            "total": total,
            "fixed": fixed,
            "declined": declined,
            "false_positive": false_positive,
            "failed": failed,
            "in_progress": in_progress,
            "success_rate": round(success_rate, 1),
            "total_acus": round(total_acus, 1),
            "acus_per_fix": round(acus_per_fix, 1),
            "completed": completed,
        },
    }


def _render_html(view: dict) -> str:
    m = view["metrics"]
    rows_html = ""
    for r in view["rows"]:
        action = r["action_taken"] or "—"
        action_class = ""
        if action == "fixed":
            action_class = "action-fixed"
        elif action == "declined":
            action_class = "action-declined"
        elif action == "false_positive":
            action_class = "action-fp"

        pr_link = f'<a href="{r["pr_url"]}" target="_blank">{r["pr_url"]}</a>' if r["pr_url"] else "—"
        devin_link = f'<a href="{r["devin_url"]}" target="_blank">session</a>' if r["devin_url"] else "—"
        acus = f'{r["acus_consumed"]:.1f}' if r["acus_consumed"] else "—"

        rows_html += f"""
        <tr>
            <td class="mono">{r["identifier"]}</td>
            <td><span class="badge badge-{r["finding_type"]}">{r["finding_type"]}</span></td>
            <td><span class="badge badge-status-{r["session_status"] or 'pending'}">{r["session_status"] or "pending"}</span></td>
            <td><span class="action {action_class}">{action}</span></td>
            <td>{pr_link}</td>
            <td>{devin_link}</td>
            <td class="num">{acus}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>Remediation Dashboard</title>
<style>
:root {{
    --bg: #0f1419;
    --surface: #1a2332;
    --border: #2d3748;
    --text: #e2e8f0;
    --text-muted: #a0aec0;
    --green: #48bb78;
    --green-bg: #1a3a2a;
    --yellow: #ecc94b;
    --yellow-bg: #3a3520;
    --blue: #63b3ed;
    --blue-bg: #1a2a3a;
    --red: #fc8181;
    --red-bg: #3a1a1a;
    --purple: #b794f4;
    --accent: #4fd1c5;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 2rem;
    line-height: 1.5;
}}
h1 {{
    font-size: 1.5rem;
    font-weight: 600;
    margin-bottom: 0.25rem;
}}
.subtitle {{
    color: var(--text-muted);
    font-size: 0.85rem;
    margin-bottom: 2rem;
}}
.metrics-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
}}
.metric-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem;
    text-align: center;
}}
.metric-card.highlight {{
    border-color: var(--accent);
    background: linear-gradient(135deg, #0f2027, #1a3a3a);
}}
.metric-value {{
    font-size: 2rem;
    font-weight: 700;
    line-height: 1.2;
}}
.metric-value.highlight {{
    color: var(--accent);
    font-size: 2.5rem;
}}
.metric-label {{
    font-size: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: 0.25rem;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    background: var(--surface);
    border-radius: 8px;
    overflow: hidden;
    border: 1px solid var(--border);
}}
th, td {{
    padding: 0.75rem 1rem;
    text-align: left;
    border-bottom: 1px solid var(--border);
    font-size: 0.85rem;
}}
th {{
    background: #111820;
    color: var(--text-muted);
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.7rem;
    letter-spacing: 0.05em;
}}
tr:last-child td {{ border-bottom: none; }}
tr:hover {{ background: #1e2d3d; }}
.mono {{ font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.8rem; }}
.num {{ text-align: right; font-family: 'SF Mono', monospace; }}
a {{ color: var(--blue); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.badge {{
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
}}
.badge-sca {{ background: var(--blue-bg); color: var(--blue); }}
.badge-sast {{ background: #2a1a3a; color: var(--purple); }}
.badge-status-exit {{ background: var(--green-bg); color: var(--green); }}
.badge-status-error {{ background: var(--red-bg); color: var(--red); }}
.badge-status-running {{ background: var(--yellow-bg); color: var(--yellow); }}
.badge-status-new, .badge-status-claimed, .badge-status-resuming {{
    background: var(--yellow-bg); color: var(--yellow);
}}
.badge-status-pending {{ background: #2d3748; color: var(--text-muted); }}
.action {{
    font-weight: 600;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
}}
.action-fixed {{ background: var(--green-bg); color: var(--green); }}
.action-declined {{ background: var(--yellow-bg); color: var(--yellow); }}
.action-fp {{ background: var(--blue-bg); color: var(--blue); }}
.refresh-note {{
    text-align: center;
    color: var(--text-muted);
    font-size: 0.75rem;
    margin-top: 1.5rem;
}}
</style>
</head>
<body>
<h1>Remediation Automation</h1>
<p class="subtitle">Read-only observability dashboard &mdash; auto-refreshes every 5s</p>

<div class="metrics-grid">
    <div class="metric-card highlight">
        <div class="metric-value highlight">{m["acus_per_fix"]}</div>
        <div class="metric-label">ACUs per Fix</div>
    </div>
    <div class="metric-card">
        <div class="metric-value">{m["total_acus"]}</div>
        <div class="metric-label">Total ACUs</div>
    </div>
    <div class="metric-card">
        <div class="metric-value">{m["success_rate"]}%</div>
        <div class="metric-label">Fix Rate</div>
    </div>
    <div class="metric-card">
        <div class="metric-value" style="color: var(--green)">{m["fixed"]}</div>
        <div class="metric-label">Fixed</div>
    </div>
    <div class="metric-card">
        <div class="metric-value" style="color: var(--yellow)">{m["declined"]}</div>
        <div class="metric-label">Declined</div>
    </div>
    <div class="metric-card">
        <div class="metric-value" style="color: var(--blue)">{m["false_positive"]}</div>
        <div class="metric-label">False Positive</div>
    </div>
    <div class="metric-card">
        <div class="metric-value" style="color: var(--red)">{m["failed"]}</div>
        <div class="metric-label">Failed</div>
    </div>
    <div class="metric-card">
        <div class="metric-value">{m["total"]}</div>
        <div class="metric-label">Total Findings</div>
    </div>
    <div class="metric-card">
        <div class="metric-value">{m["completed"]}</div>
        <div class="metric-label">Completed</div>
    </div>
</div>

<table>
<thead>
<tr>
    <th>Identifier</th>
    <th>Type</th>
    <th>Status</th>
    <th>Action</th>
    <th>PR</th>
    <th>Devin Session</th>
    <th style="text-align:right">ACUs</th>
</tr>
</thead>
<tbody>
{rows_html}
</tbody>
</table>

<p class="refresh-note">Auto-refreshes every 5 seconds &bull; {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")} UTC</p>
</body>
</html>"""
