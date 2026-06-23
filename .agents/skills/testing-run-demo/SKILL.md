---
name: testing-run-demo
description: Test the three-mode run_demo.py script (verify, record, demo) end-to-end against the local replay stack. Use when verifying changes to the demo script, orchestrator endpoints, or dashboard.
---

# Testing run_demo.py

## Devin Secrets Needed

None for replay testing. The replay stack (`DEVIN_REPLAY=1`) requires no API keys.

For `record` mode (real Devin API), you would need:
- `DEVIN_API_KEY` — Devin service-user Bearer token
- `DEVIN_ORG_ID` — Organization ID

## Prerequisites

```bash
cd /home/ubuntu/repos/remediation-automation
source .venv/bin/activate  # or create: python -m venv .venv && pip install -r requirements.txt
export PYTHONPATH=$PWD
```

## Running the Local Stack

The stack needs two services (orchestrator + dashboard) sharing a SQLite DB:

```bash
# Use a temp DB to avoid polluting any persistent state
export DEVIN_REPLAY=1
export REMEDIATION_DB_PATH=/tmp/test_remediation.db
python -c "from shared.db import init_db; init_db('/tmp/test_remediation.db')"

# Start services in separate shells
uvicorn orchestrator.main:app --host 0.0.0.0 --port 8000  # shell 1
uvicorn dashboard.main:app --host 0.0.0.0 --port 8001     # shell 2
```

**Important:** Both services MUST have the same `DEVIN_REPLAY=1` and `REMEDIATION_DB_PATH` env vars set, otherwise:
- Missing `DEVIN_REPLAY=1` on orchestrator → dispatch tries real Devin API → fails with `KeyError: 'DEVIN_API_KEY'`
- Mismatched DB paths → dashboard shows stale/empty data

## Testing Procedure

### Test 1: `verify` mode (shell-only, no recording needed)

```bash
python -m scripts.run_demo verify
```

**Expected:** All 4 gates pass (19 `[PASS]` lines total), final output `ALL 4 GATES PASSED`, exit code 0.

**What each gate covers:**
- Gate 1: Service health (orchestrator + dashboard reachable)
- Gate 2: Full dispatch pipeline — seeds 3 findings, runs batch, checks per-finding structured output fields + dashboard aggregates
- Gate 3: Webhook path — sends `issues.labeled` payloads, verifies one-to-one event→session mapping
- Gate 4: Idempotency guard (duplicate webhook → no new session) + reset endpoint (system returns to zero)

**If Gate 2 hangs (polling timeout):** Check orchestrator logs — likely `DEVIN_REPLAY=1` is not set and it's trying to hit the real API.

### Test 2: `demo` mode (browser + shell, record this)

1. Open dashboard at http://localhost:8001 — should show empty state (all zeros)
2. Run `python -m scripts.run_demo demo --pace 5`
3. Dashboard auto-refreshes every 5s; watch it populate progressively
4. Final state: Fixed=2, Declined=1, Total Findings=3, 3 table rows with correct badges

**Table assertions:**
- hive-column-injection → SAST / EXIT / fixed / PR link present
- PyJWT → SCA / EXIT / fixed / PR link present
- paramiko → SCA / EXIT / declined / "—" (no PR)

**Metric assertions:** ACUs per Fix=2.2, Total ACUs=4.5, Fix Rate=66.7%

### Test 3: `record` mode safety guard (shell-only)

```bash
python -m scripts.run_demo record  # no --yes
```

**Expected:** WARNING about real ACUs, "Aborted — pass --yes to confirm", exit code 1.

## Gotchas

- The `shared/devin.py` module uses `DEVIN_REPLAY` (not `DEVIN_MOCK`). If you see references to `DEVIN_MOCK` in code, that's stale and needs updating.
- The dashboard auto-refreshes every 5s via meta refresh. You may need to manually refresh (F5) if timing is tight during demo mode testing.
- The `--pace` flag in demo mode controls seconds between webhook dispatches. Use `--pace 5` or higher for visible progressive population; `--pace 1` makes everything appear nearly simultaneously.
- If services were previously running with data, run `curl -X POST http://localhost:8000/reset` before testing to clear state.
- The script uses `requests` library — make sure it's installed (`pip install -r requirements.txt`).
