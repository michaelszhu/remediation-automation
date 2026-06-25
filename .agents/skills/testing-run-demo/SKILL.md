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
```

## Running the Stack (Docker — recommended)

The recommended way to run and test is via Docker. This avoids any local Python/dependency issues:

```bash
# Copy .env.example to .env (already has DEVIN_REPLAY=1)
cp .env.example .env

# Build and start
docker compose up --build -d

# Verify services are running
docker compose ps
```

**Important .env gotcha:** Docker's `.env` parser does NOT support inline comments. If you see env vars with unexpected values (e.g. `GITHUB_TOKEN=# PAT for...`), check that all comments in `.env` are on separate lines — not inline after values.

## Running the Stack (Local — alternative)

If you need to run locally without Docker:

```bash
source .venv/bin/activate  # or create: python -m venv .venv && pip install -r requirements.txt
export PYTHONPATH=$PWD
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

All commands below use the Docker approach. For local, drop the `docker compose exec orchestrator` prefix.

### Test 1: `verify` mode (shell-only, no recording needed)

```bash
docker compose exec orchestrator python -m scripts.run_demo verify
```

**Expected:** All 4 gates pass (35 `[PASS]` lines total), final output `ALL 4 GATES PASSED`, exit code 0.

**What each gate covers:**
- Gate 1: Service health (orchestrator + dashboard reachable via internal URL `http://dashboard:8001`)
- Gate 2: Full dispatch pipeline — seeds 8 findings, runs batch, checks per-finding structured output fields + dashboard aggregates
- Gate 3: Webhook path — sends `issues.labeled` payloads, verifies one-to-one event→session mapping
- Gate 4: Idempotency guard (duplicate webhook → no new session) + reset endpoint (system returns to zero)

**If Gate 1 fails (dashboard unreachable):** Check that `DASHBOARD_URL=http://dashboard:8001` is set in the orchestrator container's environment (should be in docker-compose.yml).

**If Gate 2 hangs (polling timeout):** Check orchestrator logs — likely `DEVIN_REPLAY=1` is not set and it's trying to hit the real API.

### Test 2: `demo` mode (browser + shell, record this)

1. Reset state first: `docker compose exec orchestrator python -c "import requests; requests.post('http://localhost:8000/reset')"`
2. Open dashboard at http://localhost:8001 — should show empty state (all zeros)
3. Run `docker compose exec orchestrator python -m scripts.run_demo demo --pace 3`
4. Dashboard auto-refreshes every 5s; watch it populate progressively
5. Final state: Fixed=6, False Positive=2, Total Findings=8, Completed=8, 8 table rows with correct badges

**Output assertions:**
- Contains "GITHUB_TOKEN not set — simulating scanner output" (proves empty token triggers simulated mode)
- Final line: `Dashboard (open in browser): http://localhost:8001` (NOT `http://dashboard:8001` — the script shows the user-facing URL)
- Tally: Fixed=6, Declined=0, False Positive=2, Total Findings=8
- ACU lines show: `Total ACUs     : 58.6 (estimated)` and `ACUs per Fix   : 9.8 (estimated)`

**Table assertions (dashboard):**
- paramiko → SCA / EXIT / false_positive / "—" (no PR)
- PyJWT → SCA / EXIT / false_positive / "—" (no PR)
- hive-column-injection → SAST / EXIT / fixed / PR link present
- apispec-upgrade → SCA / EXIT / fixed / PR link present
- dompurify-upgrade → SCA / EXIT / fixed / PR link present
- cancel-query-sql-injection → SAST / EXIT / fixed / PR link present
- yaml-unsafe-loader → SAST / EXIT / fixed / PR link present
- silenced-exceptions → SAST / EXIT / fixed / PR link present

**Metric assertions (dashboard):** ACUs per Fix (est.) = 9.8, Total ACUs (est.) = 58.6, Fix Rate = 75.0%, Fixed = 6, False Positive = 2

### Test 3: `record` mode safety guard (shell-only)

```bash
docker compose exec orchestrator python -m scripts.run_demo record  # no --yes
```

**Expected:** WARNING about real ACUs, "Aborted — pass --yes to confirm", exit code 1.

### Test 4: .env.example inline comment check (adversarial)

Verify Docker's .env parser isn't polluting values with comment text:

```bash
docker compose exec orchestrator env | grep -E "^(GITHUB_TOKEN|PLAYBOOK_ID|MAX_CONCURRENCY)="
```

**Expected:**
- `GITHUB_TOKEN=` (empty — NOT `GITHUB_TOKEN=# PAT for...`)
- `PLAYBOOK_ID=playbook-7548a6acecb2417e94cb7a1050ab11bd` (no trailing comment)
- `MAX_CONCURRENCY=3` (just the number)

### Test 5: Container networking (adversarial)

Verify the orchestrator can reach the dashboard via Docker's internal DNS:

```bash
docker compose exec orchestrator env | grep DASHBOARD_URL
docker compose exec orchestrator python -c "import requests; r = requests.get('http://dashboard:8001'); print(r.status_code)"
```

**Expected:**
- `DASHBOARD_URL=http://dashboard:8001`
- Status code: `200`

### Test 6: .dockerignore excludes sensitive files from image

Verify that `COPY . .` in the Dockerfile does NOT bake `.env`, `.git`, or non-runtime files into the image:

```bash
docker compose exec orchestrator ls /app/.env 2>&1      # Should: "No such file or directory"
docker compose exec orchestrator ls /app/.git 2>&1      # Should: "No such file or directory"
docker compose exec orchestrator ls /app/README.md 2>&1 # Should: "No such file or directory"
```

**Expected:** All three return "No such file or directory". If any exist, `.dockerignore` is misconfigured.

**Also check build context size** during `docker compose up --build`: the orchestrator context should be small (a few hundred KB, not multi-MB). If it's large, `.dockerignore` might be missing entries.

## Gotchas

- The `shared/devin.py` module uses `DEVIN_REPLAY` (not `DEVIN_MOCK`). If you see references to `DEVIN_MOCK` in code, that's stale and needs updating.
- The dashboard auto-refreshes every 5s via meta refresh. You may need to manually refresh (F5) if timing is tight during demo mode testing.
- The `--pace` flag in demo mode controls seconds between webhook dispatches. Use `--pace 3` for visible progressive population; `--pace 1` makes everything appear nearly simultaneously.
- If services were previously running with data, run `curl -X POST http://localhost:8000/reset` before testing to clear state.
- The script uses `requests` library — installed in the Docker image automatically.
- **Recording files vs defaults:** `run_demo.py` calls `_set_replay_config(defaults_only=False)` in verify mode so it loads actual `recordings/*.json` files. If you see gate 2 failing with wrong `action_taken` values, check that recording files exist and that `defaults_only=False` is set.
- **DASHBOARD_URL vs DASHBOARD_HOST_URL:** Inside the container, `DASHBOARD_URL=http://dashboard:8001` is used for HTTP requests (container-to-container). `DASHBOARD_HOST_URL` (defaults to `http://localhost:8001`) is what gets printed for users to open in their browser. If demo output shows the internal URL, check that the `DASHBOARD_HOST_URL` logic in `run_demo.py` is correct.
- **Docker .env inline comments:** Docker's `.env` parser treats everything after `=` as the value — including what looks like comments. Always put comments on separate lines in `.env` / `.env.example`. If env vars have unexpected values, this is the most likely cause.
- **ACU labels show "(estimated)":** The CLI output appends "(estimated)" to ACU values and the dashboard shows "(est.)" in metric labels. This clarifies that replay-mode ACU figures come from pre-recorded session data.
