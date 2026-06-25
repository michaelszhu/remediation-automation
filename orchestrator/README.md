# Orchestrator

FastAPI service that dispatches security findings to Devin for automated
remediation and tracks session results. This is a **dumb dispatcher** — all
remediation logic lives in the Devin Playbook (referenced by `PLAYBOOK_ID`).

## Endpoints

### `GET /healthz`

Returns `{"status": "ok"}`. Use for liveness probes.

### `POST /webhook`

Receives GitHub `issues.labeled` webhook events. When the label is
`devin-remediate`, parses the issue into a `Finding` and dispatches a Devin
session in the background.

**Request body**: raw GitHub webhook payload.

**Response**:
```json
{"status": "dispatched", "finding_id": "finding-...", "identifier": "PyJWT"}
```

Ignored events (wrong label/action) return:
```json
{"status": "ignored", "reason": "not a devin-remediate label event"}
```

### `POST /run-batch`

Manual trigger: loads all findings from the database and dispatches each.
Returns immediately; processing runs in the background.

**Response**:
```json
{"status": "dispatching", "count": 8}
```

## Dispatch Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  POST /webhook or POST /run-batch                               │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. Parse Finding from issue payload                            │
│     (finding_type, identifier, severity, source_issue_url)      │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. Acquire concurrency semaphore (MAX_CONCURRENCY)             │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. Build prompt from PARAMETERIZED template                    │
│     (finding_type, identifier, title, severity, issue URL)      │
│     — NO finding-specific logic hardcoded                       │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. Create Devin session via shared.devin.get_devin_client()    │
│     - prompt = rendered template                                │
│     - repos = [SUPERSET_FORK_REPO]                              │
│     - playbook_id = PLAYBOOK_ID                                 │
│     - tags = remediation_tags(finding_type)                     │
│     - structured_output_schema = REMEDIATION_OUTPUT_SCHEMA      │
│     - structured_output_required = true                         │
│     - max_acu_limit = MAX_ACU_LIMIT                             │
│     - idempotent = true (via title-based dedup)                 │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. Persist SessionRecord (status=running) via shared.db        │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  6. Poll until terminal (exit/error/suspended)                  │
│     - Timeout → mark as failed, don't crash                     │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  7. Update SessionRecord with:                                  │
│     - status, acus_consumed, pull_requests                      │
│     - parsed structured_output (action_taken, pr_url, etc.)     │
└─────────────────────────────────────────────────────────────────┘
```

## Configuration

| Variable             | Default                | Description                          |
|----------------------|------------------------|--------------------------------------|
| `DEVIN_REPLAY`       | `0`                    | Set to `1` for replay mode           |
| `PLAYBOOK_ID`        | —                      | Devin playbook for remediation       |
| `MAX_CONCURRENCY`    | `3`                    | Max parallel Devin sessions          |
| `MAX_ACU_LIMIT`      | `10`                   | ACU budget per session               |
| `SUPERSET_FORK_REPO` | `michaelszhu/superset` | Target repo for remediation          |
| `REMEDIATION_DB_PATH`| `remediation.db`       | SQLite database path                 |

## Running Locally

```bash
# Replay mode — no API key needed
export DEVIN_REPLAY=1
export PLAYBOOK_ID=playbook-test-123
export PYTHONPATH=$(pwd)/..  # or project root
uvicorn orchestrator.main:app --reload --port 8000
```

## Testing with curl

```bash
# Health check
curl http://localhost:8000/healthz

# Simulate a GitHub webhook
curl -X POST http://localhost:8000/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "labeled",
    "label": {"name": "devin-remediate"},
    "issue": {
      "title": "CVE-2022-29217 in PyJWT",
      "body": "Algorithm confusion attack",
      "html_url": "https://github.com/michaelszhu/superset/issues/99",
      "labels": [{"name": "devin-remediate"}, {"name": "high"}]
    }
  }'

# Batch dispatch all findings in DB
curl -X POST http://localhost:8000/run-batch
```
