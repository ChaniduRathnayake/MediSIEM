# Shuffle SOAR simulator

Local PP1 stand-in for a real Shuffle workflow runner.

## What it does

When the decision engine emits a Decision (typically by way of `POST /decide`), it can push that Decision to a webhook. This service is what receives that webhook for the local demo. It routes each Decision to the matching workflow module:

| Decision action | Workflow that runs |
|---|---|
| `monitored_mode` | `workflows.monitored_mode.run()` — records the three §4.3 components (deep telemetry, shadow auditing, zero-interference assertion) |
| `await_clinician_approval` | `workflows.tier3_dispatch.run()` — runs `monitored_mode` first (asset is contained immediately), then dispatches a clinician approval request |
| `log_only` / `block_port` / `isolate_host` | Records a single marker entry — Tier 1 enforcement is downstream of the sim |

Every step is appended to a shared **action log** (JSONL on disk + an in-memory ring) which the dashboard polls to render the "Shuffle Playbook Actions" panel under each decision.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness probe + sim metadata |
| POST | `/playbook/run` | Receive a Decision, run the matching workflow |
| GET | `/actions` | Recent actions, newest first |
| GET | `/actions/by-decision?decision_id=…` | All actions for a specific decision, oldest first |
| POST | `/clinician-decision` | Phase B: clinician approves/denies a Tier 3 request. Records the playbook-side action AND calls back into the engine's `/clinician-decision` to seal the audit log. |

## Run

```bash
cd playbooks/shuffle_sim
pip install -r requirements.txt
uvicorn server:app --reload --port 8002
```

OpenAPI schema at `http://localhost:8002/docs`.

## Layout

```
shuffle_sim/
├── server.py                # FastAPI app + routing
├── action_log.py            # Append-only JSONL + in-memory ring
├── workflows/
│   ├── monitored_mode.py    # 3-component Tier 2 workflow
│   └── tier3_dispatch.py    # Tier 3 dispatch + Phase B recorder
├── data/                    # action_log.jsonl lives here
└── tests/                   # pytest, no FastAPI required for action_log + workflow tests
```

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `ENGINE_URL` | `http://localhost:8000` | Where the engine lives — used for the Phase B callback to `/clinician-decision` |
| `CLINICIAN_ENDPOINT` | `https://clinician-pager.example/internal/notify` | Decorative — the URL that's logged in the `clinician_dispatch` action's `extra` field. PP2 replaces this with a real notification service. |
| `SHUFFLE_ACTION_LOG_PATH` | `data/action_log.jsonl` | Where the action log is persisted |
