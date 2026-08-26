# Playbooks — SOAR response orchestration

This directory holds the SOAR (Security Orchestration, Automation, and Response) layer of the architecture from §4.3 of the proposal. It has two parts:

| Subdir | Purpose |
|---|---|
| `shuffle_sim/` | Local PP1 Python simulator that stands in for a real Shuffle workflow runner. Receives decisions pushed from the engine, runs the matching playbook, records every step in an action log. Read by the dashboard. |
| `shuffle_export/` | Architectural artifact: representative Shuffle workflow JSON exports documenting how the **real** Shuffle workflows would be wired in PP2. Not executable for PP1 — Shuffle is not running. |

## Why a Python sim instead of a real Shuffle workflow for PP1

Real Shuffle workflows are visual graphs built in Shuffle's web UI. Demoing them means screen-recording a browser, which fights against the project's terminal/SOC-console aesthetic. The Python sim:

- runs anywhere (no Shuffle infrastructure required for the demo)
- prints clean log lines that read beautifully on screen
- can be smoke-tested with `pytest`
- exposes an HTTP API the dashboard can poll directly

Same stubbing philosophy as the Day 7 Wazuh wiring: stub the runner side, build the integration shape that PP2 can plug into. The exported workflow JSON in `shuffle_export/` is the bridge to that PP2 work.

## Workflows

| Workflow | Trigger (engine action) | What it records |
|---|---|---|
| `monitored_mode` | `monitored_mode` (Tier 2) | The three §4.3 components: deep telemetry trigger, shadow auditing trigger, zero-interference assertion |
| `tier3_dispatch` | `await_clinician_approval` (Tier 3) | All three Monitored Mode components **first** (asset is contained immediately) **then** clinician dispatch. Phase B (clinician approve/deny) is recorded via `POST /clinician-decision` on the sim. |
| `tier1_enforcement` (marker) | `log_only` / `block_port` / `isolate_host` | Single marker entry — Tier 1 actions are executed by downstream enforcement; the sim just records that the decision was seen. |

## Run the sim locally

```bash
cd playbooks/shuffle_sim
pip install -r requirements.txt          # one-time
uvicorn server:app --reload --port 8002
```

Then visit `http://localhost:8002/docs` for the OpenAPI schema.

For the engine to push decisions to the sim, set `SHUFFLE_WEBHOOK_URL` before starting the engine:

```bash
export SHUFFLE_WEBHOOK_URL=http://localhost:8002/playbook/run
cd engine && uvicorn src.main:app --reload --port 8000
```

If `SHUFFLE_WEBHOOK_URL` is not set, the engine works exactly as before (no push). The dashboard's "Shuffle Playbook Actions" panel will show "Shuffle sim not reachable" when this happens.

## Tests

```bash
cd playbooks/shuffle_sim
python -m pytest tests/ -v
```

## PP2 path

When migrating to a real Shuffle deployment:

1. Import `shuffle_export/tier3_dispatch.workflow.json` and `shuffle_export/monitored_mode.workflow.json` into Shuffle.
2. Configure the apps referenced in the workflows (`twilio`, `wazuh`, `shadow_audit`) with real credentials.
3. Point the engine's `SHUFFLE_WEBHOOK_URL` at the imported workflow's webhook URL.
4. Retire the Python sim — same engine contract, no other changes needed.
