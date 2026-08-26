# Decision Engine

The core of the Life-Critical-Aware framework. Receives enriched alerts and
classifies them into Tier 1, 2, or 3 response tiers using deterministic,
rule-based logic.

## Why rule-based, not ML?

Patient safety decisions must be explainable, auditable, and reproducible.
A black-box ML model that "probably" suggests Tier 2 is unacceptable when
the wrong call could disrupt life-sustaining care. Every decision the engine
makes can be traced to a specific rule and a specific value in the input
alert. See `src/decision/classifier.py` for the four rules.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness check |
| POST | `/decide` | Classify an enriched alert |
| GET | `/alerts/recent` | Recently classified alerts (in-memory ring buffer) |
| GET | `/audit` | Read the full audit log |
| GET | `/audit/verify` | Verify the audit log's hash chain |
| POST | `/clinician-decision` | Phase B of the Tier 3 two-phase flow — record a clinician's approve/deny response |
| GET | `/clinician-decisions` | Latest clinician follow-up per decision_id (read-side helper for the dashboard) |

`POST /decide` accepts an alert conforming to `docs/alert-schema.md` and
returns a `Decision` with the chosen tier, recommended action, rationale,
and which rule fired. If `SHUFFLE_WEBHOOK_URL` is set, the resulting
Decision is also pushed to that URL as a fire-and-forget background task.

Interactive API documentation is available at `http://localhost:8000/docs`
once the server is running.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `AUDIT_LOG_PATH` | `engine/data/audit_log.jsonl` | Where the hash-chained audit log is persisted |
| `RECENT_ALERTS_BUFFER_SIZE` | `50` | Size of the in-memory ring read by `/alerts/recent` |
| `SHUFFLE_WEBHOOK_URL` | *(unset)* | If set, every Decision is POSTed here as a background task. Unset = no push (fully backwards-compatible). |
| `SHUFFLE_PUSH_TIMEOUT` | `3.0` | Timeout (seconds) for the Shuffle push |

## Running locally

```bash
# From the engine/ directory
python -m venv .venv
source .venv/Scripts/activate    # Git Bash on Windows
# (on macOS/Linux: source .venv/bin/activate)

pip install -r requirements.txt

# Start the dev server with hot reload
uvicorn src.main:app --reload --port 8000
```

Then visit `http://localhost:8000/docs` to try out the API in the browser.

## Running the tests

```bash
# From the engine/ directory, with the virtualenv active
pytest -v
```

Tests cover:
- Every stub alert in `data/sample-alerts/` classifies into the expected tier
- Fail-safe rule (missing criticality → life-critical)
- Categorical-vs-numeric criticality resolution
- Extreme-threat detection (CVSS, severity, category)
- Audit log hash-chain integrity (including tamper detection)

## Architecture

```
src/
├── main.py              FastAPI app + endpoints
├── models/
│   ├── alert.py         Pydantic models for the alert schema
│   └── decision.py      Decision response model
├── decision/
│   ├── classifier.py    The four classification rules
│   └── rationale.py     Human-readable rationale builder
└── audit/
    └── logger.py        Hash-chained append-only audit log
```

## Status

✅ PP1-ready. Full Tier 1/2/3 classification, audit logging, REST API, tests, optional Shuffle push, two-phase Tier 3 flow with clinician callback.

Pending for PP2:
- Real Shuffle deployment (currently we push to a Python sim at
  `playbooks/shuffle_sim/`; same contract, swap the URL for PP2)
- Full clinician-facing approval UI with mobile notifications (currently
  Phase B is driven from the SOC dashboard's approve/deny buttons)
- Blockchain anchoring of audit log root hashes (currently hash-chain only)
