# Running the PP1 Demo

End-to-end demo of the Life-Critical-Aware Incident Response Orchestration framework — Wazuh-shape alerts flowing through the enrichment shim, decision engine, audit log, Shuffle SOAR sim, and SOC dashboard, with clinician approve/deny closing the Tier 3 two-phase flow.

## One-time setup

(Already done if you've been developing locally. Documented here for fresh clones.)

```bash
# Decision engine
cd engine
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
deactivate

# Enrichment shim
cd ../enrichment
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
deactivate

# Shuffle SOAR sim
cd ../playbooks/shuffle_sim
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
deactivate

# Frontend dashboard
cd ../../frontend
npm install
```

## Starting everything

Open **four Git Bash terminals**, all in the repo root.

### Terminal 1 — Decision engine on `:8000`

The `SHUFFLE_WEBHOOK_URL` env var is what makes the engine push decisions to the sim — without it, the dashboard's Shuffle Playbook Actions panel will stay empty.

```bash
cd engine
source .venv/Scripts/activate
SHUFFLE_WEBHOOK_URL=http://localhost:8002/playbook/run uvicorn src.main:app --reload --port 8000
```

### Terminal 2 — Enrichment shim on `:8001`

```bash
cd enrichment
source .venv/Scripts/activate
uvicorn src.main:app --reload --port 8001
```

### Terminal 3 — Shuffle SOAR sim on `:8002`

```bash
cd playbooks/shuffle_sim
source .venv/Scripts/activate
uvicorn server:app --reload --port 8002
```

### Terminal 4 — SOC dashboard on `:5173`

```bash
cd frontend
npm run dev
```

Then open **http://localhost:5173** in a browser and click the **Live** toggle in the top-right of the header so the dashboard begins polling for incoming alerts.

## The demo script — one-shot pipeline test

In a fifth terminal (or any free one), from the repo root:

```bash
./scripts/run_full_demo.sh
```

### What it does

Health-checks all three services first — engine, shim, sim — and aborts cleanly if any are down. Then iterates the five sample Wazuh alerts in `data/sample-wazuh-alerts/` in order:

1. **Tier 3 ransomware on the linear accelerator** (`RAD-LINAC-001`) — the showpiece.
2. **Tier 3 active exploitation on the anaesthesia machine** (`OR-ANAES-002`) — proves the corrected escalation logic works for the `clinical_support` band too.
3. **Tier 2 monitored mode** on the ICU ventilator.
4. **Tier 1 brute force** on an admin laptop.
5. **Fail-safe case** — alert from an asset that isn't in the registry. The engine substitutes `score=10 / band=life_critical` and the alert lands in Tier 2 with `fail_safe_applied: true`.

Each alert is POSTed to the shim, which enriches it and forwards it to the engine. The engine classifies, writes to the hash-chained audit log, and pushes the decision to the Shuffle sim as a fire-and-forget background task. The sim runs the matching playbook and records every step. All of this surfaces in the dashboard within a few seconds per alert.

After it finishes, the demo prints a summary: total audit entries, total Shuffle actions, chain integrity status, and pending vs resolved Tier 3 counts.

### Pacing options

```bash
./scripts/run_full_demo.sh                  # default 3-second pause between alerts
./scripts/run_full_demo.sh --pause 5        # slower, easier to follow visually
./scripts/run_full_demo.sh --no-pause       # rip through fast (good for quick verification)
```

## Driving the Tier 3 two-phase flow

Once an alert hits Tier 3, the **Pending Clinician Approval** strip appears at the top of the dashboard with a card per asset. Either click that card or click the alert directly in the feed — then in the Decision Detail's **Tier 3 — Two-phase Flow** section, click:

- **Approve → isolate_host** — the workflow would escalate to full host isolation.
- **Deny → stay in monitored_mode** — FR-06 fail-safe; the asset stays in non-disruptive containment.

Within ~3 seconds the Shuffle Playbook Actions panel adds the `clinician_response` row, the pending tray drops the resolved card, and the audit timeline shows the new follow-up entry. The chain still verifies.

## Resetting state for a clean demo run

If the audit log or action log has accumulated noise from testing and you want a fresh slate:

```bash
# Stop the engine and sim first (Ctrl+C in their terminals), then:
rm engine/data/audit_log.jsonl
rm playbooks/shuffle_sim/data/action_log.jsonl
```

Restart engine + sim, hard-refresh the dashboard (`Ctrl+F5`), and you've got a clean state.

## Health checks

```bash
curl http://localhost:8000/health         # engine
curl http://localhost:8001/health         # shim
curl http://localhost:8002/health         # sim
curl http://localhost:8000/audit/verify   # should return {"ok":true,"error":null}
```

The chain-verify call is also wired to a button on the dashboard's audit timeline.

## Single-alert demo (alternative to the full runner)

For testing a specific scenario rather than the whole sequence:

```bash
./scripts/post_wazuh_alert.sh data/sample-wazuh-alerts/01-tier3-linac-ransomware.json
```

Invoke without an argument for an interactive picker.
