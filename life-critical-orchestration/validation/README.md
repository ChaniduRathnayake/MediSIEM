# Validation harness — Phase 4 disruption-rate measurement

Turns the proposal's headline claim into a measured number: the **accidental
disruption rate** of a life-critical service (ICU-VENT-003), comparing a
traditional-SOAR baseline against this project's tiered engine.

## The metric chain

```
heartbeat downtime  ->  disrupted? yes/no  ->  disruption RATE (headline, <= 5%)
(measured evidence)     (per incident)         (= disrupted incidents / total)
```

Downtime measured on the real emulated device is the *evidence* behind each
per-incident yes/no; the headline is the **rate** — how often the service was
actually disrupted. Also reported (proposal section 3.5): **response
precision** and **decision time**.

## What it does

For 3 realistic scenarios (ransomware, active-exploit, suspicious-traffic) on
the life-critical device, under two policies:

- **Baseline SOAR** — always `isolate_host` (blind automation). Device cut → disrupted.
- **Tiered engine** — the real classifier decides → `monitored_mode` /
  `await_clinician_approval`. Device never auto-isolated → service intact.

Each run isolates (or not), holds, releases, then measures the heartbeat
downtime inside that window from `device-sim/data/availability.jsonl`.

## Running it

Requires the **device-sim stack up** (real heartbeat to disrupt + measure).
Nothing else — the engine classifier and enforcement run in-process.

```bash
# device-sim stack must be running first:
#   cd device-sim && docker compose up -d

cd validation
source ../engine/.venv/Scripts/activate   # shared engine venv

python run_validation.py --quick   # fast sanity run (short windows)
python run_validation.py           # full run (~2-3 min) — the real result
```

Reset a stuck isolation between runs:

```bash
curl -s -X POST "http://localhost:8002/enforcement/release?asset_id=ICU-VENT-003"
```
(or just re-run — each run releases what it isolated)
