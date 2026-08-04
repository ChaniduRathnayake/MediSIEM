# ML detection pipeline — real CAAP scoring for live/simulated traffic

This replaces the earlier rule.level-fallback approach with the real thing:
every alert your dashboard shows comes from an actual RF + Isolation Forest +
K-Means prediction, because it's built from genuine flow features.

## Run order

1. **OpenSearch/Elasticsearch (Wazuh Indexer)** — already running per your setup.
2. **Flask AI server**: `python src/app.py` (port 5001) — unchanged.
3. **CICFlowMeter**, live mode, capturing on the interface your simulated
   traffic runs on, writing CSV rows to a folder (e.g. `./cicflowmeter_output/`).
   - Original Java tool: run its `-i <interface> -c` live-capture mode with an
     output directory.
   - Python port (`pip install cicflowmeter`) also supports live sniffing to CSV
     if you'd rather avoid the Java toolchain — check its CLI flags for your
     installed version, output columns should match what trained your model
     (verify against Flask's startup log, see below).
4. **flow_consumer.py** — watches that folder, enriches via `/predict`, indexes
   into `caap-alerts`:
   ```bash
   pip install -r requirements.txt
   python flow_consumer.py \
     --flow-dir ./cicflowmeter_output \
     --caap-url http://localhost:5001 \
     --indexer-url https://localhost:9200 \
     --indexer-user admin --indexer-pass changeme
   ```
5. **attack_simulator.py** — generates the traffic CICFlowMeter captures:
   ```bash
   pip install scapy
   sudo python attack_simulator.py --target 192.168.56.10 --scenario all
   ```
   ⚠ Only run this against a target IP on an isolated lab/VM network you
   control — see the warning at the top of the script.
6. **Node backend + React frontend** — already built in `../backend` and
   `../frontend`; point `WAZUH_INDEXER_INDEX=caap-alerts` in `.env` (already
   the default in `.env.pipeline.example`).

## Verifying feature alignment (do this once)

When Flask starts, it prints:
```
[CAAP] Feature columns: ['Flow Duration', 'Total Fwd Packets', ...]
```
Compare that list to the header row CICFlowMeter is producing in your live
CSV. If your CICFlowMeter version differs from what built the training
dataset, some column names may not match — `to_feature_frame()` in `app.py`
silently zero-fills anything missing (`payload.get(col, 0.0)`), which quietly
degrades accuracy without erroring. If predictions look off, this mismatch is
the first thing to check — a **diff of the two column lists**, not a retrain.

## device_map.json

Keyed by IP because flow records identify devices by IP, not by a Wazuh agent
name. Keep this in sync with `backend/config/deviceInventory.js` (or better:
move both to one shared source — a small Mongo `devices` collection — once
you're past the demo stage).

## What happened to the rule.level fallback?

`backend/services/caapService.js` still has it, but it's now clearly a
fallback path only — it fires if the Node backend ever polls an index that
isn't pre-enriched (e.g. you point `WAZUH_INDEXER_INDEX` back at raw
`wazuh-alerts-*`). `alertPipeline.js` logs a warning if that happens, so it
won't silently mix rule-based scores into what should be an all-ML result set.
