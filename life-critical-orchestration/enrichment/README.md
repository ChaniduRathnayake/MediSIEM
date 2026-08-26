# Enrichment Shim

A small FastAPI service that sits between Wazuh and the decision engine.
It accepts Wazuh-shaped alerts, enriches them with clinical context from the
asset registry, and forwards the enriched alert to the engine's `/decide`
endpoint.

> ⚠️ **Stub component.** This module stands in for a teammate's real
> enrichment service. The asset registry here is a JSON lookup table mirroring
> the 12 sample alerts; the production version will be a live registry/service
> producing the same `cc_score` + metadata contract.

## What it does

```
Wazuh JSON  →  /wazuh-alert  →  asset registry lookup  →  POST /decide  →  Decision
```

Three responsibilities:

1. **Restructure** Wazuh's native alert shape (`rule.*`, `agent.*`, `data.*`)
   into the engine's v1.0 schema (`source` / `threat` / `asset` /
   `clinical_context` / `enrichment_meta`).
2. **Derive** threat fields the engine cares about — category, technical
   severity, CVSS hint — from Wazuh's rule groups and level.
3. **Enrich** with clinical context from `data/asset_registry.json`. Registry
   miss → empty `clinical_context`, which intentionally triggers the engine's
   fail-safe (treat as `life_critical`).

## Endpoints

| Method | Path             | Purpose                                       |
| ------ | ---------------- | --------------------------------------------- |
| GET    | `/health`        | Liveness probe                                |
| GET    | `/registry`      | Read-only peek at known assets (debugging)    |
| POST   | `/wazuh-alert`   | Accept a Wazuh-shape alert, enrich, forward   |

## Run locally

```bash
cd enrichment
python3 -m venv .venv
source .venv/bin/activate            # Git Bash on Windows
pip install -r requirements.txt
uvicorn src.main:app --reload --port 8001
```

Configurable via env vars:

- `ENGINE_URL` — base URL of the decision engine (default
  `http://localhost:8000`).
- `REGISTRY_PATH` — path to the registry JSON (default
  `enrichment/data/asset_registry.json`).

## Quick smoke test

With both engine (`:8000`) and shim (`:8001`) running:

```bash
./scripts/post_wazuh_alert.sh data/sample-wazuh-alerts/01-tier3-linac-ransomware.json
```

You should see the shim's response with the enriched alert and the engine's
decision. The audit log gets a new entry; the dashboard's Live mode picks it up
on the next poll.

## Tests

```bash
# from repo root
pytest enrichment/tests
```

Covers registry lookup, mapper restructuring, threat-derivation, and the
fail-safe path on registry miss.
