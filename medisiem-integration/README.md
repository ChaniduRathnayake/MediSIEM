# Live CAAP pipeline: simulated attacks → real ML detection → MediSIEM UI

## What this adds

Two source options feed the same downstream dashboard, but for research
results you want the **ML pipeline**, not the fallback:

```
ml-pipeline/attack_simulator.py (scapy)
        │  simulated attack + benign traffic
        ▼
CICFlowMeter (live capture) ──► flow_consumer.py ──► Flask /predict (real RF + IF + K-Means)
                                                                │
                                                                ▼
                                              OpenSearch "caap-alerts" index
                                                                │
                                                                ▼
                                        Node backend polls ──► Socket.IO push
                                                                │
                                                                ▼
                                                  React AdminDashboard (live)
```

`ml-pipeline/` (see its own README) is the primary path — every alert is a
genuine model output. The Node backend also *can* fall back to scoring raw
Wazuh HIDS alerts via `caapService.js`'s rule.level estimate if you ever point
it at plain `wazuh-alerts-*` instead, but that's explicitly a degraded path
(no flow features → no real classification) and is logged as a warning if it
ever fires — it's not meant to be your primary detection method.

## Files

| File | Purpose |
|---|---|
| `backend/config/deviceInventory.js` | Maps Wazuh agent → clinical device_type/department (CC score input). **Fill in your real inventory.** |
| `backend/services/wazuhIndexerService.js` | Polls Wazuh Indexer REST API for new alerts since last timestamp |
| `backend/services/caapService.js` | Maps a Wazuh alert → CAAP `/predict` payload, calls Flask, handles the no-flow-features fallback |
| `backend/services/alertPipeline.js` | Poll loop, in-memory buffer, Socket.IO broadcast |
| `backend/routes/alerts.js` | `GET /api/alerts` — CAS-ranked snapshot |
| `backend/server.js` | Updated: adds Socket.IO server, mounts `/api/alerts`, starts the pipeline on boot |
| `frontend/src/services/alertsApi.ts` | `apiGetAlerts()` |
| `frontend/src/hooks/useLiveAlerts.ts` | REST fetch + Socket.IO subscription combined |
| `AdminDashboard.patch.md` | Exact 3-step diff to wire your existing dashboard to live data |
| `ml-pipeline/attack_simulator.py` | Scapy traffic generator — ARP spoof, port scan, SYN flood, benign (lab use only) |
| `ml-pipeline/flow_consumer.py` | Watches CICFlowMeter output → calls real `/predict` → indexes into `caap-alerts` |
| `ml-pipeline/device_map.json` | IP → clinical device metadata, used by `flow_consumer.py` |
| `ml-pipeline/README.md` | Full run order + the feature-alignment check you should do once |

## Install

```bash
# backend
cd backend
npm install socket.io undici
cat .env.pipeline.example >> .env   # then edit values for your Wazuh Indexer

# frontend
cd ../frontend
npm install socket.io-client
```

Node 18+ has `fetch` built in, so no extra HTTP client is needed there — only
`socket.io` (server) and `undici` (Agent, for the self-signed-cert bypass) on
the backend, and `socket.io-client` on the frontend.

## Before it works end-to-end

1. **Wazuh Indexer credentials** — get the real user/pass for your Wazuh Indexer
   (default installs use `admin`/whatever you set during `wazuh-passwords-tool`),
   and set `WAZUH_INDEXER_URL` to wherever it's reachable from your Node server.
2. **Flask server running** — `CAAP_AI_URL` (default `http://localhost:5001`)
   needs `src/app.py` up and its CORS already allows the Node backend per your
   Phase 6 plan.
3. **Device inventory** — `deviceInventory.js` is a stub with 6 sample devices.
   Replace with your actual hospital asset list, or better, pull it from Mongo.
4. **Flow features** — see the big comment at the top of `caapService.js`.
   Until you're also feeding Suricata/NetFlow records into the same Wazuh
   Indexer, alerts get scored via the `rule.level` fallback rather than a real
   RF classification. This still produces a usable CAS/action, just flag it
   in your thesis writeup as a current limitation of the live deployment vs.
   the offline model evaluation (which used real flow data from the datasets).

## Test without a live Wazuh cluster

`wazuhIndexerService.js` just needs something answering the OpenSearch
`_search` API at `WAZUH_INDEXER_URL`. You can point it at a bare OpenSearch/
Elasticsearch container seeded with a few fake `wazuh-alerts-*` documents to
verify the whole chain (poll → enrich → Socket.IO push → dashboard row
appears) before wiring in the real cluster.
