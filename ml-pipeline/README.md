# ML detection pipeline — real CAAP scoring for live/simulated traffic

Every alert the dashboard shows should come from an actual RF + Isolation
Forest + K-Means prediction, built from genuine flow features — not a
rule.level guess. See `backend/services/alertPipeline.js`, which logs a loud
warning any time it has to fall back.

## Why there's no CICFlowMeter step here

The original plan was CICFlowMeter (Java tool or the `cicflowmeter` pip
package) → `flow_consumer.py` → `/predict`. That doesn't work for this model:
`ai_server/models/feature_cols.pkl` uses the **CICIoT2023 / CIC IoMT-2024**
45-column feature schema (`Header_Length`, `Rate`, `Srate`, `Drate`,
`Magnitue`, `Radius`, `Covariance`, `Weight`, ...), which CICFlowMeter does
not produce — CICFlowMeter's own ~80-column schema (`Flow Duration`,
`Total Fwd Packets`, ...) has **zero name overlap** with it. Verified with
`ai_server/verify_feature_cols.py --against <a real CICFlowMeter header>`:
0/45 matched. Installing CICFlowMeter would silently zero-fill every feature.

Instead, `live_feature_extractor.py` reconstructs the actual 45 columns from
live packets directly (see its docstring for the exact formulas, sourced from
the CICIoT2023 paper's Table 4, and the assumptions made where the paper
doesn't fully specify an implementation). It writes CSV rows into the same
folder `flow_consumer.py` already watches, so `flow_consumer.py` itself is
unchanged.

**Read the ASSUMPTIONS section in `live_feature_extractor.py`'s docstring
before trusting the numbers in a thesis writeup.** Column names will match
your model exactly (that's mechanical). Whether the *values* have the same
distribution the model was trained on is a reconstruction from the published
paper, not the original extractor's source code — sanity-check your live
"benign" output against `ai_server/data/train/Benign_train.pcap.csv` (similar
order of magnitude = good sign) before relying on it for accuracy claims.

## Topology

Host machine (Windows) runs the stuff that's already there or safe/easy to
run natively: your existing **real Wazuh Indexer** (the `single-node-wazuh`
docker stack — manager/indexer/dashboard — started and managed separately,
NOT by anything in this repo), the Flask AI server, the Node backend, the
React dashboard. `start-caap-pipeline.ps1` in the repo root checks the
indexer is reachable, then starts the other three in order.

The **lab VM(s)** (VirtualBox/VMware, host-only or NAT network) run the stuff
that needs raw sockets and shouldn't touch your real network: the victim VM
runs `live_feature_extractor.py` and `flow_consumer.py` from this folder
(colocated since they share a local output folder); the attacker VM runs
`attack_simulator.py` from
[`Extra_Material/Demo_Attack/`](../Extra_Material/Demo_Attack) — kept
separate since it's attack-simulation tooling, not part of the live capture
path. The VM(s) reach the host's Flask server and Wazuh Indexer via the
host-only adapter's IP — `start-caap-pipeline.ps1` prints the commands with
that IP and your real `backend/.env` credentials filled in for you.

```
[lab VM]                                              [host]
attack_simulator.py --target <victim-vm>
        │ traffic
        ▼
live_feature_extractor.py (sniffs, writes CSV)
        │
        ▼
flow_consumer.py  ──/predict (real RF+IF+KMeans)──►  Flask :5001
        │
        └──index doc───────────────────────────────►  Wazuh Indexer :9200 (caap-alerts index)
                                                              │
                                                        Node backend :5000 polls
                                                              │
                                                        Socket.IO push
                                                              │
                                                        React dashboard :5173
```

## Setup — inside the lab VM

1. **Npcap** (packet capture driver): download from
   https://npcap.com/#download, install with **"WinPcap API-compatible
   mode"** checked. Reboot if prompted.
2. **Python deps**, from an elevated (Administrator) shell — raw capture
   needs it:
   ```powershell
   cd "ml-pipeline"    # or wherever you copied it
   pip install -r requirements.txt
   ```
3. **Find your interface name**:
   ```powershell
   python -c "from scapy.all import get_if_list; print(get_if_list())"
   ```
4. **Start the extractor** (writes to `./cicflowmeter_output/live_flows.csv`):
   ```powershell
   python live_feature_extractor.py --iface "<name from step 3>" --out-dir .\cicflowmeter_output
   ```
5. **Start flow_consumer.py**, pointed at the host's IP (find it on the host
   with `ipconfig` — the VirtualBox Host-Only / VMware Host-Only adapter):
   ```powershell
   python flow_consumer.py --flow-dir .\cicflowmeter_output `
       --caap-url http://<host-ip>:5001 --indexer-url https://<host-ip>:9200 `
       --indexer-user <WAZUH_INDEXER_USER from backend/.env> --indexer-pass <WAZUH_INDEXER_PASS from backend/.env>
   ```
   (`start-caap-pipeline.ps1` prints this command with both filled in for you.)
6. **Generate traffic**, from the attacker VM/machine, using
   `Extra_Material/Demo_Attack/attack_simulator.py` (only against a target IP
   on this isolated lab network — see the warning at the top of that file):
   ```powershell
   python ../Extra_Material/Demo_Attack/attack_simulator.py --target <victim-vm-ip> --scenario all
   ```
   Or `multi_target_attack_simulator.py` in the same folder to sweep every VM
   device instead of one `--target` at a time — see
   [`Extra_Material/Demo_Attack/README.md`](../Extra_Material/Demo_Attack/README.md).

## device_map.json

Keyed by IP because flow records identify devices by IP, not by a Wazuh agent
name. Keep in sync with `backend/config/deviceInventory.js` — or move both to
one shared source (e.g. a Mongo `devices` collection) past the demo stage.

## What happened to the rule.level fallback?

`backend/services/caapService.js` still has it, but it's a fallback path
only — it fires if the Node backend ever polls an index that isn't
pre-enriched (e.g. `WAZUH_INDEXER_INDEX` points at raw `wazuh-alerts-*`
instead of `caap-alerts`). `alertPipeline.js` logs a loud warning if that
happens, so it won't silently mix rule-based scores into what should be an
all-ML result set.
