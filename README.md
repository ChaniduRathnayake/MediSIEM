# MediSIEM — Next-Generation SIEM/IDS for Smart Hospitals

MediSIEM is a multi-service SIEM/IDS platform for hospital networks. It ingests
[Wazuh](https://wazuh.com/) HIDS alerts and live network flow data, scores
them with a custom ML pipeline called **CAAP** (*Clinically Aware Alert
Prioritization*), and surfaces everything in a real-time SOC dashboard.

CAAP extends CVSS-style severity with clinical context: a Random Forest
classifier, an Isolation Forest anomaly detector, and a K-Means traffic-context
model are combined with rule-based **Clinical Criticality**, **Active
Exploitation**, and **Temporal Context** scores into a single 0–10
**Clinical Alert Score (CAS)** — e.g. an exploit against an ICU ventilator at
night ranks far above the same exploit against an idle admin workstation. See
[`CAAP_Weight_Justification.html`](CAAP_Weight_Justification.html) for the full
weighting rationale and a live CAS calculator.

## Architecture

```
                         ┌─────────────────────┐
                         │  Wazuh (Docker)      │
                         │  manager :55000      │
                         │  indexer :9200       │
                         └──────────┬───────────┘
                                    │ polls / proxies
                                    ▼
┌───────────────┐   REST/WS   ┌───────────────┐   /predict   ┌───────────────┐
│ React frontend │◄───────────►│ Node backend  │◄────────────►│ Flask AI      │
│ (Vite, :5173)  │  Socket.IO  │ (Express,     │   RF/IF/KMeans│ server (CAAP, │
└───────────────┘             │  :5000)        │              │  :5001)       │
                               └───────┬────────┘              └───────────────┘
                                       │
                                       ▼
                               ┌───────────────┐
                               │  MongoDB       │
                               │  (users, audit,│
                               │  devices, ...) │
                               └───────────────┘

        [isolated lab VM — not started by this repo]
   attack_simulator.py → live_feature_extractor.py → flow_consumer.py
        (simulated traffic)   (packet capture)      (predicts + indexes
                                                       into caap-alerts)
```

## What's in this repo

| Directory | What it is |
|---|---|
| [`backend/`](backend) | Node.js/Express API — auth, users, devices, compliance, Wazuh proxy, live CAAP alert pipeline (Socket.IO) |
| [`frontend/`](frontend) | React 19 + Vite + Tailwind SOC dashboard (admin & user views, Wazuh browser, compliance panels) |
| [`ai_server/`](ai_server) | Flask model-serving API for CAAP (`/predict`) + offline training scripts + `reports/` (charts/metrics from the train/test evaluation) |
| [`ml-pipeline/`](ml-pipeline) | Live network-flow capture pipeline — a custom 45-column CICIoT2023/IoMT-2024 feature extractor + the flow consumer that scores and indexes real captured traffic. Runs on the lab victim VM(s), not the host. |
| [`Extra_Material/`](Extra_Material) | Presentation-facing package — the attack simulation lab (`Demo_Attack/`) and demo runbooks |
| [`medisiem-integration/`](medisiem-integration) | Reference copy of the patch kit used to wire the live CAAP pipeline into `backend`/`frontend`/`ml-pipeline` (already merged — kept for reference) |
| [`start-caap-pipeline.ps1`](start-caap-pipeline.ps1) | One-shot script that brings up the AI server, backend, and frontend in order |
| [`WAZUH_SETUP.md`](WAZUH_SETUP.md) | Wazuh Docker connectivity troubleshooting (proxy chain, ports, host values) |
| [`CAAP_Weight_Justification.html`](CAAP_Weight_Justification.html) | Interactive writeup + calculator for the CAS weighting scheme |

## Features

- **Authentication & users** — JWT auth, `admin`/`user` roles, admin-managed
  user CRUD, live "logged in now" presence widget, audit log
- **Device & device group management** — maps Wazuh agents to clinical device
  types/departments (ICU ventilator, infusion pump, cardiac monitor, ...)
- **Medical device inventory** — a MongoDB-backed hospital asset inventory
  (ventilators, infusion pumps, monitors, imaging systems, dialysis machines,
  etc.), independent of Wazuh agent enrollment. Admins onboard devices from
  the dashboard's Devices tab and tag them with the same group system used
  for live Wazuh agents; this inventory is what CAAP's Clinical Criticality
  scoring resolves an alert's `device_type`/`department` against, replacing
  the old hardcoded lookup table. Seeded with 28 starter devices on first run.
- **Wazuh integration** — proxies the Wazuh Manager API (agents, alerts,
  vulnerabilities, SCA policy checks, agent details) and the Wazuh Indexer
  (full alert search, HIPAA/GDPR compliance rollups, File Integrity
  Monitoring) without exposing Wazuh credentials to the browser
- **CAAP live alert pipeline** — polls the Wazuh Indexer, scores every alert
  with the ML model, and pushes it to the dashboard over Socket.IO in real
  time, with a CAS-distribution chart, IP reputation widget, and per-alert
  analyst assignment
- **ML scoring engine** (`ai_server`) — Random Forest (attack classification),
  Isolation Forest (anomaly/time-sensitivity), K-Means (traffic context), SHAP
  explainability, combined into the CAS score with an action recommendation
  (`Immediate` / `Investigate` / `Monitor`)
- **Live traffic capture & simulation lab** (`ml-pipeline/` + `Extra_Material/Demo_Attack/`) —
  a from-scratch flow feature extractor for generating realistic training/demo
  data on an isolated VM, plus a Scapy-based attack simulator (single-target
  and multi-target/whole-subnet variants)

## Prerequisites

- **Node.js** 18+ (built-in `fetch` is used by the backend)
- **Python** 3.10+ with `venv`
- **MongoDB**, reachable at `MONGO_URI` (defaults to `mongodb://localhost:27017/medisiem`)
- **Wazuh** (Docker) — a running `single-node-wazuh` stack with the manager
  API (`55000`) and indexer (`9200`) reachable. Wazuh itself is **not**
  started by this repo — see [`WAZUH_SETUP.md`](WAZUH_SETUP.md) for the
  Docker port mapping and connectivity checks.
- (Optional, for the live-traffic demo) A second isolated VM (VirtualBox/VMware)
  with [Npcap](https://npcap.com/#download) installed, for packet capture and
  attack simulation — see [`ml-pipeline/README.md`](ml-pipeline/README.md).

## Quick start

### 1. Backend

```bash
cd backend
cp .env.example .env      # set JWT_SECRET, MONGO_URI, WAZUH_INDEXER_*, CAAP_AI_URL
npm install
npm run seed               # creates the default admin/demo users (see below)
npm run dev                 # http://localhost:5000
```

### 2. AI server (CAAP model)

Trained model artifacts (`ai_server/models/*.pkl`) are gitignored — train them
locally first if they're not already present:

```bash
cd ai_server
python -m venv venv
.\venv\Scripts\Activate.ps1     # (Windows) or: source venv/bin/activate
pip install -r requirements.txt
python train.py                  # produces ai_server/models/*.pkl
python src/app.py                # http://localhost:5001
```

### 3. Frontend

```bash
cd frontend
npm install
npm run dev                # http://localhost:5173 (proxies /api/* to :5000)
```

### 4. All at once (Windows)

Once `backend/.env` is configured and the AI server's models are trained, the
whole host side can be brought up in order with one script (also verifies the
Wazuh Indexer is reachable first):

```powershell
powershell -ExecutionPolicy Bypass -File .\start-caap-pipeline.ps1
```

This starts the Flask AI server (`:5001`), Node backend (`:5000`), and React
dashboard (`:5173`) each in their own window, then prints the exact commands
to run inside the lab VM for live traffic capture (step 5 below).

### 5. (Optional) Live traffic capture & attack simulation lab

For end-to-end CAAP scoring on real captured traffic instead of static test
data, run the capture/simulation tools inside an **isolated lab VM** (they use
raw sockets and shouldn't run on your main host):

```powershell
# victim VM — capture + scoring
cd "ml-pipeline"    # or wherever you copied it
pip install -r requirements.txt
python live_feature_extractor.py --iface "<interface>" --out-dir .\cicflowmeter_output
python flow_consumer.py --flow-dir .\cicflowmeter_output `
    --caap-url http://<host-ip>:5001 --indexer-url https://<host-ip>:9200 `
    --indexer-user <WAZUH_INDEXER_USER> --indexer-pass <WAZUH_INDEXER_PASS>

# attacker VM — simulated traffic
cd "Extra_Material\Demo_Attack"    # or wherever you copied it
python attack_simulator.py --target <victim-vm-ip> --scenario all
# or, to sweep every VM device in one run: python multi_target_attack_simulator.py --scenario all
```

`start-caap-pipeline.ps1` prints the capture/consumer commands pre-filled with
your host-only adapter IP and `backend/.env` credentials. Full setup (Npcap,
finding your interface name, network topology) is in
[`ml-pipeline/README.md`](ml-pipeline/README.md); the attack tooling is
documented in
[`Extra_Material/Demo_Attack/README.md`](Extra_Material/Demo_Attack/README.md).

Then open **http://localhost:5173** and log in — alerts appear in the admin
dashboard in real time as `flow_consumer.py` indexes them.

## Default credentials

Created by `npm run seed` (backend):

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@medisiem.com | Admin@1234 |
| User | user@medisiem.com | User@1234 |

There is no public self-registration endpoint — new users are created by an
admin via the dashboard (`POST /api/users`).

## API overview

All routes are mounted under `/api` on the backend (`:5000`).

| Prefix | Auth | Purpose |
|--------|------|---------|
| `/api/auth` | login / me / logout | JWT login, current user, logout |
| `/api/users` | admin (mostly) | User CRUD, presence ("logged in now") |
| `/api/audit-log` | admin | Audit log listing |
| `/api/devices` | mixed | Wazuh agent metadata, group/OS-category assignment |
| `/api/device-groups` | mixed | Device group (tag) CRUD |
| `/api/medical-devices` | mixed | Onboarded medical device inventory CRUD + tagging (admin write, any authenticated user read) |
| `/api/wazuh` | protected | Proxies the Wazuh Manager API — agents, alerts, vulnerabilities, SCA checks, agent details |
| `/api/compliance` | protected | HIPAA/GDPR rollups and File Integrity Monitoring, via the Wazuh Indexer |
| `/api/alerts` | protected | CAS-ranked live alert feed + analyst assignment |
| `/api/health` | none | Health check |

Live alerts are additionally pushed to connected clients over **Socket.IO** as
the backend's pipeline (`backend/services/alertPipeline.js`) polls the Wazuh
Indexer and scores new alerts through the AI server.

## Environment variables

### `backend/.env`

```env
PORT=5000
MONGO_URI=mongodb://localhost:27017/medisiem
JWT_SECRET=your_super_secret_jwt_key_here_change_in_production
JWT_EXPIRES_IN=7d
NODE_ENV=development

# CAAP live pipeline
WAZUH_INDEXER_URL=https://localhost:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=changeme
WAZUH_INDEXER_INDEX=caap-alerts
WAZUH_INDEXER_VERIFY_SSL=false
CAAP_AI_URL=http://localhost:5001
ALERT_POLL_INTERVAL_MS=5000
ALERT_BUFFER_SIZE=500
```

Wazuh **Manager API** credentials (used by `/api/wazuh/*`) are supplied
per-request from the dashboard's connection panel rather than stored in
`.env` — see [`WAZUH_SETUP.md`](WAZUH_SETUP.md).

## Stack

- **Backend**: Node.js (ESM), Express, MongoDB/Mongoose, JWT + bcrypt, Socket.IO
- **Frontend**: React 19, Vite, TypeScript, Tailwind CSS 4, React Router 7, Axios, Socket.IO client
- **AI server**: Python, Flask, scikit-learn (Random Forest, Isolation Forest, K-Means), SHAP
- **ML pipeline**: Python, Scapy (packet capture / traffic simulation), pandas
- **SIEM backbone**: Wazuh (manager + indexer, run via Docker separately from this repo)
