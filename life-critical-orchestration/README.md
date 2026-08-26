# Life-Critical-Aware Incident Response Orchestration

> Safety-preserving SIEM/SOAR orchestration for healthcare systems

**Project ID:** R26-CS-008
**Author:** W.D.S Jayasinghe (IT22086648)
**Programme:** B.Sc. (Hons) Information Technology — Cyber Security, SLIIT
**Supervisor:** Mr. Amila Nuwan Senarathne
**Co-supervisor:** Ms. Ayesha Wijesooriya

---

## Overview

Traditional Security Orchestration, Automation, and Response (SOAR) platforms execute
disruptive containment actions — network isolation, port blocking, host quarantine —
without evaluating the clinical context of the affected system. In a smart hospital,
blindly applying these actions to a life-sustaining medical device (ventilator, infusion
pump, radiation therapy unit) can directly harm patients.

This project introduces a **Life-Critical-Aware Incident Response Orchestration**
framework that integrates clinical context into automated security responses through
a tiered decision logic:

| Tier | Trigger | Response |
|------|---------|----------|
| **Tier 1** | Non-critical asset | Standard disruptive containment |
| **Tier 2** | Life-critical asset, standard risk | Non-disruptive Monitored Mode |
| **Tier 3** | Life-critical asset, extreme risk | Clinician-in-the-loop approval |

**Goal:** Maintain ≤5% accidental disruption rate for life-critical medical assets,
compared to traditional SOAR systems.

---

## Architecture

```
[Smart Hospital Environment]
            │
            ▼
[SIEM (Wazuh)] ──► [Enrichment Module] ──► [Decision Engine] ──► [SOAR (Shuffle)]
                          │                       │                      │
                          │                       ▼                      ▼
                          │                  [Audit Log]            [Playbooks]
                          │                       │                      │
                          ▼                       ▼                      ▼
                   [Asset Registry]        [SOC Dashboard]       [Tier 1/2/3 Actions]
```

See [`docs/architecture.md`](docs/architecture.md) for full diagrams.

---

## Repository Structure

```
.
├── engine/         # Decision engine — Security-vs-Life logic (FastAPI + Python)
├── enrichment/     # Stand-in enrichment module (placeholder for teammate's component)
├── frontend/       # SOC dashboard (React + Vite + Tailwind)
├── playbooks/      # Shuffle SOAR playbooks (Tier 1, 2, 3)
├── infra/          # Docker Compose stack (Wazuh + Shuffle + engine)
├── data/           # Stub alert datasets for development & testing
├── docs/           # Architecture, API spec, integration notes
└── scripts/        # Helper scripts (seed data, verify audit log, setup)
```

---

## Quick Start

> **Prerequisites:** Docker Desktop, Python 3.11+, Node.js 20+, Git

The PP1 demo runs four local services plus the Wazuh / Shuffle Docker stack
(only needed for the SIEM/SOAR side; optional for end-to-end pipe testing
because alerts can be POSTed directly to the shim).

```bash
# Terminal 1 — Decision engine on :8000
# Set SHUFFLE_WEBHOOK_URL so the engine pushes decisions to the SOAR sim.
cd engine
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
SHUFFLE_WEBHOOK_URL=http://localhost:8002/playbook/run \
  uvicorn src.main:app --reload --port 8000

# Terminal 2 — Enrichment shim on :8001
cd enrichment
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn src.main:app --reload --port 8001

# Terminal 3 — Shuffle SOAR sim on :8002 (PP1 stand-in for real Shuffle)
cd playbooks/shuffle_sim
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn server:app --reload --port 8002

# Terminal 4 — SOC dashboard on :5173
cd frontend
npm install
npm run dev
```

Then open the dashboard at `http://localhost:5173`, click the **Live**
toggle in the header, and either fire a single alert through the pipe:

```bash
./scripts/post_wazuh_alert.sh data/sample-wazuh-alerts/01-tier3-linac-ransomware.json
```

…or run the full demo (all 5 sample alerts in sequence with paced pauses):

```bash
./scripts/run_full_demo.sh
```

The alerts appear in the dashboard's feed within a few seconds, the audit
log gets new entries, the **Shuffle Playbook Actions** panel under each
decision shows the playbook steps that fired, the chain-verify button stays
green, and Tier 3 alerts surface in the pending tray with **Approve / Deny**
buttons that drive Phase B of the two-phase flow.

Detailed Wazuh + Shuffle setup: [`infra/README.md`](infra/README.md)
Wazuh-to-shim integration (PP2 path): [`infra/wazuh/integrator-config.md`](infra/wazuh/integrator-config.md)
Shuffle sim and PP2 export path: [`playbooks/README.md`](playbooks/README.md)

---

## Project Status

**Current phase:** PP1 preparation (deadline: 12 May 2026)

| Component | PP1 Target | Status |
|-----------|------------|--------|
| Docker environment (Wazuh + Shuffle) | Running | ✅ Done |
| Decision engine (Tier 1, 2, 3) | Working with audit log | ✅ Done |
| Enrichment shim (Wazuh → engine) | Stub registry, mapper, demo button | ✅ Done |
| Frontend dashboard | Polished, with Live mode | ✅ Done |
| End-to-end integration | Demoable | ✅ Done |
| Shuffle SOAR sim (Tier 2 + Tier 3 playbooks) | Working, dashboard-visible | ✅ Done |
| Tier 3 clinician approval (two-phase flow) | Engine + sim + dashboard panel | ✅ Done (full clinician UI in PP2) |
| Demo runner script | One-shot all-5-alerts demo | ✅ Done |

---

## Roadmap

| Milestone | Date | Deliverable |
|-----------|------|-------------|
| Proposal Submission | 15 Mar 2026 | ✅ Submitted |
| **PP1** | **12 May 2026** | Frontend + Tier 1/2 logic + integration |
| PP2 | 17–19 Aug 2026 | Tier 3 Clinician UI + full SIEM integration |
| Final Report | 11 Oct 2026 | Validation results + paper draft |
| Final Submission | 15 Oct 2026 | Website + research paper + viva |

---

## Related Repositories

This component will be linked into the main group research repository.
*(Group repo link TBD)*

---

## License

MIT — see [`LICENSE`](LICENSE).
