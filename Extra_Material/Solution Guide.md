# MediSIEM & CAAP — Solution Guide

A presentation-facing companion to the codebase: what the system is, why it's
built the way it is, what the evaluation actually showed, and how to walk
someone through it live. Written for a thesis defense / project demo
audience — technical enough to survive questions, not a marketing page.

---

## 1. The problem in one paragraph

A generic SIEM ranks alerts by signature severity alone (Wazuh's `rule.level`,
CVSS-style scoring). That means a brute-force login attempt against an idle
admin workstation and the exact same attack against a networked ICU
ventilator get the same priority. In a hospital SOC, that's backwards — the
alert that matters is the one on a device that can hurt a patient if it's
compromised, and generic severity has no way to know that. CAAP (**Clinically
Aware Alert Prioritization**) fixes this by scoring *what the device is* and
*what happens if it's compromised*, not just *what kind of attack it is*.

## 2. The solution: the Clinical Alert Score (CAS)

CAS is a weighted 0–10 score computed from five dimensions:

```
CAS = 0.25·TR + 0.30·CC + 0.25·TS + 0.10·AE + 0.10·TC
```

| Dim. | Name | Weight | What it measures | How it's computed |
|---|---|---|---|---|
| **TR** | Threat Risk | 0.25 | How confident the model is this is a real attack, and what kind | Random Forest classifier's prediction confidence, rescaled 1–10 |
| **CC** | Clinical Criticality | **0.30** (largest weight) | How much patient harm follows if this device is compromised | Rule-based lookup against the device's onboarded criticality (ICU Ventilator = 10, Workstation = 4, etc.) — see §3 |
| **TS** | Temporal/behavioural Sensitivity | 0.25 | How anomalous this traffic is against the device's normal baseline | Isolation Forest anomaly score, adjusted for time-of-day |
| **AE** | Active Exploitation | 0.10 | Is this a known-exploited vulnerability, not just a theoretical one | CISA KEV catalog match + AbuseIPDB source-IP reputation |
| **TC** | Temporal Context | 0.10 | Is this happening when fewer staff are on duty to respond | Night shift (22:00–06:00) scores higher than day shift |

CC has the largest weight deliberately — clinical impact is the dimension a
generic SIEM has no concept of at all, so it's the one CAAP leans on hardest
to differentiate itself. The result maps to an action:
**CAS ≥ 8 → Immediate**, **CAS ≥ 5 → Investigate**, otherwise **Monitor**.

**Worked example** (the one in the root README): an ARP-spoofing attempt
against an ICU ventilator at 2 AM. TR=8 (RF is confident this is an attack),
CC=10 (ICU Ventilator, top criticality tier), TS=7 (traffic pattern deviates
from this device's normal baseline), AE=2 (not a known-CVE exploit, just
anomalous behaviour), TC=8 (night shift). CAS = 0.25(8) + 0.30(10) + 0.25(7)
+ 0.10(2) + 0.10(8) = **7.55 → Investigate**, edging toward Immediate. The
same attack signature against an idle admin workstation during the day
(CC=4, TC=4) scores **CAS ≈ 5.85** — still flagged, but correctly ranked
below the ventilator case.

## 3. Why three ML models, not one

- **Random Forest** — supervised multi-class classifier (ARP_Spoofing,
  Benign, DoS_TCP, MQTT_Brute_Force, MQTT_Publish_Flood, Recon). Drives TR.
  Chosen for SHAP explainability — every alert ships with the top 3 features
  that drove the classification, which a black-box model can't give you.
- **Isolation Forest** — trained *only* on benign traffic (one-class
  configuration), so it learns what "normal" looks like for this network and
  flags deviation from that, independent of whether the deviation matches a
  known attack signature. Drives TS. This is what catches novel attacks the
  RF was never trained on.
- **K-Means** (k=2) — unsupervised traffic-context clustering (`idle` /
  `active`), used as a secondary signal, not scored into CAS directly.

Three independent models instead of one gives CAAP two things a single
classifier can't: a genuine anomaly signal for zero-day-shaped traffic (RF
alone can only recognize what it was trained on), and redundancy — if RF
misclassifies, IF's anomaly signal still contributes to TS independently.

## 4. Clinical Criticality: rule-based, not learned

CC is deliberately **not** an ML output. It's a lookup against the hospital's
own device inventory (admin-managed, MongoDB-backed — devices are onboarded
with a criticality tier: `critical`/`high`/`medium`/`low`, which maps onto
the 1–10 CC scale). This is a design choice, not a limitation: clinical
criticality is a *policy* fact (this ventilator is life-critical because a
biomedical engineer says so), not something that should be inferred
statistically from network traffic. The rule-based `cas_engine.py` evaluation
harness additionally sources its device-class default criticalities from two
official documents — FDA 21 CFR Part 860 (device classification) and FDA's
2023 medical-device-cybersecurity guidance — so the scoring isn't an
arbitrary internal opinion; it's traceable to a real regulatory source.

## 5. System architecture

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

  [isolated lab VM(s) — ml-pipeline/ (capture) + Extra_Material/Demo_Attack/
                         (attack), not started by the app]
   attack_simulator.py → live_feature_extractor.py → flow_consumer.py
        (simulated traffic)   (packet capture)      (predicts + indexes
                                                       into caap-alerts)
```

The **primary** scoring path is `flow_consumer.py` writing pre-scored
documents directly into the `caap-alerts` Wazuh Indexer index — the Node
backend just polls that index and pushes over Socket.IO. There's also a
**Node-side fallback** (`backend/services/caapService.js`) for alerts that
arrive without a pre-computed CAS (e.g. an indexer pointed at raw
`wazuh-alerts-*` instead), which calls `/predict` live or, if the AI server
itself is unreachable, degrades to a rule-level + device-criticality
estimate rather than dropping the alert — this fallback is logged loudly so
it's never silently mistaken for a real ML classification.

## 6. The SOC platform, not just the score

CAS is the engine; the platform is what makes it usable in a real SOC shift:

- **Live triage** — real-time alert feed with claim-next, quick-verdict
  presets, bulk claim/snooze, saved filter views, a command palette, and a
  compact-density mode for a busy shift
- **Case management** — assignment, closure with mandatory reason/evidence,
  investigation notes with @mentions for a second opinion, related-activity
  correlation, and a full audit trail
- **Detection rules** — an admin-configurable AND-condition rule engine
  layered alongside the ML classification (matched rules show up as their
  own badge, independent of the ML label)
- **Reports** — Detection Accuracy, Escalation Backlog, Off-Hours Activity,
  Device Risk, Threat Summary, and Compliance Evidence reports, all built
  from durable per-alert logs rather than the bounded in-memory buffer
- **AI assistant** (Anthropic-backed, admin-configured API key) — drafts a
  close-case reason/evidence from an alert's context, summarizes an
  investigation's notes, writes narrative threat-summary and compliance
  reports, turns plain-English into a detection rule draft, and answers
  natural-language alert searches — every feature degrades gracefully to "AI
  assistant not configured" rather than breaking when no key is set
- **Compliance** — HIPAA/GDPR alignment derived from Wazuh's own rule-tag
  mappings, plus a real CIS SCA benchmark scan view, explicitly labeled as
  "observed activity" rather than a certified audit
- **Security** — TOTP two-factor auth (self-service, plus admin-enforced
  requirement for non-admin accounts, since a second person can never
  generate someone else's authenticator secret), org-wide password policy,
  account lockout, and a tamper-evident hash-chained audit log
- **Role model** — admin, SOC analyst, biomedical engineer (device inventory
  access), and auditor (read-only compliance/audit access), each scoped to
  what their job actually needs to see

## 7. Evaluation results

All numbers below are from the actual train/test run — see
`ai_server/reports/` for the full charts, per-class breakdowns, and raw CSVs
behind every figure here.

### 7.1 Model accuracy (7.16M training rows, 1.61M held-out test rows, 45 features, 6 classes)

| Model | Metric | Test accuracy |
|---|---|---|
| Random Forest | Multi-class classification accuracy | **99.87%** (AUC-ROC 0.9993, OOB 99.92%) |
| Isolation Forest | Binary normal/attack agreement (one-class, benign-only trained) | **98.54%** (99.18% attack detection, 28.26% false-positive rate) |
| K-Means | Majority-vote cluster purity (k=2) | **92.24%** (silhouette 0.84) |

Per-class RF recall is not uniform — `DoS_TCP` and `MQTT_Publish_Flood`
essentially saturate at ~100% (they're the dominant, high-volume classes),
while the minority classes are meaningfully weaker: `ARP_Spoofing` recall
80%, `MQTT_Brute_Force` recall 85%. This is an honest class-imbalance
limitation worth stating up front rather than letting the headline 99.87%
number imply uniform performance — see
`ai_server/reports/classification_report.txt` for the full per-class
precision/recall/F1 breakdown.

Isolation Forest's 28.26% false-positive rate is the most defensible-sounding
number to interrogate: it means roughly 1 in 4 truly benign flows gets
flagged anomalous by IF alone. This is why IF only contributes 25% of the
final CAS weight (as TS) rather than gating anything outright — RF's
classification and CC's device criticality are what actually separate a real
Immediate-tier alert from noise.

### 7.2 CAAP vs. a CVSS-equivalent baseline (3 simulated hospital scenarios, 600 alerts total)

This is the evaluation that answers "does clinical context actually change
triage outcomes, or is this just a relabeling exercise." Real flow feature
rows from the held-out test set are replayed through the real trained
models; only the *device identity* assigned to each row is simulated (no
real hospital telemetry dataset exists for this — declared explicitly, not
hidden, in `hospital_scenarios.py`).

| Scenario | Alerts | Life-critical | ARA@top-10 (CAAP vs CVSS) | Alert-fatigue reduction |
|---|---|---|---|---|
| ICU / Critical Care Ward | 200 | 103 | **9.71% vs 6.8%** | **100%** (30.0 pts) |
| General Ward / Radiology / Admin | 200 | 24 | 20.83% vs 8.33% | 37.5% (30.0 pts) |
| Hospital-Wide Mixed Stream | 200 | 58 | 17.24% vs 8.62% | 100% (50.0 pts) |
| **All scenarios combined** | 600 | 185 | **5.41% vs 3.78%** | **100%** (30.0 pts) |

**ARA** (Alert Ranking Accuracy) is the share of life-critical alerts that
land inside the top-N ranked positions — CAAP outperforms the CVSS-style
baseline in every scenario. **MTCAI** (Mean Time-to-Critical-Alert-Identification,
combined) drops from a mean rank of 265.97 under CVSS-only ranking to
**166.48** under CAAP — a life-critical alert surfaces roughly 100 ranks
sooner on average. **Alert-fatigue reduction** measures the drop in false
positives inside the top-10 window; CAAP hits 0% FPR@top-10 in two of three
scenarios where CVSS still carries 30–50%.

The honest caveat: this is a simulated-device-assignment evaluation on real
flow data, not a real hospital's historical alert log (none exists publicly
for this). It demonstrates the scoring *mechanism* works as designed, not a
field-validated deployment outcome.

## 8. Running the live demo

The full step-by-step runbook lives in
[`Extra_Material/Demo_Attack/DEMO_RUNBOOK.md`](Demo_Attack/DEMO_RUNBOOK.md),
with a presentation-facing companion (talking points, fallback plan, and an
anticipated-questions cheat sheet) in
[`Extra_Material/Demo_Attack/PP2_DEMO_SCRIPT.md`](Demo_Attack/PP2_DEMO_SCRIPT.md).
Short version:

1. **Windows host**: `powershell -ExecutionPolicy Bypass -File .\start-caap-pipeline.ps1`
   brings up the Flask AI server, Node backend, and React dashboard.
2. **Victim VM** (stands in for a clinical device — tag its IP in
   `device_map.json` first for a real CAS score): runs
   `run_victim_capture.sh`, which captures its own traffic, reconstructs the
   45-column feature schema live, scores it through the real models, and
   indexes into `caap-alerts`.
3. **Attacker VM**: runs `run_attack.sh <victim-ip> all` — cycles ARP spoof →
   port scan → SYN flood → benign, so the CAS score visibly rises and falls
   on the dashboard as the attack progresses. `multi_target_attack_simulator.py`
   (same folder) does the same across every VM device in one run instead of a
   single target.
4. Watch the SOC live feed and the Wazuh browser tab side by side — same
   underlying activity, one view scored by signature severity alone, the
   other factoring in device type, anomaly, exploitation, and time of day.

If a live network demo isn't practical in the room (Wi-Fi, VM networking,
projector constraints), `ml-pipeline/replay_test_flows.py`
replays real held-out test rows through the real models into the same
dashboard — genuine model output, no live capture required.

## 9. What's in `Extra_Material/`

The live-demo pipeline is split by role: the packet-capture/scoring side
(`live_feature_extractor.py`, `flow_consumer.py`, `device_map.json`,
`run_victim_capture.sh`) lives in `ml-pipeline/` at the repo root, not under
`Extra_Material/`, since it's genuine pipeline code rather than
presentation-only material. What's actually in this folder:

| Item | What it's for |
|---|---|
| `Demo_Attack/` | Attack-simulation tooling — `attack_simulator.py`/`run_attack.sh` (single target) and `multi_target_attack_simulator.py`/`run_multi_attack.sh` (every VM device in one run), plus `DEMO_RUNBOOK.md` and `PP2_DEMO_SCRIPT.md`. Self-contained; runs from wherever this folder is copied to. |
| `Solution Guide.md` | This file. |
| `CAS_Scoring_Viva_Guide.docx` | A deep-dive, defense-ready reference on the CAS formula alone — every dimension's exact computation, the three-method weight justification (AHP, standards mapping, sensitivity analysis), worked examples, and an extensive Viva Q&A section. See §2 above for the short version; this is the full one. |

The model evaluation charts/reports behind §7 above live in `ai_server/reports/`
alongside the code that generates them (`train.py`/`test.py`/`check_drift.py`),
not in this folder — they're regenerated by re-running training, so they stay
next to that pipeline rather than in the presentation-only materials here.

## 10. Suggested narrative arc for a presentation

1. **Open with the gap**: show a generic severity-only alert list, ask "which
   of these needs attention first?" — there's no way to tell from severity
   alone.
2. **Introduce CAS**: the five-dimension formula, emphasizing CC's weight and
   why clinical criticality is a policy input, not an ML guess.
3. **Live or replayed demo**: same attack, two views (Wazuh raw vs. CAAP
   scored), CAS visibly responding to device identity and time of day.
4. **Back it with the evaluation numbers**: §7.2's ARA/MTCAI comparison is
   the single strongest slide — it directly answers "did this change
   anything" with a number, not just a demo.
5. **Show the platform**: this isn't just a scoring function, it's a working
   SOC shift tool — claim/close/report/audit, not a research notebook.
6. **State the limitations honestly** (§7.1's per-class recall, IF's FPR,
   the simulated-scenario caveat in §7.2) — a panel trusts a defended
   limitation more than a suspiciously perfect result.

## 11. Anticipated questions

- **"Is this real attack traffic or canned data?"** — Real, if run live:
  `attack_simulator.py` sends genuine packets over an isolated VM network;
  `live_feature_extractor.py` captures and reconstructs the actual feature
  vector the model was trained on. `replay_test_flows.py` exists as an
  explicitly-labeled offline alternative for when a live capture isn't
  practical.
- **"Why three models instead of one, isn't that more to maintain?"** — Each
  covers a gap the others can't: RF classifies known patterns with
  explainability, IF catches deviation from *this* network's own baseline
  regardless of whether it matches a known signature, K-Means adds traffic
  context. A single classifier can only ever be as good as its training
  labels; IF is what gives CAAP a real anomaly-detection capability against
  attacks it's never seen.
- **"Isn't Clinical Criticality just a hardcoded number — how is that
  rigorous?"** — It's a policy input by design (see §4), sourced from FDA
  device-classification regulation, not invented. The alternative — trying
  to infer clinical importance from network traffic statistically — would be
  the actual methodological weakness.
- **"How do you know this generalizes past the lab network?"** — It doesn't,
  fully, yet — §7.2 is explicit that device assignment is simulated on real
  flow data, not a real hospital's historical log. That's stated as a
  limitation, not hidden.
- **"What happens if the AI (Anthropic) service is down?"** — Every AI
  feature is additive, not load-bearing: the platform's core scoring and
  triage functions have zero dependency on it, and every AI-backed UI
  element shows a clear "not configured / unreachable" state instead of
  breaking.
