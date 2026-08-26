# Project Roadmap — R26-CS-008

**Life-Critical-Aware Incident Response Orchestration for Smart Hospitals**
W.D.S Jayasinghe (IT22086648) · Supervisor: Mr. Amila Nuwan Senarathne · Co-supervisor: Ms. Ayesha Wijesooriya

A living checklist from PP1 (done) through final submission. Tick items as they land. Phases follow the proposal's WBS; the technical workstreams are how we actually get there.

---

## Milestones at a glance

| Milestone | Proposal phase | Target date | Status |
|---|---|---|---|
| **PP1** — core engine + demo path | Phase 2 (Prototype) | 12 May 2026 | ✅ Done |
| **PP2** — real device-in-the-loop integration | Phase 3 (Integration) | 17–19 Aug 2026 | ⏳ In progress |
| **Validation** — stress testing + ≤5% proof | Phase 4 (Validation) | ~Sep → 11 Oct 2026 | ⬜ Not started |
| **Final Report + Website** | Phase 4/5 | 11 Oct 2026 | ⬜ Not started |
| **Final Presentation, Viva & Paper** | Phase 5 (Output) | 15 Oct 2026 | ⬜ Not started |

**The headline deliverable that must work:** a real (emulated) IoMT device, monitored by real Wazuh rules, where `monitored_mode` provably preserves device function and `isolate_host` provably disrupts it — with the gap measured as the ≤5% accidental-disruption rate vs. a traditional always-isolate SOAR baseline.

---

## PHASE 3 — INTEGRATION (toward PP2, ~17–19 Aug)

Goal: replace both PP1 stubs (hand-crafted Wazuh JSON in, Python sim faking actions out) with a real loop around an emulated IoMT device, and turn the clinician placeholder into a working human-in-the-loop UI.

### A. Device-in-the-loop — emulated IoMT VM
Goal: a controllable "device" with an observable clinical service that becomes the disruption-rate instrument.

- [ ] Stand up an Ubuntu VM; take a clean baseline snapshot for repeatable runs
- [ ] Build the primary device: **ICU vitals monitor** — MQTT publisher streaming vitals (HR, SpO₂, etc.) + Mosquitto broker
- [ ] Build the **heartbeat / uptime logger** (the measurement harness's core sensor — records when the stream is up vs. interrupted)
- [ ] Install + enrol the **Wazuh agent**; confirm it reports to the manager
- [ ] *(after the loop is proven)* Add the secondary device: **DICOM radiology node (Orthanc)** + agent — maps to the RAD-LINAC-001 scenario, adds device-type diversity
- [ ] Document the VM build steps in `infra/` so it's reproducible

### B. Real ingest path — replace the JSON stubs
Goal: real activity → real Wazuh rule → real alert → enrichment shim → engine.

- [ ] Define/confirm Wazuh rules that fire on real activity:
  - [ ] SSH brute-force (drive with hydra) → SSHD rules
  - [ ] Mass file modification in a watched dir (the "ransomware" signal) → FIM / syscheck
  - [ ] Suspicious outbound beacon → connection rules
- [ ] Configure the **Wazuh integrator** to POST alerts to the shim's `/wazuh-alert` (use the PP1 `infra/wazuh/integrator-config.md`)
- [ ] Update the mapper to handle real Wazuh alert fields (vs. the hand-crafted fixtures)
- [ ] Verify end-to-end: trigger activity → rule fires → integrator → shim → engine `/decide` → decision rendered on the dashboard
- [ ] Retire / archive the hand-crafted `data/sample-wazuh-alerts/` + `post_wazuh_alert.sh` as the primary demo path

### C. Real enforcement — replace the sim's pretend actions
Goal: decisions actually do something to the device, and the safety claim becomes observable.

- [ ] `isolate_host` → **real firewall DROP** on the VM via Wazuh active-response (custom AR script)
- [ ] `block_port` → real targeted port block
- [ ] `monitored_mode` → real but **non-disruptive**: telemetry/verbosity bump + shadow-audit check + **no block** — prove the heartbeat keeps flowing
- [ ] `log_only` → log entry, no action
- [ ] Decide the enforcement trigger path: Shuffle sim triggers real actions **or** Wazuh AR fires directly *(fork from the logbook — Wazuh AR can carry it either way)*
- [ ] Wire clinician approval → real `isolate_host` on approve; stay in `monitored_mode` on deny (FR-06)
- [ ] **Build the "scoring strategy" seam** in the classifier now (so the teammate's future single-score swap is a config flip — see Phase 4 §G)

### D. Clinician approval — human-in-the-loop UI
Goal: the PP1 placeholder (`ClinicianDecisionPanel`) becomes a real Tier 3 approval interaction (FR-03, FR-04, NFR-04).

- [ ] Functional Approve / Deny flow in the dashboard, writing back through the real loop to the engine audit chain
- [ ] Keep the interface simple + context-rich (NFR-04, NFR-05 — show "Device Role: Ventilator" etc.)
- [ ] *(stretch / per proposal budget)* Mobile-friendly push notification (Twilio / Pushover) so approval reaches a clinician off-LAN

### E. Measurement harness + first validation pass
Goal: produce preliminary ≤5% numbers for PP2 (full statistical validation is Phase 4).

- [ ] Instrument device service continuity (uptime %, interruption duration) per scenario
- [ ] Run the flagship scenarios once end-to-end under the tiered engine
- [ ] Run the same scenarios under a **traditional-SOAR baseline** (always isolate) for comparison
- [ ] Produce a first disruption-rate comparison table (the PP2 "it works on a real device" evidence)

### A2. Device fidelity — speak a real clinical protocol *(panel feedback)*
Goal: answer the "you don't understand IoMT" concern by making the emulator faithful at the layer that matters — the standard clinical traffic a SIEM actually sees.

- [ ] Vitals monitor emits **HL7 v2 `ORU^R01`** vital-signs messages over **MLLP** (device #1 — fits the existing monitor; do this first)
- [ ] **DICOM** via the Orthanc node (device #2 — radiology, `RAD-LINAC-001`)
- [ ] Make at least one attack scenario protocol-aware (e.g. forged HL7 order / tampered DICOM) rather than a generic file edit
- [ ] **Demonstrate one agentless path** (Wazuh ingesting the device's network/protocol logs) to show awareness that real devices usually can't host an agent
- [ ] Make sure I can *defend* HL7/DICOM in the viva — not just name-drop it (knowledge write-up queued)

**Defense framing (for the report + viva) — the rationale, captured so it's not lost:**
- *Concession:* real IoMT devices run closed, proprietary firmware/protocols and usually can't host a security agent — so they can't be replicated on a laptop, and that's not the claim.
- *Scope:* the contribution is the **Security-vs-Life decision logic** and the **measured disruption evidence** — not the device. The device is a calibrated test rig (a "crash dummy"), which is standard research practice.
- *Why the emulation is valid:* even proprietary devices must speak **standard protocols (HL7/DICOM)** the moment they touch the hospital network — and that standardised traffic is the only thing a SIEM sees and the only thing the orchestration layer acts on. The emulator and a real device **converge at the network boundary**, which is exactly where the system operates.
- *Honest limitation:* the rig measures **service disruption directly**; the **patient harm** it implies is supported from the literature (the proposal's mortality stats), not measured — stated as a limitation.

### F. PP2 deliverables
- [ ] Update `DEMO.md` for the new real-device flow (4-terminal + VM startup)
- [ ] Record the demo (~3–5 min): trigger real attack → rule fires → tiered decision → monitored_mode keeps device alive → Tier 3 approval → isolate → chain verify
- [ ] PP2 slide deck
- [ ] Supervisor review before submission
- [ ] Update the logbook + roadmap; commit & push everything
- [ ] **Submit PP2**

---

## PHASE 4 — VALIDATION (toward Final Report, ~Sep → 11 Oct)

Goal: turn the PP2 demo into a rigorous, defensible result that satisfies the acceptance condition and the proposal's metrics.

### G. Teammate single-score tiering integration
Goal: swap the engine's current two-input matrix for the teammate's single composite score, using the seam built in §C.

- [ ] Confirm with teammate: score **range/scale**, **tier thresholds**, and whether it **encodes threat severity** or only asset criticality
- [ ] Write the adapter: single score → tier/action via the scoring-strategy seam
- [ ] Keep both modes runnable (current cc_score+CVSS *and* new single-score) for fallback + comparison
- [ ] Preserve the fail-safe (missing/invalid score → safest tier)
- [ ] Update engine tests for the new strategy; confirm all green
- [ ] Update `docs/alert-schema.md` + the decision-logic docs

### H. Full validation & stress testing — the ≤5% proof
Goal: the proposal's headline result, measured (Objective 2.1, metrics §3.5).

- [ ] Finalise **≥3 realistic scenarios** (e.g. ransomware on ventilator, exploit on anaesthesia machine, suspicious traffic on monitor — proposal requires ≥3)
- [ ] Run enough repetitions per scenario for a statistically meaningful disruption rate
- [ ] Compute + document the three metrics:
  - [ ] **Accidental disruption rate** on life-critical assets (target ≤5%) — tiered vs. baseline
  - [ ] **Response precision** (correct non-disruptive strategy chosen per asset criticality)
  - [ ] **Decision time / latency** (NFR-02 — logic adds no significant delay)
- [ ] Stress / resilience testing of the orchestration engine (NFR-03 high availability)
- [ ] Confirm auditability end-to-end: every decision + clinician action in the immutable chain (NFR-01)
- [ ] Write up results (tables, charts) for the final report

### I. Immutable logging — scope decision
- [ ] Decide blockchain anchoring scope: keep the hash-chained ledger (current) as sufficient, or add anchoring as a stretch (proposal lists it as deferrable) — document the decision either way

### J. Response-strategy depth — *core research focus, later phase*
Goal: the real research depth isn't the tiering — it's the **repertoire of responses** the engine can choose. Move beyond the current five actions to a richer set of graded, clinically-aware, non-disruptive containment strategies (the proposal's "Life-Critical Response Layer").

- [ ] Design additional response strategies beyond `log_only` / `block_port` / `isolate_host` / `monitored_mode` / `await_clinician_approval` — e.g. selective port/flow blocking, rate-limiting, micro-segmentation/VLAN quarantine, credential/session revocation, deception/honeypot redirection, heightened monitored-mode variants
- [ ] Make responses **device-type-aware** (a ventilator, an infusion pump, and a radiology node should get different safe responses)
- [ ] Map each response to its disruption cost so the engine can pick the *least-disruptive effective* option, not just a tier default
- [ ] Implement the chosen strategies as real playbook actions and measure each one's disruption under the §H harness
- [ ] This is the differentiator vs. traditional SOAR (binary block/allow) — give it the most design attention for the Final phase

#### Workstream F — the §J build (chosen strategies)

Three graded responses on a **least-disruptive-effective** spine, device-type-gated, each measured under the §H harness.

**Strategies**

- **`selective_block`** *(flagship)* — scoped DROP of the malicious flow (dest IP / port) applied at the device's network edge, leaving clinical protocols open (MQTT `1883`, HL7/MLLP `2575`). Disruption: **low**. Effective vs C2 beaconing, exfil to a known dest, exploitation of a specific service port.
- **`throttle`** — `tc` qdisc on the device interface capping egress; low-bandwidth telemetry unaffected, bulk flows choked. Disruption: **low–medium**. Effective vs exfiltration, ransomware staging, noisy scanning.
- **`quarantine`** — micro-segmentation: reuse the `docker network` primitive to move the device off the general network onto a `clinical-only` network (broker + EHR only). Disruption: **medium**; clinical path preserved. Effective vs lateral movement, worms, broad/unknown threats.

**Selection model (the contribution)** — tag each action with a disruption cost + an effectiveness set (threat categories it stops); pick the lowest-cost action that is (a) permitted for the device's `device_category` and (b) effective against the detected threat; fall back to the Tier-3 `isolate_host` approval flow as the escalation backstop. Rule-based and explainable, consistent with the existing classifier.

**Device-type gating** (from the enrichment registry's `device_category`): life-critical (ventilator / vitals) → `selective_block` / `throttle` / `quarantine`, `isolate` only via approval; imaging / radiology → + `isolate` at a lower bar; non-critical → full menu incl. `isolate`.

**Faithfulness note** — the per-flow filter is applied to the device's network interface from the orchestrator (outside the device's application / control plane), modelling an access-switch / NAC per-port ACL — the same network-edge layer as the existing `docker network disconnect`. Higher-fidelity future option: an inline L3 gateway container the device routes through.

**Phases**

- [ ] **F-1** — `selective_block` in `enforcement.py` + sim wiring + a harness scenario; measured (heartbeat ~0 downtime while the malicious flow is cut, vs isolate's full downtime).
- [ ] **F-2** — `throttle` via `tc` + harness scenario.
- [ ] **F-3** — `quarantine` via a `clinical-only` docker network + harness scenario.
- [ ] **F-4** — response-selection layer in the classifier (cost / effectiveness matrix + device-type gating) replacing the flat tier→action default; update tests + re-run validation.
- [ ] **F-5** — surface the chosen strategy + its cost in the dashboard / clinician view; produce the disruption-cost table (each response × measured clinical impact) for the write-up.

---

## PHASE 5 — OUTPUT & DELIVERY (11 Oct → 15 Oct)

### J. Final report / dissertation
- [ ] Draft chapters: Intro/Background, Lit Review, Methodology, Design & Implementation, Results/Validation, Discussion, Conclusion
- [ ] Fold in the validation results + the real-device evidence
- [ ] Supervisor review pass(es)
- [ ] **Submit final report — 11 Oct**

### K. Research paper
- [ ] Condense the contribution + results into paper format
- [ ] Internal/supervisor review
- [ ] **Submit paper — 15 Oct**

### L. Project website
- [ ] Build the project site (overview, architecture, demo, results, team)
- [ ] **Submit website — 11 Oct**

### M. Viva & final presentation
- [ ] Final presentation deck
- [ ] Rehearse the live demo (have a recorded fallback)
- [ ] Anticipate viva questions (esp. "how do you know it works on a real device?" → §H numbers)
- [ ] **Final presentation & viva — 15 Oct**

---

## Cross-cutting / ongoing (every session)

- [ ] Logbook entry at the end of each working session (reverse-chronological, Word)
- [ ] Commit & push working code; keep `main` clean
- [ ] Periodic supervisor check-ins (not just at milestones)
- [ ] Keep the running **open-questions-for-teammate** list current
- [ ] Re-snapshot the VM before each scenario-run batch (clean baseline)

---

## Open questions for the teammate (live list)

- [ ] Single-score: range/scale, thresholds, and whether it encodes threat severity (blocks §G)
- [ ] Delivery format for enriched alerts (REST API / file / stream?)
- [ ] Data scope: per-asset registry lookup or per-alert live enrichment?
- [ ] Confirm `patient_dependency` vocabulary + `time_sensitivity` scale (display-only, low priority)
