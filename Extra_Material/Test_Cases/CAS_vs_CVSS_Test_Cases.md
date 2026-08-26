# CAS vs CVSS — Test Case Specification & Results

All numbers on this page were produced by actually running
`Extra_Material/Test_Cases/test_cas_vs_cvss_scenarios.py`, which calls the real
scoring engine (`ai_server/src/cas_engine.score_alert()` and
`ai_server/src/cas_config.lookup_cvss()`, backed by the single source of truth
`shared/cas_config.json`) — nothing here is hand-computed. Run the script yourself
to reproduce:

```
python Extra_Material/Test_Cases/test_cas_vs_cvss_scenarios.py
```

Last run: **22/22 checks PASSED**.

## Background

**CAS (Clinical Alert Score)**:
`CAS = 2 × (0.25·TR + 0.30·CC + 0.25·TS + 0.10·AE + 0.10·TC)`, each dimension
scored 1–5, so CAS lands on 0–10.

| Dimension | Meaning | Driven by |
|---|---|---|
| TR | True-positive confidence | Model prediction confidence |
| CC | Clinical Criticality | FDA 21 CFR §860.3 device class, resolved from destination port |
| TS | Threat Severity | Isolation Forest anomaly score |
| AE | Active Exploitation | Attack-type base severity (+ known-exploited-CVE boost) |
| TC | Temporal Context | Shift (day / evening / night) |

Action thresholds: **CAS ≥ 8.0 → Immediate**, **CAS ≥ 5.0 → Investigate**, else
**Monitor** (and `Benign` always forces Monitor regardless of the numeric score).

**CVSS-equivalent baseline**: a fixed CVSS v3.1 base-score band per attack
technique's general CWE class (`shared/cas_config.json`'s `cvss_base_by_label`) —
DoS_TCP 7.5, MQTT_Publish_Flood 7.5, MQTT_Brute_Force 8.1, ARP_Spoofing 6.5,
Recon 3.1, Benign 0.0. No CVE field exists anywhere in the dataset, so this is
deliberately the closest fair baseline: it varies by attack technique **and
nothing else** — never by device, never by time, never by how confident the
detector is. That single property is what every test case below is designed to
expose.

---

## TC1 — Device Criticality (CC) Sensitivity

**Objective:** prove CVSS is device-blind while CAS is not.

**Input:** identical alert (`DoS_TCP`, confidence 0.95, IF score −0.40,
anomaly=True, day shift) fired at two different devices.

| Device | Port | FDA Class | CVSS | CAS | Action |
|---|---|---|---|---|---|
| ICU Ventilator | 4000 | III | 7.5 | **9.2** | Immediate |
| Admin / Clerical Workstation | 4054 | I | 7.5 | **6.8** | Investigate |

**Pass criteria:** CVSS identical; CAS gap ≥ 2.0 points; action tiers differ.
**Verdict:** PASS.

**Why CVSS can't show this:** CVSS is a property of the vulnerability/attack
technique alone — it has no device field to vary on. The exact same "DoS_TCP,
7.5" verdict is returned whether the target is a ventilator keeping someone
alive or an admin PC. CAS's CC dimension is what closes that gap.

---

## TC2 — Temporal Context (TC) Sensitivity

**Objective:** prove CAS reflects reduced night-shift response capacity; CVSS
cannot.

**Input:** identical alert (`ARP_Spoofing`, confidence 0.90, anomalous,
`Bedside Patient Monitor`, port 4002) fired at two different times.

| Shift | CVSS | CAS | Action |
|---|---|---|---|
| Day | 6.5 | **7.4** | Investigate |
| Night | 6.5 | **8.2** | Immediate |

**Pass criteria:** CVSS identical; CAS crosses the Investigate→Immediate
boundary from shift alone.
**Verdict:** PASS.

**Why CVSS can't show this:** a hospital SOC is realistically thinner-staffed
at 2 a.m. than at 2 p.m., so the same intrusion is objectively higher-risk at
night. CVSS has no time axis at all; CAS's TC dimension does.

---

## TC3 — Detection Confidence (TR) Sensitivity

**Objective:** prove CAS discounts a shaky detection while CVSS treats every
detection of the same attack type identically, however uncertain.

**Input:** identical alert (`MQTT_Brute_Force`, `MQTT Broker` port 1883,
evening shift) with two different model confidences.

| Confidence | CVSS | CAS | Action |
|---|---|---|---|
| 0.97 (near-certain) | 8.1 | **8.8** | Immediate |
| 0.55 (barely above threshold) | 8.1 | **7.3** | Investigate |

**Pass criteria:** CVSS identical; CAS(high) > CAS(low); action tiers differ.
**Verdict:** PASS.

**Why CVSS can't show this:** CVSS scores the vulnerability class, not the
trustworthiness of a specific detection event — it has no confidence input.
CAS's TR dimension prevents a knee-jerk "Immediate" response to a
barely-above-threshold classification.

---

## TC4 — Alert Ranking Inversion (headline case)

**Objective:** show CVSS-only triage can rank alerts in the wrong clinical
order; CAS corrects it. This is the direct evidence for the report's central
claim.

**Input:** two simultaneous alerts.

| Alert | Attack | Device | CVSS | CAS |
|---|---|---|---|---|
| X | Recon (port scan) | ICU Ventilator (4000, Class III) | 3.1 | **7.4** |
| Y | DoS_TCP | Admin Workstation (4054, Class I) | 7.5 | 6.8 |

**Result:** under CVSS-only triage, an analyst works **Y first** (7.5 ≫ 3.1) —
a reconnaissance probe against a life-support ventilator sits at the bottom of
the queue. Under CAS, the analyst works **X first** (7.4 > 6.8) — a full rank
inversion.

**Pass criteria:** `CVSS_X < CVSS_Y` **and** `CAS_X > CAS_Y` simultaneously.
**Verdict:** PASS.

**Why this matters:** CVSS's wide gap (7.5 vs 3.1) is driven entirely by attack
technique. CAS's narrower but inverted gap (7.4 vs 6.8) is driven by context —
which alert actually threatens a patient right now. This is the single
clearest evidence that CVSS-based triage is clinically blind.

---

## TC6 — Benign Convergence (no cry-wolf)

**Objective:** confirm CAS doesn't alarm-fatigue staff on benign traffic even
under worst-case device/time conditions — a safety check, not a divergence
case.

**Input:** `Benign` traffic on the ICU Ventilator (port 4000) with an
anomalous-looking IF score and night shift — every dimension except AE is
pushed toward its ceiling.

| | CVSS | CAS (numeric) | Action |
|---|---|---|---|
| Benign on ICU Ventilator, night | 0.0 | 7.0 | **Monitor** |

**Pass criteria:** action is `Monitor` regardless of the numeric CAS; CVSS is
0.0.
**Verdict:** PASS.

**Why it matters:** the `Benign` label overrides the numeric CAS in
`get_action()` — this is deliberate: no combination of device criticality or
timing should turn confirmed-benign traffic into a false alarm. CVSS agrees
(0.0) for the same reason CVSS scores nothing for a non-attack. This is the one
case where CAS and CVSS are expected to converge, and both do.

---

## TC7 — Action-Threshold Boundary Correctness

**Objective:** guard the two constants (8.0 and 5.0) that every conclusion
above depends on.

| CAS | Action |
|---|---|
| 8.00 | Immediate |
| 7.99 | Investigate |
| 5.00 | Investigate |
| 4.99 | Monitor |
| 0.00 | Monitor |

**Pass criteria:** exact match at every boundary.
**Verdict:** PASS.

---

## TC5 / TC8 — Batch-Level Companions (live system run)

TC1–TC7 above are controlled, single-alert unit tests. The following two
batch-level evaluations answer the same question ("does CAS beat CVSS?") at
scale, across 200 simulated alerts per hospital scenario
(`icu_critical_care`, `general_ward_admin`, `hospital_wide_mixed`). They are
implemented in `ai_server/src/hospital_scenarios.py`, and are run here via
`run_hospital_scenarios_live.py` (a scriptable, non-notebook path — same
functions `ai_server/05_evaluation.ipynb` uses) against the real trained
RF/IsolationForest/K-Means models in `ai_server/models/` and the real
held-out `data/test/*.csv` rows. Not part of the CI regression suite (that
needs no model artifacts by design); run manually whenever the models or
`shared/cas_config.json` change.

**TC5 — Alert Ranking Accuracy / Fatigue Reduction**
(`build_caap_vs_cvss_table()`): for each scenario, compares CAS vs CVSS on:
- **ARA@5/10/20** — % of life-critical alerts ranked in the top N
- **MTCAI** — mean rank position of life-critical alerts (lower = surfaced faster)
- **FPR@10** — % of the top-10 ranked alerts that are actually low/no
  patient-dependency
- **Alert Fatigue Reduction %** — relative drop in FPR@10 versus CVSS

**Live result** (`run_hospital_scenarios_live.py`, real trained models + real
1,614,182-row held-out test set, 600 simulated alerts / 185 life-critical,
run 2026-08-24):

| Scenario | n | n life-critical | ARA@10 CAS | ARA@10 CVSS | MTCAI CAS | MTCAI CVSS | FPR@10 CAS | FPR@10 CVSS | Fatigue Reduction |
|---|---|---|---|---|---|---|---|---|---|
| ICU / Critical Care | 200 | 103 | 9.71% | 6.8% | 66.7 | 99.5 | 0.0% | 30.0% | 100.0% |
| General Ward / Admin | 200 | 24 | 20.83% | 8.33% | 36.3 | 102.0 | 50.0% | 80.0% | 37.5% |
| Hospital-Wide Mixed | 200 | 58 | 17.24% | 8.62% | 54.8 | 110.0 | 0.0% | 50.0% | 100.0% |
| **ALL COMBINED** | 600 | 185 | **5.41%** | 3.78% | **150.2** | 266.0 | **0.0%** | 30.0% | **100.0%** |

CAS wins on every metric in every scenario except one (General Ward's FPR@10,
where CAS still nearly halves CVSS's 80% down to 50%) — the aggregate,
system-level version of TC4's single-alert ranking inversion. **Verdict: PASS.**

Output in this folder: `hospital_scenarios_raw.csv` (per-alert raw data),
`caap_vs_cvss_results.csv` (summary table), `caap_vs_cvss_comparison.png`
(chart), `live_run_summary.md` (auto-generated narrative).

**TC8 — Weight-Perturbation Rank Stability**
(`sensitivity_analysis()`): perturbs each CAS weight by ±5% (renormalized) and
recomputes CAS, reporting Spearman rank correlation against the unperturbed
baseline. This doubles as a comparison point in its own right: CVSS has *no*
tunable weighting mechanism at all, so it can't be checked for
robustness-to-tuning the way CAS can.

**Live result:** largest mean score shift from a single ±0.05 perturbation is
0.234 points (AE, Δ=−0.05); the least rank-stable perturbation (AE, Δ=+0.05)
still preserves a Spearman rank correlation of **0.982** against the
baseline-weight ranking, and every other dimension stays above 0.99. CAS's
prioritisation order does not flip under plausible re-weighting. **Verdict: PASS.**

Output in this folder: `cas_sensitivity_analysis.csv` and
`cas_sensitivity_analysis.png`.

**To regenerate TC5/TC8:** `python Extra_Material/Test_Cases/run_hospital_scenarios_live.py`
(needs the trained model artifacts in `ai_server/models/` and the held-out
test set in `ai_server/data/test/` — both already present locally). This
overwrites the CSVs/PNGs/summary in this folder directly; no notebook or
manual re-copy step needed.

---

## Summary Table

| Test Case | Dimension isolated | CVSS behavior | CAS behavior | Verdict |
|---|---|---|---|---|
| TC1 | CC (device criticality) | Constant (7.5) | 9.2 vs 6.8 | PASS |
| TC2 | TC (temporal context) | Constant (6.5) | 7.4 vs 8.2 | PASS |
| TC3 | TR (detection confidence) | Constant (8.1) | 8.8 vs 7.3 | PASS |
| TC4 | Combined (ranking) | 3.1 < 7.5 | 7.4 > 6.8 (inverted) | PASS |
| TC6 | AE / label override | 0.0 | Monitor (safe) | PASS |
| TC7 | Threshold boundaries | n/a | exact | PASS |
| TC5 | Batch ranking accuracy (live, n=600) | ARA@10 3.78%, FPR@10 30.0% | ARA@10 5.41%, FPR@10 0.0% | PASS |
| TC8 | Weight robustness (live, n=600) | no equivalent mechanism | Spearman ≥ 0.982 (all dims) | PASS |
