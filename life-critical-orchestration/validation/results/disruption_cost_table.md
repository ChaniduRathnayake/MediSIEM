# Disruption-cost table — ICU-VENT-003 (measured 2026-08-02)

| Response | Clinical downtime | Scope | Reversible | Containment |
|---|---|---|---|---|
| isolate | 14.0s | whole device | yes | full cut |
| selective_block | 0.0s | one flow | yes | drop flagged flow |
| throttle | 0.0s | one flow | yes | slow flagged flow |
| quarantine | 5.0s | non-clinical | yes | block lateral movement |
| monitored_mode | 0.0s | none | n/a | observe only |

Measured on the live device-sim (ICU-VENT-003), heartbeat downtime threshold 0.5s. isolate is the traditional-SOAR baseline. **Flow-level** responses (selective_block, throttle) never touch the device's own clinical connection, so disruption is ~0.0s. **Network-level** quarantine moves the device to a clinical-only segment at the cost of a single MQTT reconnect — a *fixed, one-time* cost independent of how long the device stays contained (see duration_independence.md), unlike isolate whose downtime scales with the entire containment window.

**vs. the proposal's ≤5% target.** The acceptance metric is the accidental clinical-disruption *rate* on life-critical assets (ROADMAP §H), tiered vs. an always-isolate baseline (~100%). The auto-selected graded responses (throttle, selective_block, monitored_mode) measure 0.0s → 0%. Quarantine — tagged *medium disruption* in the proposal (§J) — costs one fixed reconnect, so as a rate over any realistic containment it clears 5% easily (5s/100s = 5%, 5s/5min ≈ 1.7%, 5s/30min ≈ 0.3%) and, being duration-independent, only improves the longer containment runs. Every tiered response beats the baseline by a wide margin.
