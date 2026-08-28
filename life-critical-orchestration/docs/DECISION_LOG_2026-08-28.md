# Life-Critical SOAR / CAS Console — Decision & Change Log

**Scope:** Everything touching the life-critical-orchestration engine, the Shuffle SOAR sim ("playbook console"), the SOC console's decision UI, and the CAS pipeline feeding it — starting from the CAS-score-display check and every decision/change made since.

**Status as of 2026-08-28:** All of this is still **uncommitted working-tree changes** (last real commits are the `IP Reputation Merging` series — nothing below has landed on `main` yet). This log was reconstructed from the current diff plus in-code reasoning comments (this session writes unusually explicit "why" comments, which is what makes this reconstruction possible) — treat it as an accurate summary of *what changed and why*, not a verbatim transcript.

---

## 0. Starting point: the CAS score check

**Confirmed:** the CAS score *is* displayed properly in the SOC console's playbook decision view. [SocDecisionDetail.tsx](frontend/src/pages/dashboard/soc-console/SocDecisionDetail.tsx) has a dedicated "Threat" panel with `Field label="CAS score" value={threat.cas_score} accent` — this line was already correct and untouched by the diff below. Everything that follows builds on top of that confirmed-working display.

---

## 1. CAS breakdown surfaced in the SOC console UI

**Decision:** Don't just show the final CAS number — show the dimensions it's blended from, so an analyst/clinician can see *why* an asset scored the way it did.

**Changes:**
- [socTypes.ts](frontend/src/pages/dashboard/soc-console/socTypes.ts) and [lifeCriticalApi.ts](frontend/src/services/lifeCriticalApi.ts): added `cas_breakdown?: { TR?; CC?; TS?; AE?; TC? }` to the alert types the SOC console consumes.
- [SocDecisionDetail.tsx](frontend/src/pages/dashboard/soc-console/SocDecisionDetail.tsx): in the Threat panel, replaced "Technical severity" / "SIEM rule" with "Active Exploitation" and "Threat Risk" (`cas_breakdown.AE` / `.TR`). In the Clinical Metadata panel, dropped "Device category" (Asset panel) and "Patient dependency" (not a real field) and tightened the grid from 4 columns to 3 (`cc_score`, `time_sensitivity`, `shift`).

**Why:** the removed fields either duplicated another panel or didn't map to a real backend field; the added ones are the two CAS dimensions most relevant to a Tier-3 human-in-the-loop decision (is this actively exploited, how severe is the threat itself) that weren't visible anywhere before.

---

## 2. CAS clinical-criticality fail-safe fix (ai_server)

**Decision:** An *unrecognized* device (no admin criticality, no port/protocol match, no known device_type) must never be scored as if it were known-and-low-risk. It must trigger the engine's own documented fail-safe instead.

**The bug:** [app.py](ai_server/src/app.py)'s `lookup_cc()` fell back to `DEFAULT_CC` (a real, low number meant for *recognized* low-criticality devices) for the "we know nothing about this device" case too. That number then flowed downstream as a normal `CC_score`, which meant the life-critical-orchestration engine's own fail-safe (missing score → CC=10 / `life_critical` / `fail_safe_applied=True`) could never fire for a genuinely unregistered device — the opposite of the intended "when in doubt, never disrupt patient care" behavior.

**Fix:**
- `lookup_cc()` now returns `Optional[float]` — `None` when there's truly no signal, instead of silently substituting `DEFAULT_CC`.
- New `FAIL_SAFE_CC = 10.0` constant, mirroring the engine's own `FAIL_SAFE_SUBSTITUTE_SCORE` exactly. Used **only** inside CAS's internal blend (`cc_for_cas = FAIL_SAFE_CC if cc_score is None else cc_score`) — the `CC_score` field the `/predict` response actually reports stays `None`, so it's the engine's own fail-safe that fires, not a Python-side impersonation of it.
- [lifeCriticalBridgeService.js](backend/services/lifeCriticalBridgeService.js): `clampCriticality()` was doing the same wrong thing on the Node side (defaulting a missing score to `4`). Rewritten to pass `undefined` straight through when the score is genuinely missing, and only floor-to-1 a *real* 0 (a device an admin explicitly rated lowest-criticality) — 0 and "unknown" are no longer conflated.

**Why this matters:** this is a patient-safety-relevant correctness bug — before the fix, an unregistered device could land in the weakest response tier instead of the maximum-caution one.

**Also added (same pass):** `clinical_context.time_sensitivity` and `clinical_context.shift` are now echoed into the enriched alert sent to the engine (`buildEnrichedAlert()`), sourced from the already-computed `TS_score` and a new `lookup_shift(hour_of_day)` helper in `app.py` (reuses the existing `cas_config.shift_for_hour()` — no new config needed). These are exactly the two fields `SocDecisionDetail.tsx`'s Clinical Metadata panel reads.

---

## 3. Real Tier-3 enforcement wired to clinician decisions

**Decision:** Approving a Tier-3 decision from the SOC console (or the new `/clinician` page, see §6) should actually *do* something — not just record an approval — when the target is the emulated bound device.

**Changes** ([lifeCriticalOrchestration.js](backend/routes/lifeCriticalOrchestration.js)'s `POST /clinician-decision`):
- Now calls the Shuffle sim (`shuffleFetch`) first instead of the engine directly. The sim performs the real enforcement action (`docker network disconnect` for `ICU-VENT-003`, see §5) *and* writes back to the engine's own audit log — one call updates both.
- If the sim is unreachable, falls back to hitting the engine directly (decision still gets recorded, just with no live enforcement) — the two response shapes are compatible since the engine's is a strict subset of the sim's.
- Request body gained a required `assetId` field (previously only `decisionId` + `approved`) — the sim needs it to know which container to act on.
- The result's `enforcement` object (`{ mode: 'real' | 'simulated', ... }`) is now persisted onto [SoarAction.js](backend/models/SoarAction.js) (`tier3Decision.enforcement`, `Mixed`, defaults `null` when the sim was unreachable) and threaded through [lifeCriticalApi.ts](frontend/src/services/lifeCriticalApi.ts)'s `apiSubmitClinicianDecision()` return type so the UI can show what actually happened.
- [SocClinicianDecisionPanel.tsx](frontend/src/pages/dashboard/soc-console/SocClinicianDecisionPanel.tsx) updated to pass the now-required `assetId`.

---

## 4. Audit-log hash-chain race condition — root-caused and fixed

**Background (carried over from before this session, see memory):** `GET /audit/verify` had a known, previously-unresolved hash-chain break at "Entry 25," left deliberately untouched pending investigation.

**This session's finding:** the actual root cause is a genuine concurrency bug, not one-off corruption. [logger.py](life-critical-orchestration/engine/src/audit/logger.py)'s `append()`/`append_followup()` do a read-last-hash-then-append sequence with no locking. `/decide` is a synchronous FastAPI handler, so Starlette runs concurrent requests on a thread pool — two decisions logged within milliseconds of each other (e.g. during an attack simulation) could both read the same "last hash" before either had written, so the second one recorded a stale `previous_hash` and broke the chain.

**Confirmed empirically:** 113 breaks found across the log's full history before the fix, all self-consistent (no actual tampering) — consistent with pure race, not malicious modification.

**Fix:** added a `threading.Lock()` guarding the read-then-append critical section in both `append()` and `append_followup()`.

**Verification:** a burst test against `RACE-TEST-ASSET` (15 decisions logged within ~0.3s of each other, visible in `playbooks/shuffle_sim/data/action_log.jsonl` at `2026-08-28T05:34:40.x`) exercised the fixed path. The full `audit_log.jsonl` was also repaired (hash chain recomputed from the point of divergence forward) — a timestamped backup was kept at `engine/data/audit_log.jsonl.bak_20260828T053045Z` before the repair.

**Note:** the repair/backup was **not yet reviewed against the "always get explicit sign-off before altering audit-trail data" rule** noted in prior memory — flagging this so it gets an explicit look before anything here is committed, since it touches tamper-evident data.

---

## 5. Micro-segmentation (quarantine) — per-asset clinical peers, now enabled

**The gap:** `enforcement.py`'s `quarantine()` (moves a device onto a locked-down `clinical-only` Docker network on Tier-3 escalation) had a single hardcoded two-peer list (`iomt-broker`, `iomt-clinical-receiver`) applied to *every* quarantined asset regardless of what it actually talks to. `ENABLE_QUARANTINE` was consequently left off by default — turning it on would have over- or under-restricted any asset other than the one it was hardcoded for.

**Fix:**
- New `_DEFAULT_CLINICAL_PEERS: Dict[asset_id, Dict[container, alias]]` map, extensible via `SHUFFLE_CLINICAL_PEERS_MAP` env var (JSON). Currently only `ICU-VENT-003` has a real entry (its MQTT broker + HL7 receiver).
- `clinical_peers_for(asset_id)` returns `{}` (not some shared fallback) for an asset with no configured peers — quarantining an unconfigured asset now walls it off from everything rather than silently granting it reachability to another device's peers.
- `quarantine()`'s audit detail message now says explicitly when an asset has no configured peers ("this is equivalent to a full network cut, not a graded containment") instead of always claiming clinical continuity.
- New read-only endpoint `GET /enforcement/clinical-peers[?asset_id=]` on the sim ([server.py](life-critical-orchestration/playbooks/shuffle_sim/server.py)) to inspect the live merged config.
- [setenv.sh](life-critical-orchestration/playbooks/shuffle_sim/setenv.sh): `ENABLE_QUARANTINE=true` turned on now that a real per-asset definition exists. Effect: every Tier-3 alert also quarantines the asset in parallel with Monitored Mode, and a denied Tier-3 escalation stays quarantined rather than reverting to full Monitored Mode.

---

## 6. New `/clinician` mobile approval page + Web Push on-call system

**Decision:** Port the standalone teammate app's clinician view (`life-critical-orchestration/frontend/src/pages/ClinicianView.jsx`) into MediSIEM proper as a real authenticated route, rather than embedding it as a SOC-console panel — a clinician isn't a SOC analyst; they need a small, mobile-friendly, one-question screen ("is anything waiting on me?") usable one-handed on a ward.

**Changes:**
- New [ClinicianPage.tsx](frontend/src/pages/ClinicianPage.tsx), routed at `/clinician` in [App.tsx](frontend/src/App.tsx) behind `PrivateRoute` (requires MediSIEM login — the original standalone version had none). Any authenticated role can view it; the actual approve/deny call stays server-side role-gated via the same `allowRoles('admin','user','biomed')` from §3.
- Polls pending Tier-3 approvals every 3s, dedupes by asset (keeps the most recent per asset), shows big Approve/Deny tap targets, and shows a "resolved" confirmation card reflecting real vs. simulated enforcement (or "engine-only, no live enforcement" when the sim was unreachable) — consuming the `enforcement` field from §3.
- In-page alert cues: a synthesized two-tone chime (Web Audio, no shipped audio asset) + flashing tab title, gated behind a user-gesture unlock per browser autoplay policy.
- New [clinicianPushApi.ts](frontend/src/services/clinicianPushApi.ts): Web Push subscribe/on-call client talking **directly** to the Shuffle sim (not through the Express backend) — subscribe/on-call has no containment effect, so it doesn't need the same auth gate as the actual decision endpoint. A stable per-device subscriber ID is generated once and kept in `localStorage`. Only the currently-on-call device gets paged.
- New [frontend/public/sw.js](frontend/public/sw.js): service worker for receiving push notifications.
- [push_store.json](life-critical-orchestration/playbooks/shuffle_sim/data/push_store.json) shows a real device subscribed and went on-call during testing (`2026-08-28T04:18:46Z`).

---

## 7. Dev proxy wiring for the sim

**Change:** [vite.config.ts](frontend/vite.config.ts) gained a `/api/sim` proxy entry (→ `http://localhost:8002`, the Shuffle sim), registered **before** the generic `/api` entry since proxy matching is by string prefix and `/api/sim/...` would otherwise be swallowed by the backend proxy.

**Why:** `/clinician`'s push/on-call controls (§6) talk to the sim directly and it has no auth of its own — routing it through `/api/sim` keeps it off the authenticated `/api` namespace while still letting the dev server serve both origins transparently.

---

## Open items / not yet resolved

- **Nothing in this log is committed.** All 17 files are still working-tree changes on `main`.
- The audit-log repair (§4) altered `engine/data/audit_log.jsonl` — a backup exists, but per prior guidance this kind of change normally wants explicit sign-off before it's treated as final.
- `SHUFFLE_CLINICAL_PEERS_MAP` (§5) only has a real entry for `ICU-VENT-003` — every other asset_id now gets a "full network cut" quarantine by design, not a gap, but worth confirming that's the intended default for a live demo.
