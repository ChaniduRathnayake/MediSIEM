// Bridges a CAAP-scored MediSIEM alert to the teammate's Security-vs-Life
// Decision Engine (life-critical-orchestration/engine, FastAPI on :8000).
// Fire-and-forget, mirroring the same non-blocking pattern the engine itself
// already uses to push decisions onward to Shuffle — if the engine is down
// or slow, MediSIEM's own alert pipeline is never delayed or affected.
//
// Schema this builds: life-critical-orchestration/docs/alert-schema.md (v1.0).

import AlertLog from '../models/AlertLog.js';

const { LIFE_CRITICAL_ENGINE_URL = 'http://localhost:8000' } = process.env;

// Visibility into fire-and-forget failures — a down engine should never be
// silent beyond a console line (see the Technical Integration Guide's §5.4).
// Deliberately in-memory only; this is operational visibility, not an
// audit trail (the engine's own hash-chained audit log is that).
const stats = {
  pushed: 0,
  failed: 0,
  lastError: null,
  lastErrorAt: null,
  lastDecision: null,
};

export function getLifeCriticalBridgeStats() {
  return { ...stats, engineUrl: LIFE_CRITICAL_ENGINE_URL };
}

// Wazuh's own `rule.groups` tagging vocabulary for ransomware-shaped rules
// (FIM/syscheck mass-modification rulesets commonly tag this way), plus a
// plain-text fallback over the rule description for setups that don't use
// the group taxonomy. Best-effort — MediSIEM's live ML-classification path
// has no ransomware-specific label, so this exists for the direct-Wazuh-rule
// fallback path, not the primary flow_consumer.py demo path.
const RANSOMWARE_GROUP_HINTS = ['ransomware'];
const RANSOMWARE_DESCRIPTION_PATTERN = /ransomware/i;

function isRansomwareHint(displayAlert) {
  if (Array.isArray(displayAlert.ruleGroups) && displayAlert.ruleGroups.some((g) => RANSOMWARE_GROUP_HINTS.includes(String(g).toLowerCase()))) {
    return true;
  }
  return RANSOMWARE_DESCRIPTION_PATTERN.test(displayAlert.ruleDescription || '');
}

// Category the engine's hard override actually checks for (classifier.py's
// EXTREME_THREAT_CATEGORIES = {"ransomware", "active_exploitation"}). Falls
// through to the raw ML label when neither override condition is met — the
// label doesn't match the engine's override vocabulary, but is still useful
// as display/audit text (see docs/alert-schema.md's threat.category: "free
// string, optional").
function resolveCategory(displayAlert) {
  if (isRansomwareHint(displayAlert)) return 'ransomware';
  if (displayAlert.cveKnownExploited) return 'active_exploitation';
  return displayAlert.label || undefined;
}

// clinical_context.criticality_score is required 1-10 (Pydantic ge=1) —
// MediSIEM's CC_score can legitimately be 0 for the lowest-criticality
// devices, which would otherwise get every one of those alerts silently
// 422-rejected by the engine. Floor of 1 still lands correctly in the
// engine's non_critical band (threshold is < 5).
function clampCriticality(ccScore) {
  const raw = Number(ccScore ?? 4);
  const rounded = Math.round(Number.isFinite(raw) ? raw : 4);
  return Math.min(10, Math.max(1, rounded));
}

// Readable name preferred over the raw IP, per explicit instruction — a real
// Wazuh agent.id (unique, stable) still wins when present. NOTE: for the
// flow_consumer.py live-capture path, agent.name is device_map.json's
// device_type (e.g. "ICU Ventilator"), which is NOT guaranteed unique across
// two physical units of the same device type — the pending-approval tray,
// audit log, and Shuffle actions all key off asset_id, so two same-type
// devices alerting concurrently would currently be tracked as one asset.
// Not a concern for a single-device demo; worth a real per-device key (e.g.
// device_map.json entries keyed by a unique asset tag, not just IP) before
// this runs against a multi-device fleet.
function buildEnrichedAlert(raw, displayAlert) {
  const assetId = String(
    raw.agent?.id ?? raw.agent?.name ?? displayAlert.deviceType ?? displayAlert.agent ?? raw.agent?.ip ?? 'unknown-asset'
  );

  return {
    alert_id: String(displayAlert.id),
    timestamp: new Date(displayAlert.timestamp || Date.now()).toISOString(),
    source: {
      siem: 'wazuh',
      rule_id: displayAlert.ruleId ?? undefined,
      rule_description: displayAlert.ruleDescription ?? undefined,
      rule_level: displayAlert.ruleLevel ?? undefined,
    },
    threat: {
      category: resolveCategory(displayAlert),
      cvss_score: typeof displayAlert.CVSS === 'number' ? displayAlert.CVSS : undefined,
      // The validated, blended MediSIEM score — the classifier prefers this
      // over cvss_score the moment it's present (see engine/src/decision/classifier.py).
      cas_score: typeof displayAlert.CAS === 'number' ? displayAlert.CAS : undefined,
      cas_breakdown: {
        TR: displayAlert.TR_score,
        CC: displayAlert.CC_score,
        TS: displayAlert.TS_score,
        AE: displayAlert.AE_score,
        TC: displayAlert.TC_score,
      },
      indicators: {
        src_ip: displayAlert.src_ip || raw.src_ip || undefined,
        dst_ip: displayAlert.dstIp || undefined,
        dst_port: displayAlert.dstPort ?? undefined,
      },
    },
    asset: {
      asset_id: assetId,
      hostname: raw.agent?.name ?? undefined,
      ip_address: raw.agent?.ip ?? undefined,
      department: displayAlert.department ?? undefined,
    },
    clinical_context: {
      criticality_score: clampCriticality(displayAlert.CC_score),
    },
    enrichment_meta: {
      enriched_at: new Date().toISOString(),
      enricher_version: 'medisiem-caap-1.0.0',
      confidence: typeof displayAlert.confidence === 'number' ? displayAlert.confidence : undefined,
    },
  };
}

/**
 * Fire-and-forget push to the decision engine. Resolves with the Decision on
 * success (also persisted onto the matching AlertLog row); never throws —
 * callers that don't need the result can call this without awaiting or
 * catching, same as the engine's own push-to-Shuffle pattern.
 */
export async function pushToLifeCriticalEngine(raw, displayAlert) {
  try {
    const payload = buildEnrichedAlert(raw, displayAlert);
    const res = await fetch(`${LIFE_CRITICAL_ENGINE_URL}/decide`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`engine responded ${res.status}: ${body.slice(0, 300)}`);
    }

    const decision = await res.json();
    stats.pushed += 1;
    stats.lastDecision = { alertId: displayAlert.id, tier: decision.tier, action: decision.action, at: new Date().toISOString() };

    // $set explicitly — this write must only touch these three fields. The
    // base AlertLog row for this alert is written separately by
    // alertPipeline.js (racing with this fire-and-forget call in either
    // order); an un-prefixed update object here would be treated as a full
    // document replacement and could wipe out CAS/action/severity/etc.
    // depending on which write lands second.
    AlertLog.findOneAndUpdate(
      { alertId: String(displayAlert.id) },
      {
        $set: {
          lifeCriticalTier: decision.tier ?? null,
          lifeCriticalAction: decision.action ?? null,
          lifeCriticalDecisionId: decision.decision_id ?? null,
        },
        $setOnInsert: { alertId: String(displayAlert.id), timestamp: new Date(displayAlert.timestamp || Date.now()) },
      },
      { upsert: true }
    ).catch((err) => console.warn('[lifeCriticalBridge] AlertLog decision write failed:', err.message));

    return decision;
  } catch (err) {
    stats.failed += 1;
    stats.lastError = err.message;
    stats.lastErrorAt = new Date().toISOString();
    throw err;
  }
}
