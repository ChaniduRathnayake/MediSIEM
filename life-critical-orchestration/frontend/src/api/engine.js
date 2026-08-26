// Minimal client for the decision engine.
//
// Requests go through the Vite dev-server proxy (/api/engine → :8000,
// /api/sim → :8002; see vite.config.js) rather than straight to
// localhost:8000/8002. This keeps everything same-origin, which is what
// makes the app work unchanged on a phone over LAN HTTPS — a hardcoded
// localhost would resolve to the phone itself, and an http:// call from an
// https:// page would be blocked as mixed content. On the dev machine the
// proxy just forwards to localhost, so nothing changes there.
//
// The Shuffle sim path stays optional — calls fall back gracefully when
// it's unreachable so the dashboard remains useful without the SOAR sim.

const BASE_URL = "/api/engine";
const SHUFFLE_SIM_URL = "/api/sim";

async function handle(response) {
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Engine ${response.status}: ${text || response.statusText}`);
  }
  return response.json();
}

async function handleShuffle(response) {
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Shuffle ${response.status}: ${text || response.statusText}`);
  }
  return response.json();
}

export async function decide(alert) {
  const res = await fetch(`${BASE_URL}/decide`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(alert),
  });
  return handle(res);
}

export async function getAuditLog() {
  const res = await fetch(`${BASE_URL}/audit`);
  return handle(res);
}

export async function verifyAuditChain() {
  const res = await fetch(`${BASE_URL}/audit/verify`);
  return handle(res);
}

export async function checkHealth() {
  const res = await fetch(`${BASE_URL}/health`);
  return handle(res);
}

// Returns recently classified alerts (newest first), each shaped as
// { alert: <engine v1.0 alert>, decision: <engine response> }.
// Backed by an in-memory ring buffer on the engine side, so it resets
// on engine restart. Used by the dashboard's live mode to surface
// alerts injected via the enrichment shim.
export async function getRecentAlerts(limit = 50) {
  const res = await fetch(`${BASE_URL}/alerts/recent?limit=${limit}`);
  return handle(res);
}

// Submit a clinician's approve/deny response for a Tier 3 decision.
// Posts to the Shuffle sim, which records the playbook-side action AND
// calls back into the engine's audit log. Falls back to posting directly
// to the engine if the sim is unreachable, so the demo still works.
export async function submitClinicianDecision({ decisionId, assetId, approved, clinicianId = "clinician-on-call" }) {
  // Try Shuffle sim first (the production path)
  try {
    const res = await fetch(`${SHUFFLE_SIM_URL}/clinician-decision`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        decision_id: decisionId,
        asset_id: assetId,
        approved,
        clinician_id: clinicianId,
      }),
    });
    if (res.ok) return res.json();
    // fall through to engine fallback
  } catch (_) {
    // Sim unreachable — fall through to direct engine call
  }
  // Direct engine fallback so the demo flow still works without the sim
  const fallback = await fetch(`${BASE_URL}/clinician-decision`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      decision_id: decisionId,
      approved,
      clinician_id: clinicianId,
    }),
  });
  return handle(fallback);
}

// Returns the latest clinician follow-up for each Tier 3 decision_id.
// Shape: { "<decision_id>": {...followup...}, ... }
export async function getClinicianDecisions() {
  const res = await fetch(`${BASE_URL}/clinician-decisions`);
  return handle(res);
}

// ---------- Shuffle sim ----------
//
// Calls go directly to the sim's HTTP server. All Shuffle-related calls
// catch network errors and return safe empties so a stopped sim never
// breaks the dashboard.

export async function getShuffleHealth() {
  try {
    const res = await fetch(`${SHUFFLE_SIM_URL}/health`);
    if (!res.ok) return null;
    return res.json();
  } catch (_) {
    return null;
  }
}

export async function getShuffleActionsByDecision(decisionId) {
  if (!decisionId) return [];
  try {
    const res = await fetch(
      `${SHUFFLE_SIM_URL}/actions/by-decision?decision_id=${encodeURIComponent(decisionId)}`
    );
    if (!res.ok) return [];
    return res.json();
  } catch (_) {
    return [];
  }
}

export async function getShuffleActionsByAsset(assetId, limit = 100) {
  if (!assetId) return [];
  try {
    const res = await fetch(
      `${SHUFFLE_SIM_URL}/actions/by-asset?asset_id=${encodeURIComponent(assetId)}&limit=${limit}`
    );
    if (!res.ok) return [];
    return res.json();
  } catch (_) {
    return [];
  }
}

export async function getRecentShuffleActions(limit = 100) {
  try {
    const res = await fetch(`${SHUFFLE_SIM_URL}/actions?limit=${limit}`);
    if (!res.ok) return [];
    return res.json();
  } catch (_) {
    return [];
  }
}

// ---------- Enforcement ----------
//
// Reconnects a network-isolated device (docker network connect under the
// hood, or a simulated no-op for assets with no bound container). Used by
// the SOC dashboard to reset a device between demo runs — this is an
// ops/demo action, not something exposed to the clinician view.
export async function releaseEnforcement(assetId) {
  const res = await fetch(
    `${SHUFFLE_SIM_URL}/enforcement/release?asset_id=${encodeURIComponent(assetId)}`,
    { method: "POST" }
  );
  return handleShuffle(res);
}
