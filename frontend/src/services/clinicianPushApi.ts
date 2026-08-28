// Web Push client for the /clinician page — subscribes the on-call
// clinician's device directly to the Shuffle sim (life-critical-orchestration
// /playbooks/shuffle_sim), via the /api/sim dev-server proxy (see
// vite.config.ts). The sim has no auth of its own; reaching it at all still
// requires being logged into MediSIEM first, since /clinician itself is a
// PrivateRoute — but the actual approve/deny decision goes through the
// backend's authenticated, role-gated endpoint instead of this module (see
// apiSubmitClinicianDecision in lifeCriticalApi.ts), never straight to the
// sim, so push/on-call staying auth-free here doesn't weaken that gate.
//
// Ported from life-critical-orchestration/frontend/src/api/push.js.

const SIM = '/api/sim';

export interface PushConfig {
  configured: boolean;
  reason?: string;
  vapid_public_key?: string;
  count: number;
  on_call: string | null;
  subscribers: { subscriber_id: string; label: string; on_call: boolean }[];
}

// A stable per-device id so the sim can tell devices apart and know which one
// is on-call. Generated once and kept in localStorage.
export function getSubscriberId(): string {
  let id = localStorage.getItem('oncall_subscriber_id');
  if (!id) {
    id = 'sub-' + (crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2));
    localStorage.setItem('oncall_subscriber_id', id);
  }
  return id;
}

export function getDeviceLabel(): string {
  return localStorage.getItem('oncall_device_label') || '';
}

export function setDeviceLabel(label: string): void {
  localStorage.setItem('oncall_device_label', label || '');
}

function urlBase64ToUint8Array(base64String: string): Uint8Array {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  return out;
}

export function pushSupported(): boolean {
  return 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
}

export async function getPushConfig(): Promise<PushConfig> {
  const res = await fetch(`${SIM}/push/config`);
  if (!res.ok) throw new Error(`Sim ${res.status}`);
  return res.json();
}

export async function getOnCall(): Promise<PushConfig | null> {
  try {
    const res = await fetch(`${SIM}/push/on-call`);
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export async function setOnCall(subscriberId: string | null): Promise<PushConfig> {
  const res = await fetch(`${SIM}/push/on-call`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subscriber_id: subscriberId ?? null }),
  });
  if (!res.ok) throw new Error(`Sim ${res.status}: ${await res.text()}`);
  return res.json();
}

// Full subscribe flow: register the SW, ask permission, subscribe via the
// PushManager using the sim's VAPID key, and register the subscription with
// the sim. Returns { subscriberId, config } or throws with a friendly reason.
export async function enablePush({ label = '' }: { label?: string } = {}): Promise<{ subscriberId: string; config: PushConfig }> {
  if (!pushSupported()) {
    throw new Error("This browser doesn't support notifications.");
  }

  const config = await getPushConfig();
  if (!config.configured || !config.vapid_public_key) {
    throw new Error(config.reason || "Push isn't configured on the server yet (VAPID keys missing).");
  }

  const permission = await Notification.requestPermission();
  if (permission !== 'granted') {
    throw new Error('Notification permission was not granted.');
  }

  const registration = await navigator.serviceWorker.register('/sw.js');
  await navigator.serviceWorker.ready;

  let subscription = await registration.pushManager.getSubscription();
  if (!subscription) {
    subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(config.vapid_public_key) as BufferSource,
    });
  }

  const subscriberId = getSubscriberId();
  if (label) setDeviceLabel(label);

  const res = await fetch(`${SIM}/push/subscribe`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      subscriber_id: subscriberId,
      subscription: subscription.toJSON(),
      label: label || getDeviceLabel(),
    }),
  });
  if (!res.ok) throw new Error(`Sim ${res.status}: ${await res.text()}`);

  return { subscriberId, config: await res.json() };
}

export async function disablePush(): Promise<void> {
  const subscriberId = getSubscriberId();
  try {
    const reg = await navigator.serviceWorker.getRegistration();
    const sub = reg && (await reg.pushManager.getSubscription());
    if (sub) await sub.unsubscribe();
  } catch {
    // best-effort local cleanup
  }
  await fetch(`${SIM}/push/unsubscribe`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subscriber_id: subscriberId }),
  }).catch(() => {});
}

export async function sendTestPush(): Promise<{ ok: boolean; reason?: string; error?: string }> {
  const res = await fetch(`${SIM}/push/test`, { method: 'POST' });
  if (!res.ok) throw new Error(`Sim ${res.status}`);
  return res.json();
}
