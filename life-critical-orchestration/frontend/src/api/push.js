// Web Push client (Workstream E) — subscribe the on-call clinician's device.
//
// Talks to the Shuffle sim through the Vite dev-server proxy (/api/sim) so it
// works identically on localhost and on a phone over LAN HTTPS — no
// mixed-content or CORS issues, because every call is same-origin and Vite
// forwards it to the sim server-side. See vite.config.js.

const SIM = "/api/sim";

// A stable per-device id so the sim can tell devices apart and know which one
// is on-call. Generated once and kept in localStorage.
export function getSubscriberId() {
  let id = localStorage.getItem("oncall_subscriber_id");
  if (!id) {
    id =
      "sub-" +
      (crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2));
    localStorage.setItem("oncall_subscriber_id", id);
  }
  return id;
}

export function getDeviceLabel() {
  return localStorage.getItem("oncall_device_label") || "";
}

export function setDeviceLabel(label) {
  localStorage.setItem("oncall_device_label", label || "");
}

function urlBase64ToUint8Array(base64String) {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  return out;
}

export function pushSupported() {
  return "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
}

export async function getPushConfig() {
  const res = await fetch(`${SIM}/push/config`);
  if (!res.ok) throw new Error(`Sim ${res.status}`);
  return res.json();
}

export async function getOnCall() {
  try {
    const res = await fetch(`${SIM}/push/on-call`);
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export async function setOnCall(subscriberId) {
  const res = await fetch(`${SIM}/push/on-call`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ subscriber_id: subscriberId ?? null }),
  });
  if (!res.ok) throw new Error(`Sim ${res.status}: ${await res.text()}`);
  return res.json();
}

// Full subscribe flow: register the SW, ask permission, subscribe via the
// PushManager using the sim's VAPID key, and register the subscription with
// the sim. Returns { subscriberId, config } or throws with a friendly reason.
export async function enablePush({ label = "" } = {}) {
  if (!pushSupported()) {
    throw new Error("This browser doesn't support notifications.");
  }

  const config = await getPushConfig();
  if (!config.configured || !config.vapid_public_key) {
    throw new Error(
      config.reason || "Push isn't configured on the server yet (VAPID keys missing)."
    );
  }

  const permission = await Notification.requestPermission();
  if (permission !== "granted") {
    throw new Error("Notification permission was not granted.");
  }

  const registration = await navigator.serviceWorker.register("/sw.js");
  await navigator.serviceWorker.ready;

  let subscription = await registration.pushManager.getSubscription();
  if (!subscription) {
    subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(config.vapid_public_key),
    });
  }

  const subscriberId = getSubscriberId();
  if (label) setDeviceLabel(label);

  const res = await fetch(`${SIM}/push/subscribe`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      subscriber_id: subscriberId,
      subscription: subscription.toJSON(),
      label: label || getDeviceLabel(),
    }),
  });
  if (!res.ok) throw new Error(`Sim ${res.status}: ${await res.text()}`);

  return { subscriberId, config: await res.json() };
}

export async function disablePush() {
  const subscriberId = getSubscriberId();
  try {
    const reg = await navigator.serviceWorker.getRegistration();
    const sub = reg && (await reg.pushManager.getSubscription());
    if (sub) await sub.unsubscribe();
  } catch {
    // best-effort local cleanup
  }
  await fetch(`${SIM}/push/unsubscribe`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ subscriber_id: subscriberId }),
  }).catch(() => {});
}

export async function sendTestPush() {
  const res = await fetch(`${SIM}/push/test`, { method: "POST" });
  if (!res.ok) throw new Error(`Sim ${res.status}`);
  return res.json();
}
