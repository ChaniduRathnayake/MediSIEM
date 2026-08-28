/* Service worker for on-call clinician push notifications (Workstream E).
 *
 * Lives at the site root (served from /sw.js) so its scope covers /clinician.
 * It does two things:
 *   1. push        — render the incoming Tier 3 approval as a notification,
 *                    even when no tab is open.
 *   2. notificationclick — focus an existing /clinician tab, or open one,
 *                    deep-linking straight to the pending approval.
 */

self.addEventListener("install", () => {
  // Activate immediately so a freshly-registered worker can receive pushes
  // without waiting for a reload.
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("push", (event) => {
  let data;
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = { title: "Approval needed", body: event.data ? event.data.text() : "" };
  }

  const title = data.title || "Tier 3 approval needed";
  const options = {
    body: data.body || "A device is awaiting your approval.",
    tag: data.tag || "tier3-approval",
    renotify: true,
    requireInteraction: true, // stays until the clinician acts on it
    data: { url: data.url || "/clinician" },
    // icon/badge are optional; the site favicon is used if omitted.
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const targetUrl = (event.notification.data && event.notification.data.url) || "/clinician";

  event.waitUntil(
    self.clients
      .matchAll({ type: "window", includeUncontrolled: true })
      .then((clientList) => {
        for (const client of clientList) {
          if (client.url.includes("/clinician") && "focus" in client) {
            return client.focus();
          }
        }
        if (self.clients.openWindow) {
          return self.clients.openWindow(targetUrl);
        }
        return undefined;
      })
  );
});
