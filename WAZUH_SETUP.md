# Wazuh Docker Integration — Setup & Troubleshooting

## Why it wasn't working

Three issues existed in the repo:

| # | Problem | Fix |
|---|---------|-----|
| 1 | **No Vite proxy** — `vite.config.ts` had no `server.proxy`, so `/api/wazuh/*` calls from the browser hit Vite (port 5173) instead of Express (port 5000) | Added `server.proxy` to `vite.config.ts` |
| 2 | **Wrong default host** — hardcoded to `192.168.52.129` but Docker Desktop on Windows exposes Wazuh at `localhost` | Changed default to `https://localhost` + added Docker hints dropdown |
| 3 | **Vague error messages** — connection errors didn't explain whether the backend or Wazuh was unreachable | Improved error messages with actionable hints |

---

## Files to replace

```
frontend/vite.config.ts                          ← vite.config.ts
frontend/src/pages/dashboard/wazuhApi.ts         ← wazuhApi.ts
frontend/src/pages/dashboard/WazuhDashboard.tsx  ← WazuhDashboard.tsx
```

---

## Docker port mapping check

Make sure your `docker-compose.yml` (or `docker run`) exposes Wazuh's API port:

```yaml
services:
  wazuh.manager:
    image: wazuh/wazuh-manager:4.x.x
    ports:
      - "55000:55000"   # ← This line is required
      - "1514:1514"
      - "1515:1515"
```

Verify it's mapped:
```bash
docker ps
# Should show: 0.0.0.0:55000->55000/tcp
```

---

## Test the connection manually

From your Windows host, open PowerShell or cmd:

```powershell
# Test 1 — is Wazuh reachable?
curl -k -u wazuh-wui:"MyS3cr37P450r.*-" https://localhost:55000/security/user/authenticate?raw=true

# Test 2 — is the MediSIEM backend reachable?
curl http://localhost:5000/api/health
```

If Test 1 fails → port 55000 is not mapped in Docker.
If Test 2 fails → Express backend isn't running (`cd backend && npm run dev`).

---

## Common host values

| Wazuh setup | Host to enter in the config panel |
|-------------|----------------------------------|
| Docker Desktop (Windows/Mac) | `https://localhost` |
| Docker on Linux (same machine) | `https://127.0.0.1` |
| Wazuh on a different machine | `https://192.168.x.x` |
| Docker with custom hostname | `https://hostname` |

Port is always `55000` unless you changed it in docker-compose.

---

## How the proxy chain works

```
Browser (Vite :5173)
  → fetch('/api/wazuh/ping')
    → Vite proxy forwards to Express (:5000)
      → Express backend calls Wazuh API (:55000) with Bearer JWT
        → Returns data back up the chain
```

The backend proxy is necessary because:
- Wazuh uses self-signed TLS certs (browser blocks direct calls)
- CORS headers aren't set on the Wazuh API
- Credentials shouldn't be exposed to the browser network tab
