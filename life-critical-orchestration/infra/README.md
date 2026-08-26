# Infrastructure — Local Development Stack

The Wazuh (SIEM) and Shuffle (SOAR) deployments used by this project are
**not committed to this repository**. They are large third-party projects
maintained upstream, and pinning copies here would bloat the repo without
benefit. Instead, you clone them into this directory yourself by following
the steps below.

The `.gitignore` at the repo root excludes `infra/wazuh-docker/` and
`infra/shuffle/`, so anything you put inside those folders will not be
tracked.

---

## Prerequisites

- **Docker Desktop** (Windows / macOS) or Docker Engine + Compose plugin (Linux)
  - Allocate at least **6 GB RAM** to Docker (8 GB recommended)
  - WSL2 backend on Windows
- **Git**
- **Disk space:** ~6 GB for both stacks combined

## Port allocation

| Port | Service | Stack |
|------|---------|-------|
| 443 | Wazuh dashboard (HTTPS) | Wazuh |
| 1514–1515 | Wazuh agent comms | Wazuh |
| 9200 | Wazuh indexer | Wazuh |
| 55000 | Wazuh manager API | Wazuh |
| 3001 | Shuffle frontend (HTTP) | Shuffle |
| 3443 | Shuffle frontend (HTTPS) | Shuffle |
| 5001 | Shuffle backend | Shuffle |
| 9201 | Shuffle OpenSearch (remapped from 9200 to avoid Wazuh clash) | Shuffle |

If any of these ports are already in use on your host, you'll need to remap
the conflicting service in its `docker-compose.yml`.

---

## 1. Wazuh — Single-node deployment

```bash
cd infra
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.5
cd wazuh-docker/single-node

# Generate SSL certificates for inter-component communication
docker compose -f generate-indexer-certs.yml run --rm generator

# Bring up the stack (manager + indexer + dashboard)
docker compose up -d
```

First boot takes 3–5 minutes for cert handshakes and index initialisation.

**Verify:**

```bash
docker compose ps   # all three containers should show "Up"
```

**Access:** `https://localhost` (accept the self-signed certificate warning)

**Default credentials:** `admin` / `SecretPassword` — change these for any
non-development deployment.

---

## 2. Shuffle — SOAR

```bash
cd infra
git clone https://github.com/Shuffle/Shuffle.git shuffle/Shuffle
cd shuffle/Shuffle
```

**Important port remap.** Edit `docker-compose.yml` and change the
OpenSearch port mapping from `9200:9200` to `9201:9200` to avoid clashing
with Wazuh's indexer:

```yaml
opensearch:
  # ...
  ports:
    - "9201:9200"
```

Then bring it up:

```bash
docker compose up -d
```

First boot takes 1–2 minutes.

**Verify:**

```bash
docker compose ps   # four containers: frontend, backend, opensearch, orborus
```

**Access:** `http://localhost:3001`

Shuffle has no default credentials — the first visit will prompt you to
create an admin account.

---

## Daily use

| Task | Command |
|------|---------|
| Start (after first install) | `docker compose start` (in the relevant stack folder) |
| Stop (preserves data) | `docker compose stop` |
| Tear down (preserves data) | `docker compose down` |
| Tear down + wipe data | `docker compose down -v` |
| Watch logs | `docker compose logs -f` |
| Restart one service | `docker compose restart <service-name>` |

---

## Troubleshooting

**Wazuh indexer container keeps restarting**
Most often `vm.max_map_count` too low. On Docker Desktop / WSL2:

```bash
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```

**Shuffle OpenSearch fails to start with port 9200 conflict**
Confirm Wazuh is using 9200 (`docker ps | grep 9200`) and remap Shuffle to
9201 as documented above.

**"Cannot allocate memory"**
Bump Docker Desktop's RAM allocation (Settings → Resources). On WSL2
backend, edit `C:\Users\<you>\.wslconfig`:

```ini
[wsl2]
memory=8GB
processors=4
```

Then fully quit and restart Docker Desktop.

**Wazuh dashboard shows certificate error in browser**
Expected — Wazuh uses self-signed certificates for local development. Accept
the warning and proceed.

---

## Status

- Wazuh single-node ✓ working (verified 2 May 2026)
- Shuffle ✓ working (verified 2 May 2026)
- Wazuh → Shuffle webhook integration: pending (Day 4–5)
- Engine container in this stack: pending (Day 4–5)
