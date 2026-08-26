# SOC Console (Frontend)

React + Vite + Tailwind dashboard for the Life-Critical-Aware Decision Engine.
Visualises classified alerts, surfaces tiered decisions with rationale, and
displays the hash-chained audit log.

## Prerequisites

- Node.js 18+ (Vite 8 requirement)
- The decision engine running locally on `http://localhost:8000`
  (see `engine/README.md`)

## Running in development

From this directory:

```bash
npm install
npm run dev
```

Vite will start on `http://localhost:5173`.

The engine must be running separately. From the `engine/` directory:

```bash
source .venv/Scripts/activate    # Git Bash on Windows
                                 # or .venv/bin/activate on Linux/macOS
uvicorn src.main:app --reload --port 8000
```

The header bar shows `engine: ONLINE` (green) when the link is alive.

## Building for production

```bash
npm run build
```

Output goes to `dist/`. Serve with any static host. The engine URL is
hard-coded to `http://localhost:8000` in `src/api/engine.js`; change it
there before deploying.

## Layout

- **Header** — title, project ID, live engine status indicator
- **Pending Approval Tray** — visible only when there are open Tier 3
  decisions; PP1 placeholder for the PP2 clinician approval workflow
- **Alert Feed (left)** — all 12 bundled stub alerts, colour-coded by
  expected tier; clicking one calls `POST /decide`
- **Decision Detail (centre)** — tier badge, action, full rationale,
  Tier 3 two-phase flow (when applicable), engine internals (effective
  score / band / extreme-threat / matched rule), asset and threat
  context, and display-only clinical metadata
- **Audit Timeline (lower)** — the engine's hash-chained audit log,
  newest first, with a "Verify chain" button that calls
  `GET /audit/verify`

## Project structure
src/
api/
engine.js          — fetch wrappers for /health, /decide, /audit, /audit/verify
components/
AlertFeed.jsx
DecisionDetail.jsx
AuditTimeline.jsx
PendingApprovalTray.jsx
data/
sampleAlerts.js    — bundles the 12 stub alerts
tier{1,2,3}-cases.json
App.jsx              — layout shell + state orchestration
main.jsx
index.css            — Tailwind directives + base body styles

## Notes

- All UI state is in-memory; reloading the page clears the selected alert
  but the audit log is server-side and persists.
- The "PP2: clinician UI here" caption inside the Pending Approval Tray
  is intentional — it marks where the future approval interaction will
  live.
- The audit log file lives at `engine/data/audit_log.jsonl` (or wherever
  `AUDIT_LOG_PATH` points). Delete it to reset the timeline.