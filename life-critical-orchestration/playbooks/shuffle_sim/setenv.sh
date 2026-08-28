#!/usr/bin/env bash
# Local dev convenience for the Shuffle sim (Workstream E).
# GITIGNORED — do not commit (holds the VAPID private key).
#
# Usage, from playbooks/shuffle_sim:
#     source setenv.sh
#     uvicorn server:app --reload --port 8002

# Resolve this script's own dir so the venv path works regardless of cwd.
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Activate the shared engine venv (Windows / Git Bash path).
source "$_here/../../engine/.venv/Scripts/activate"

# VAPID keys for Web Push. Regenerate anytime with:  python generate_vapid.py
export VAPID_PUBLIC_KEY=BDAW-YleJnmK7-xOO1-z0fVsaceD54XhOR4XAw547Thy0jDvOx4EUqrT44QuVmQ6z_a-jbREk4CoY-syfZRK07Y
export VAPID_PRIVATE_KEY=sHVkvJ-sugKmJjEdQfYXVLeK0reDRdRmx5IXZbNz7Og
export VAPID_SUBJECT=mailto:oncall@hospital.local

# F-3 micro-segmentation (quarantine). Off by default in server.py/
# tier3_dispatch.py until a real per-asset clinical-peers definition existed
# (see enforcement.py's _DEFAULT_CLINICAL_PEERS / SHUFFLE_CLINICAL_PEERS_MAP)
# — that's now built, so this is safe to turn on. Effect: every Tier 3 alert
# also quarantines the asset in parallel with Monitored Mode, and a denied
# Tier 3 escalation stays quarantined (not just Monitored Mode). Real for
# ICU-VENT-003 (docker network move), simulated for every other asset_id.
export ENABLE_QUARANTINE=true

echo "✓ venv active + VAPID set — start the sim with:  uvicorn server:app --reload --port 8002"
