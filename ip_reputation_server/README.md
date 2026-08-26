# ip_reputation_server

MedShield IP Reputation Intelligence — a FastAPI microservice providing the
backend for MediSIEM's **IP Reputation** tab. Sits alongside `ai_server/`
(the CAAP Flask ML service) as a sibling Python service; the Node backend
(`backend/routes/ipReputation.js`) proxies authenticated requests to it, the
same way it already proxies to Wazuh.

## What it does
- Classifies an IP (public/private/reserved, IPv4/IPv6).
- Enriches public IPs via AbuseIPDB + VirusTotal, and computes a MedShield
  reputation score/risk level/confidence from that evidence.
- Correlates the IP against locally observed flow events (RF/Isolation
  Forest/context-risk scores written by the flow collector) to produce a
  MIRS (MedShield Integrated Risk Score).
- Pulls matching Wazuh alerts for the IP.
- Persists an internal allow/watch/block list, analyst verdicts/notes,
  investigation cases, log-source health, and a full audit trail — all in
  their own MongoDB database (`medshield_ip_reputation`), separate from
  MediSIEM's main `medisiem` database.

## Run it
```
cd ip_reputation_server
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8088
```
Config lives in `.env` (Mongo URI, `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`,
Wazuh indexer creds) — not committed to git. `MEDSHIELD_PORT` defaults to
8088; the Node backend's `IP_REPUTATION_SERVICE_URL` must match.

## Relationship to ip-reputation-Componets/
The RF/Isolation Forest scores this service correlates against are produced
by a separate flow-scoring collector (see `ip-reputation-Componets/`, nested
in this folder) — that pipeline is not imported by this FastAPI app directly
(no Python import, no shared process); in the original lab deployment it
runs as its own service on a separate flow-collector host and writes into
the shared `events` collection this service reads from over MongoDB.
