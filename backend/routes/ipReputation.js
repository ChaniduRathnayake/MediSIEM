// Authenticated proxy to the ip_reputation_server FastAPI microservice
// (MedShield IP Reputation Intelligence — AbuseIPDB/VirusTotal enrichment,
// internal allow/watch/block lists, analyst verdicts, MIRS correlation,
// cases, log sources, audit trail). Same shape as wazuh.js: the frontend
// never talks to the Python service directly, so a MediSIEM login is
// required for every request, and the service's own base URL/credentials
// never reach the browser bundle.
import express from 'express';
import { protect, allowRoles } from '../middleware/auth.js';

const router = express.Router();

router.use(protect);

const SERVICE_URL = (process.env.IP_REPUTATION_SERVICE_URL || 'http://localhost:8088').replace(/\/+$/, '');

// ip_reputation_server has no role model of its own — every route (allow/
// block lists, analyst verdicts, cases) is equally reachable to anyone who
// clears this proxy's `protect` check. Restrict writes here to the same
// admin/user pairing the rest of the app uses for security-relevant
// mutations (e.g. alerts.js's assign/close) — read access (investigation,
// case/list lookups) stays open to every authenticated role.
const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
router.all(/.*/, (req, res, next) => (WRITE_METHODS.has(req.method) ? allowRoles('admin', 'user')(req, res, next) : next()));

router.all(/.*/, async (req, res) => {
  const target = `${SERVICE_URL}/api/v1${req.url}`;

  const init = {
    method: req.method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (!['GET', 'HEAD'].includes(req.method) && req.body && Object.keys(req.body).length > 0) {
    init.body = JSON.stringify(req.body);
  }

  let upstream;
  try {
    upstream = await fetch(target, init);
  } catch (err) {
    return res.status(502).json({
      error: `Cannot reach the IP Reputation service at ${SERVICE_URL}. Make sure ip_reputation_server is running (uvicorn app:app --port 8088). (${err.message})`,
    });
  }

  const contentType = upstream.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    const data = await upstream.json().catch(() => null);
    return res.status(upstream.status).json(data);
  }
  const text = await upstream.text();
  return res.status(upstream.status).send(text);
});

export default router;
