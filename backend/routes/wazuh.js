// backend/routes/wazuh.js
// Proxies calls to Wazuh REST API using the raw JWT auth pattern:
//   curl -k -u wazuh-wui:'MyS3cr37P450r.*-' \
//     https://192.168.52.129:55000/security/user/authenticate?raw=true
// The ?raw=true flag returns a plain JWT string (not JSON).

import express from 'express';
import https   from 'https';
import http    from 'http';

const router = express.Router();

// ── Extract Wazuh config from custom request headers ─────────────────────────
function getConfig(req) {
  const host     = (req.headers['x-wazuh-host'] || '').trim();  // e.g. https://192.168.52.129
  const port     = (req.headers['x-wazuh-port'] || '55000').trim();
  const username = (req.headers['x-wazuh-user'] || '').trim();  // e.g. wazuh-wui
  const password = (req.headers['x-wazuh-pass'] || '').trim();  // e.g. MyS3cr37P450r.*-

  if (!host || !username || !password) return null;
  return { host, port, username, password };
}

// ── Low-level HTTPS request (bypasses self-signed cert check) ─────────────────
function httpsGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const opts = {
      hostname:           u.hostname,
      port:               u.port,
      path:               u.pathname + u.search,
      method:             'GET',
      rejectUnauthorized: false,     // Wazuh uses self-signed certs
      headers,
    };
    const proto = u.protocol === 'https:' ? https : http;
    const req = proto.request(opts, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    req.end();
  });
}

function httpsRequest(url, method, headers = {}, bodyStr = null) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const opts = {
      hostname:           u.hostname,
      port:               u.port,
      path:               u.pathname + u.search,
      method,
      rejectUnauthorized: false,
      headers: {
        ...headers,
        ...(bodyStr ? { 'Content-Length': Buffer.byteLength(bodyStr) } : {}),
      },
    };
    const proto = u.protocol === 'https:' ? https : http;
    const req = proto.request(opts, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

// ── Step 1: Authenticate → get raw JWT (mirrors the curl command exactly) ─────
async function getToken({ host, port, username, password }) {
  const url       = `${host}:${port}/security/user/authenticate?raw=true`;
  const basicAuth = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;

  const { status, body } = await httpsGet(url, { Authorization: basicAuth });

  if (status >= 400) {
    throw new Error(`Wazuh auth failed (HTTP ${status}): ${body.slice(0, 200)}`);
  }

  const token = body.trim();
  if (!token) throw new Error('Wazuh returned an empty token');
  return token;
}

// ── Step 2: Call any Wazuh API endpoint with Bearer token ─────────────────────
async function wazuhCall(config, path, method = 'GET', bodyData = null) {
  const { host, port } = config;
  const token          = await getToken(config);
  const url            = `${host}:${port}${path}`;
  const bodyStr        = bodyData ? JSON.stringify(bodyData) : null;

  const { status, body } = await httpsRequest(url, method, {
    Authorization:  `Bearer ${token}`,
    'Content-Type': 'application/json',
  }, bodyStr);

  let parsed;
  try { parsed = JSON.parse(body); }
  catch { throw new Error(`Non-JSON from Wazuh: ${body.slice(0, 200)}`); }

  if (status >= 400) {
    throw new Error(parsed?.detail || parsed?.message || `Wazuh API error ${status}`);
  }

  return parsed;
}

// ─────────────────────────────────────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/wazuh/ping  — connectivity check + API version
router.get('/ping', async (req, res) => {
  const cfg = getConfig(req);
  if (!cfg) return res.status(400).json({ message: 'Missing x-wazuh-host / x-wazuh-user / x-wazuh-pass headers' });

  try {
    const data = await wazuhCall(cfg, '/');
    return res.json(data);
  } catch (err) {
    console.error('[wazuh/ping]', err.message);
    return res.status(502).json({ message: err.message });
  }
});

// GET /api/wazuh/stats  — aggregated dashboard summary
router.get('/stats', async (req, res) => {
  const cfg = getConfig(req);
  if (!cfg) return res.status(400).json({ message: 'Missing Wazuh credentials' });

  try {
    // Agent connection summary
    const agentSummary = await wazuhCall(cfg, '/agents/summary/status').catch(() => ({
      data: { connection: {} },
    }));
    const conn = agentSummary?.data?.connection ?? {};

    // Vulnerability totals (vulnerability module must be enabled)
    let vulns = { critical: 0, high: 0, medium: 0, low: 0 };
    try {
      const allAgents = await wazuhCall(cfg, '/agents?status=active&limit=1&select=id');
      const total = allAgents?.data?.total_affected_items ?? 0;

      // Use the global vulnerability stats endpoint (Wazuh 4.4+)
      const vs = await wazuhCall(cfg, `/vulnerability/000?limit=1&pretty=true`).catch(() => null);
      if (vs?.data?.total_affected_items !== undefined) {
        // Fetch severity breakdown
        const [crit, high, med, low] = await Promise.all([
          wazuhCall(cfg, `/vulnerability/000?limit=1&filters=severity%3DCritical`).catch(() => ({ data: { total_affected_items: 0 } })),
          wazuhCall(cfg, `/vulnerability/000?limit=1&filters=severity%3DHigh`).catch(()    => ({ data: { total_affected_items: 0 } })),
          wazuhCall(cfg, `/vulnerability/000?limit=1&filters=severity%3DMedium`).catch(()  => ({ data: { total_affected_items: 0 } })),
          wazuhCall(cfg, `/vulnerability/000?limit=1&filters=severity%3DLow`).catch(()     => ({ data: { total_affected_items: 0 } })),
        ]);
        vulns = {
          critical: crit.data?.total_affected_items ?? 0,
          high:     high.data?.total_affected_items ?? 0,
          medium:   med.data?.total_affected_items  ?? 0,
          low:      low.data?.total_affected_items  ?? 0,
        };
      }
    } catch { /* vulnerability module may not be enabled */ }

    const totalAgents =
      (conn.active ?? 0) + (conn.disconnected ?? 0) +
      (conn.never_connected ?? 0) + (conn.pending ?? 0);

    return res.json({
      data: {
        totalAlerts:        0,
        alertsLast24h:      0,
        criticalAlerts:     0,
        activeAgents:       conn.active        ?? 0,
        disconnectedAgents: conn.disconnected  ?? 0,
        totalAgents,
        vulnerabilities:    vulns,
      },
    });
  } catch (err) {
    console.error('[wazuh/stats]', err.message);
    return res.status(502).json({ message: err.message });
  }
});

// GET /api/wazuh/agents  — list all agents
router.get('/agents', async (req, res) => {
  const cfg = getConfig(req);
  if (!cfg) return res.status(400).json({ message: 'Missing Wazuh credentials' });

  try {
    const limit = parseInt(req.query.limit) || 500;
    const data  = await wazuhCall(
      cfg,
      `/agents?limit=${limit}&sort=-lastKeepAlive&select=id,name,ip,status,os,version,lastKeepAlive,group`
    );
    return res.json(data);
  } catch (err) {
    console.error('[wazuh/agents]', err.message);
    return res.status(502).json({ message: err.message });
  }
});

// GET /api/wazuh/alerts  — recent manager logs
router.get('/alerts', async (req, res) => {
  const cfg = getConfig(req);
  if (!cfg) return res.status(400).json({ message: 'Missing Wazuh credentials' });

  try {
    const limit = parseInt(req.query.limit) || 50;
    const data  = await wazuhCall(cfg, `/manager/logs?limit=${limit}&sort=-timestamp`).catch(() => ({
      data: { affected_items: [], total_affected_items: 0 },
    }));
    return res.json(data);
  } catch (err) {
    console.error('[wazuh/alerts]', err.message);
    return res.status(502).json({ message: err.message });
  }
});

// GET /api/wazuh/vulnerability/:agentId  — CVEs for a specific agent
router.get('/vulnerability/:agentId', async (req, res) => {
  const cfg = getConfig(req);
  if (!cfg) return res.status(400).json({ message: 'Missing Wazuh credentials' });

  try {
    const { agentId } = req.params;
    const limit       = parseInt(req.query.limit) || 100;
    const data        = await wazuhCall(cfg, `/vulnerability/${agentId}?limit=${limit}&sort=-severity`);
    return res.json(data);
  } catch (err) {
    console.error('[wazuh/vulnerability]', err.message);
    return res.status(502).json({ message: err.message });
  }
});

export default router;
