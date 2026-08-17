// Proxies calls to the Wazuh REST API. Auth uses ?raw=true on
// /security/user/authenticate, which returns a plain JWT string, not JSON.

import express from 'express';
import https   from 'https';
import http    from 'http';
import { protect } from '../middleware/auth.js';

const router = express.Router();

// Every route below only ever checked the caller-supplied Wazuh credentials
// (x-wazuh-*) — a valid MediSIEM session was never required, so anyone who
// had (or guessed) Wazuh creds could hit these without ever signing into
// this app. A MediSIEM login is now required in addition, same as every
// other route in this backend.
router.use(protect);

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

// ── Fetch one Wazuh list endpoint, normalized to { ok, items, total } — a
// module of a module (SCA, syscollector, ...) that isn't enabled or has no
// data yet fails independently rather than taking down the whole request.
async function fetchWazuhList(cfg, path) {
  try {
    const data = await wazuhCall(cfg, path);
    return {
      ok: true,
      items: data?.data?.affected_items ?? [],
      total: data?.data?.total_affected_items ?? 0,
    };
  } catch (err) {
    return { ok: false, error: err.message, items: [], total: 0 };
  }
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
    // NOTE: Wazuh's `select` param rejects the bare `os` field — it only accepts
    // explicit sub-paths (os.platform, os.name, ...). Selecting the parent field
    // fails the whole request (this previously 500'd /agents while the Overview
    // tab kept working, since it reads a different endpoint).
    const limit = parseInt(req.query.limit) || 500;
    const data  = await wazuhCall(
      cfg,
      `/agents?limit=${limit}&sort=-lastKeepAlive&select=id,name,ip,status,os.platform,os.name,os.version,os.arch,os.codename,version,lastKeepAlive,group,dateAdd,manager,node_name,group_config_status`
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

// GET /api/wazuh/agent-details/:agentId  — everything the API exposes about one agent
// Fetches syscollector (hardware/os/network/software/processes/ports), security
// (vulnerabilities/SCA/FIM) and cluster placement in parallel. Any section whose
// module isn't enabled on the manager (or has no data yet) fails independently and
// is reported as `ok: false` rather than failing the whole request.
router.get('/agent-details/:agentId', async (req, res) => {
  const cfg = getConfig(req);
  if (!cfg) return res.status(400).json({ message: 'Missing Wazuh credentials' });

  const { agentId } = req.params;

  const fetchList = (path) => fetchWazuhList(cfg, path);

  const fetchSingle = async (path) => {
    const r = await fetchList(path);
    return { ok: r.ok, error: r.error, item: r.items[0] ?? null };
  };

  try {
    // Initial load fetches up to 500 of each — Wazuh's practical per-request max
    // and enough to cover the vast majority of agents in one shot. Anything
    // beyond that is fetched on demand via the paginated section endpoint below
    // (see the "Load more" button in AgentDetailsModal).
    const [
      hardware, os, netiface, netaddr, netproto,
      packages, processes, ports,
      vulnerabilities, sca, fim,
    ] = await Promise.all([
      fetchSingle(`/syscollector/${agentId}/hardware`),
      fetchSingle(`/syscollector/${agentId}/os`),
      fetchList(`/syscollector/${agentId}/netiface?limit=500`),
      fetchList(`/syscollector/${agentId}/netaddr?limit=500`),
      fetchList(`/syscollector/${agentId}/netproto?limit=500`),
      fetchList(`/syscollector/${agentId}/packages?limit=500&sort=name`),
      fetchList(`/syscollector/${agentId}/processes?limit=500&sort=-vm_size`),
      fetchList(`/syscollector/${agentId}/ports?limit=500`),
      fetchList(`/vulnerability/${agentId}?limit=500&sort=-severity`),
      fetchList(`/sca/${agentId}?limit=500`),
      fetchList(`/syscheck/${agentId}?limit=500&sort=-mtime`),
    ]);

    return res.json({ hardware, os, netiface, netaddr, netproto, packages, processes, ports, vulnerabilities, sca, fim });
  } catch (err) {
    console.error('[wazuh/agent-details]', err.message);
    return res.status(502).json({ message: err.message });
  }
});

// ── Paths + default sort for the paginated single-section endpoint below ──────
const SECTION_PATH = {
  netiface:        (id) => `/syscollector/${id}/netiface`,
  netaddr:         (id) => `/syscollector/${id}/netaddr`,
  netproto:        (id) => `/syscollector/${id}/netproto`,
  packages:        (id) => `/syscollector/${id}/packages`,
  processes:       (id) => `/syscollector/${id}/processes`,
  ports:           (id) => `/syscollector/${id}/ports`,
  vulnerabilities: (id) => `/vulnerability/${id}`,
  sca:             (id) => `/sca/${id}`,
  fim:             (id) => `/syscheck/${id}`,
};
const SECTION_SORT = {
  packages:        'name',
  processes:       '-vm_size',
  vulnerabilities: '-severity',
  fim:             '-mtime',
};

// GET /api/wazuh/agent-details/:agentId/section/:section  — one section, paginated.
// Backs the "Load more" button for any list that's longer than the initial
// agent-details fetch above (fetched item count < the section's real total).
router.get('/agent-details/:agentId/section/:section', async (req, res) => {
  const cfg = getConfig(req);
  if (!cfg) return res.status(400).json({ message: 'Missing Wazuh credentials' });

  const { agentId, section } = req.params;
  const pathFn = SECTION_PATH[section];
  if (!pathFn) return res.status(400).json({ message: `Unknown section "${section}".` });

  const limit  = Math.min(parseInt(req.query.limit) || 300, 500);
  const offset = Math.max(parseInt(req.query.offset) || 0, 0);
  const sort   = SECTION_SORT[section];

  try {
    const qs = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (sort) qs.set('sort', sort);
    const data = await wazuhCall(cfg, `${pathFn(agentId)}?${qs.toString()}`);
    return res.json({
      ok:    true,
      items: data?.data?.affected_items ?? [],
      total: data?.data?.total_affected_items ?? 0,
    });
  } catch (err) {
    console.error(`[wazuh/agent-details/section/${section}]`, err.message);
    return res.status(502).json({ message: err.message });
  }
});

// GET /api/wazuh/sca-summary?agentIds=001,002,...  — CIS-benchmark rollup per agent.
// Fans out one /sca/{agent_id} call per requested agent, keeps only policies
// whose name/policy_id look like a CIS benchmark, and aggregates pass/fail/
// invalid across them. Backs the CIS sub-tab's per-device summary table.
router.get('/sca-summary', async (req, res) => {
  const cfg = getConfig(req);
  if (!cfg) return res.status(400).json({ message: 'Missing Wazuh credentials' });

  const agentIds = String(req.query.agentIds || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (agentIds.length === 0) return res.json({ agents: [] });

  try {
    const results = await Promise.all(agentIds.map(async (agentId) => {
      const r = await fetchWazuhList(cfg, `/sca/${agentId}?limit=500`);
      if (!r.ok) return { agentId, ok: false, error: r.error };

      const cisPolicies = r.items.filter((p) =>
        /cis/i.test(p.name || '') || /cis/i.test(p.policy_id || '')
      );

      const totals = cisPolicies.reduce((acc, p) => ({
        pass:    acc.pass    + (p.pass    ?? 0),
        fail:    acc.fail    + (p.fail    ?? 0),
        invalid: acc.invalid + (p.invalid ?? 0),
      }), { pass: 0, fail: 0, invalid: 0 });

      const total = totals.pass + totals.fail + totals.invalid;
      return {
        agentId,
        ok: true,
        policies: cisPolicies.map((p) => ({ policyId: p.policy_id, name: p.name, pass: p.pass, fail: p.fail, invalid: p.invalid, score: p.score })),
        ...totals,
        total,
        score: total > 0 ? Math.round((totals.pass / total) * 100) : null,
      };
    }));

    return res.json({ agents: results });
  } catch (err) {
    console.error('[wazuh/sca-summary]', err.message);
    return res.status(502).json({ message: err.message });
  }
});

// GET /api/wazuh/sca/:agentId/checks/:policyId  — per-check detail for one CIS policy.
router.get('/sca/:agentId/checks/:policyId', async (req, res) => {
  const cfg = getConfig(req);
  if (!cfg) return res.status(400).json({ message: 'Missing Wazuh credentials' });

  const { agentId, policyId } = req.params;
  const r = await fetchWazuhList(cfg, `/sca/${agentId}/checks/${policyId}?limit=500`);
  if (!r.ok) return res.status(502).json({ message: r.error });
  return res.json({ ok: true, items: r.items, total: r.total });
});

export default router;
