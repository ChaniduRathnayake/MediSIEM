// Proxies queries to the Wazuh Indexer (OpenSearch/Elasticsearch, wazuh-alerts-*
// index — full agent/rule fields, unlike routes/wazuh.js's raw log tail).
// Backs the paginated Alerts browser and the HIPAA/GDPR views (Wazuh's ruleset
// tags each rule with rule.hipaa/rule.gdpr controls). "Compliant" here means
// "no alert fired against a mapped rule in the window" — observed activity,
// not a certified audit; the frontend must label it plainly.

import express from 'express';
import https   from 'https';
import http    from 'http';
import { protect } from '../middleware/auth.js';

const router = express.Router();

// Every route below only ever checked the caller-supplied Indexer
// credentials (x-indexer-*) — a valid MediSIEM session was never required,
// so anyone who had (or guessed) Indexer creds could hit these without ever
// signing into this app. A MediSIEM login is now required in addition,
// same as every other route in this backend.
router.use(protect);

const FRAMEWORKS = ['hipaa', 'gdpr'];

// ── Extract Indexer config from custom request headers (mirrors wazuh.js) ─────
function getConfig(req) {
  const host     = (req.headers['x-indexer-host'] || '').trim();
  const port     = (req.headers['x-indexer-port'] || '9200').trim();
  const username = (req.headers['x-indexer-user'] || '').trim();
  const password = (req.headers['x-indexer-pass'] || '').trim();

  if (!host || !username || !password) return null;
  return { host, port, username, password };
}

// ── Raw HTTPS POST to the Indexer's _search API (self-signed certs, Basic Auth) ─
function indexerSearch(cfg, index, body) {
  return new Promise((resolve, reject) => {
    const bodyStr = JSON.stringify(body);
    const u = new URL(`${cfg.host}:${cfg.port}/${index}/_search`);
    const basicAuth = `Basic ${Buffer.from(`${cfg.username}:${cfg.password}`).toString('base64')}`;

    const opts = {
      hostname:           u.hostname,
      port:               u.port,
      path:               u.pathname + u.search,
      method:             'POST',
      rejectUnauthorized: false, // wazuh-indexer uses self-signed certs
      headers: {
        Authorization:   basicAuth,
        'Content-Type':  'application/json',
        'Content-Length': Buffer.byteLength(bodyStr),
      },
    };

    const proto = u.protocol === 'https:' ? https : http;
    const req = proto.request(opts, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(data); }
        catch { return reject(new Error(`Non-JSON from Indexer: ${data.slice(0, 200)}`)); }
        if (res.statusCode >= 400) {
          return reject(new Error(parsed?.error?.reason || parsed?.error?.type || `Indexer error ${res.statusCode}`));
        }
        resolve(parsed);
      });
    });
    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

const INDEX_PATTERN = 'wazuh-alerts-*';

// Wazuh's index template maps these as `keyword` by default, but some
// deployments' templates differ — if the plain field isn't aggregatable,
// retry once with a `.keyword` suffix before giving up.
async function searchWithKeywordFallback(cfg, body, fieldPaths) {
  try {
    return await indexerSearch(cfg, INDEX_PATTERN, body);
  } catch (err) {
    if (!/fielddata|not.*aggregatable|illegal_argument/i.test(err.message)) throw err;
    // Best-effort fallback: append .keyword to every reference to one of
    // fieldPaths, whether it appears as an agg's "field" value (terms/exists/
    // max) or as a query clause's object key (term/terms filters), then retry.
    const escaped = fieldPaths.map((f) => f.replace(/\./g, '\\.'));
    const bodyStr = JSON.stringify(body)
      .replace(new RegExp(`"field":"(${escaped.join('|')})"`, 'g'), '"field":"$1.keyword"')
      .replace(new RegExp(`"(${escaped.join('|')})":`, 'g'), '"$1.keyword":');
    return indexerSearch(cfg, INDEX_PATTERN, JSON.parse(bodyStr));
  }
}

// GET /api/compliance/:framework/summary?days=30&agentIds=001,002,...
// Per-agent violated-control rollup for the given framework/window.
router.get('/:framework/summary', async (req, res) => {
  const cfg = getConfig(req);
  if (!cfg) return res.status(400).json({ message: 'Missing Indexer credentials' });

  const { framework } = req.params;
  if (!FRAMEWORKS.includes(framework)) return res.status(400).json({ message: `Unknown framework "${framework}".` });

  const days = Math.min(Math.max(parseInt(req.query.days) || 30, 1), 365);
  const ruleField = `rule.${framework}`;
  const agentIds = String(req.query.agentIds || '').split(',').map((s) => s.trim()).filter(Boolean);

  const body = {
    size: 0,
    query: {
      bool: {
        filter: [
          { range: { '@timestamp': { gte: `now-${days}d` } } },
          { exists: { field: ruleField } },
          ...(agentIds.length > 0 ? [{ terms: { 'agent.id': agentIds } }] : []),
        ],
      },
    },
    aggs: {
      by_agent: {
        terms: { field: 'agent.id', size: 1000 },
        aggs: {
          controls:    { terms: { field: ruleField, size: 200 } },
          max_level:   { max: { field: 'rule.level' } },
          alert_count: { value_count: { field: 'rule.level' } },
        },
      },
      all_controls: { terms: { field: ruleField, size: 200 } },
    },
  };

  try {
    const data = await searchWithKeywordFallback(cfg, body, ['agent.id', ruleField]);
    const buckets = data?.aggregations?.by_agent?.buckets ?? [];
    const agents = buckets.map((b) => ({
      agentId:          b.key,
      alertCount:       b.alert_count?.value ?? b.doc_count ?? 0,
      maxLevel:         b.max_level?.value ?? null,
      violatedControls: (b.controls?.buckets ?? []).map((c) => c.key),
    }));
    const observedControls = (data?.aggregations?.all_controls?.buckets ?? []).map((c) => c.key);

    return res.json({ ok: true, days, observedControls, agents });
  } catch (err) {
    console.error(`[compliance/${framework}/summary]`, err.message);
    return res.status(502).json({ message: err.message });
  }
});

// GET /api/compliance/:framework/agent/:agentId?days=30
// Per-control breakdown for one agent — what fired, how often, how severe.
router.get('/:framework/agent/:agentId', async (req, res) => {
  const cfg = getConfig(req);
  if (!cfg) return res.status(400).json({ message: 'Missing Indexer credentials' });

  const { framework, agentId } = req.params;
  if (!FRAMEWORKS.includes(framework)) return res.status(400).json({ message: `Unknown framework "${framework}".` });

  const days = Math.min(Math.max(parseInt(req.query.days) || 30, 1), 365);
  const ruleField = `rule.${framework}`;

  const body = {
    size: 0,
    query: {
      bool: {
        filter: [
          { range: { '@timestamp': { gte: `now-${days}d` } } },
          { term: { 'agent.id': agentId } },
          { exists: { field: ruleField } },
        ],
      },
    },
    aggs: {
      controls: {
        terms: { field: ruleField, size: 200 },
        aggs: {
          alert_count: { value_count: { field: 'rule.level' } },
          max_level:   { max: { field: 'rule.level' } },
          samples: {
            top_hits: {
              size: 3,
              _source: ['rule.description', 'rule.id', '@timestamp'],
              sort: [{ '@timestamp': { order: 'desc' } }],
            },
          },
        },
      },
    },
  };

  try {
    const data = await searchWithKeywordFallback(cfg, body, ['agent.id', ruleField]);
    const buckets = data?.aggregations?.controls?.buckets ?? [];
    const violatedControls = buckets.map((b) => ({
      control:     b.key,
      alertCount:  b.alert_count?.value ?? b.doc_count ?? 0,
      maxLevel:    b.max_level?.value ?? null,
      samples: (b.samples?.hits?.hits ?? []).map((h) => ({
        description: h._source?.rule?.description ?? null,
        ruleId:      h._source?.rule?.id ?? null,
        timestamp:   h._source?.['@timestamp'] ?? null,
      })),
    }));

    return res.json({ ok: true, days, agentId, violatedControls });
  } catch (err) {
    console.error(`[compliance/${framework}/agent]`, err.message);
    return res.status(502).json({ message: err.message });
  }
});

// GET /api/compliance/alerts?page=1&pageSize=50&agentId=&agentIp=&severity=&q=
// Full paginated alert browser — backs the Wazuh SIEM "Alerts" tab. Every
// alert, not just the most recent 50, with the agent it came from and
// filters on agent id / agent ip / minimum severity / free-text rule search.
router.get('/alerts', async (req, res) => {
  const cfg = getConfig(req);
  if (!cfg) return res.status(400).json({ message: 'Missing Indexer credentials' });

  const page     = Math.max(parseInt(req.query.page) || 1, 1);
  const pageSize = Math.min(Math.max(parseInt(req.query.pageSize) || 50, 1), 200);
  const agentId  = String(req.query.agentId || '').trim();
  const agentIp  = String(req.query.agentIp || '').trim();
  const severity = parseInt(req.query.severity);
  const q        = String(req.query.q || '').trim();

  const filter = [];
  if (agentId) filter.push({ term: { 'agent.id': agentId } });
  if (agentIp) {
    // Exact IP → term (works whether agent.ip is mapped `ip` or `keyword`).
    // Partial IP → wildcard (only works if agent.ip is `keyword`-mapped,
    // which is the default in Wazuh's index template).
    const isFullIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(agentIp);
    filter.push(isFullIp ? { term: { 'agent.ip': agentIp } } : { wildcard: { 'agent.ip': `*${agentIp}*` } });
  }
  if (!Number.isNaN(severity)) filter.push({ range: { 'rule.level': { gte: severity } } });
  if (q) filter.push({ match: { 'rule.description': q } });

  const body = {
    from: (page - 1) * pageSize,
    size: pageSize,
    track_total_hits: true,
    sort: [{ '@timestamp': { order: 'desc' } }],
    query: { bool: { filter } },
    _source: ['@timestamp', 'agent', 'rule', 'location', 'full_log', 'data', 'decoder'],
  };

  try {
    const data = await searchWithKeywordFallback(cfg, body, ['agent.id', 'agent.ip']);
    const hits = data?.hits?.hits ?? [];
    const total = data?.hits?.total?.value ?? data?.hits?.total ?? 0;

    const alerts = hits.map((h) => {
      const src = h._source || {};
      return {
        id:              h._id,
        timestamp:       src['@timestamp'] ?? null,
        agentId:         src.agent?.id ?? null,
        agentName:       src.agent?.name ?? null,
        agentIp:         src.agent?.ip ?? null,
        ruleId:          src.rule?.id ?? null,
        ruleLevel:       src.rule?.level ?? null,
        ruleDescription: src.rule?.description ?? null,
        ruleGroups:      src.rule?.groups ?? [],
        ruleFiredTimes:  src.rule?.firedtimes ?? null,
        location:        src.location ?? null,
        fullLog:         src.full_log ?? null,
        data:            src.data ?? null,
        decoder:         src.decoder?.name ?? null,
        compliance: {
          hipaa:       src.rule?.hipaa ?? [],
          pciDss:      src.rule?.pci_dss ?? [],
          gdpr:        src.rule?.gdpr ?? [],
          nist80053:   src.rule?.nist_800_53 ?? [],
          tsc:         src.rule?.tsc ?? [],
          gpg13:       src.rule?.gpg13 ?? [],
        },
      };
    });

    return res.json({ ok: true, total, page, pageSize, alerts });
  } catch (err) {
    console.error('[compliance/alerts]', err.message);
    return res.status(502).json({ message: err.message });
  }
});

// GET /api/compliance/fim/:agentId?page=1&pageSize=50&days=&path=
// Real FIM *change history* for one agent — every detected add/modify/delete
// event with its full before/after diff (size, hash, permissions, owner,
// mtime, and — if the content-diff module is enabled — the actual line
// diff), sourced from the FIM alerts in the Indexer. This is deliberately
// separate from the manager API's /syscheck/{agent_id} (proxied in
// wazuh.js's agent-details route), which only reports each file's CURRENT
// state — it has no before/after values and collapses repeated changes down
// to the latest one, which is why the old FIM tab couldn't show what
// actually changed.
router.get('/fim/:agentId', async (req, res) => {
  const cfg = getConfig(req);
  if (!cfg) return res.status(400).json({ message: 'Missing Indexer credentials' });

  const { agentId } = req.params;
  const page     = Math.max(parseInt(req.query.page) || 1, 1);
  const pageSize = Math.min(Math.max(parseInt(req.query.pageSize) || 50, 1), 200);
  const days     = req.query.days ? Math.min(Math.max(parseInt(req.query.days) || 0, 1), 365) : null;
  const path     = String(req.query.path || '').trim();

  const filter = [
    { term: { 'agent.id': agentId } },
    { exists: { field: 'syscheck.path' } },
  ];
  if (days) filter.push({ range: { '@timestamp': { gte: `now-${days}d` } } });
  if (path) filter.push({ wildcard: { 'syscheck.path': `*${path}*` } });

  const body = {
    from: (page - 1) * pageSize,
    size: pageSize,
    track_total_hits: true,
    sort: [{ '@timestamp': { order: 'desc' } }],
    query: { bool: { filter } },
    _source: ['@timestamp', 'syscheck', 'rule'],
  };

  try {
    const data = await searchWithKeywordFallback(cfg, body, ['agent.id', 'syscheck.path']);
    const hits = data?.hits?.hits ?? [];
    const total = data?.hits?.total?.value ?? data?.hits?.total ?? 0;

    const events = hits.map((h) => {
      const src = h._source || {};
      const sc  = src.syscheck || {};
      return {
        id:                h._id,
        timestamp:         src['@timestamp'] ?? null,
        path:              sc.path ?? null,
        event:             sc.event ?? null,
        changedAttributes: sc.changed_attributes ?? [],
        ruleDescription:   src.rule?.description ?? null,
        ruleLevel:         src.rule?.level ?? null,
        syscheck:          sc, // raw before/after fields — frontend pairs up any *_before/*_after keys generically
      };
    });

    return res.json({ ok: true, total, page, pageSize, events });
  } catch (err) {
    console.error('[compliance/fim]', err.message);
    return res.status(502).json({ message: err.message });
  }
});

// GET /api/compliance/ping  — connectivity check for the Settings panel
router.get('/ping', async (req, res) => {
  const cfg = getConfig(req);
  if (!cfg) return res.status(400).json({ message: 'Missing Indexer credentials' });

  try {
    const u = new URL(`${cfg.host}:${cfg.port}/`);
    const basicAuth = `Basic ${Buffer.from(`${cfg.username}:${cfg.password}`).toString('base64')}`;
    const proto = u.protocol === 'https:' ? https : http;

    const info = await new Promise((resolve, reject) => {
      const request = proto.request({
        hostname: u.hostname, port: u.port, path: '/', method: 'GET',
        rejectUnauthorized: false, headers: { Authorization: basicAuth },
      }, (r) => {
        let data = '';
        r.on('data', (c) => { data += c; });
        r.on('end', () => {
          if (r.statusCode >= 400) return reject(new Error(`Indexer ping failed (HTTP ${r.statusCode})`));
          try { resolve(JSON.parse(data)); } catch { resolve({}); }
        });
      });
      request.on('error', reject);
      request.end();
    });

    return res.json({ ok: true, version: info?.version?.number ?? null });
  } catch (err) {
    console.error('[compliance/ping]', err.message);
    return res.status(502).json({ message: err.message });
  }
});

export default router;
