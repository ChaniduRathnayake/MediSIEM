// Talks to the Wazuh Indexer (OpenSearch) to pull new alerts as they land —
// pointed at the "caap-alerts" index ml-pipeline/flow_consumer.py populates,
// not raw wazuh-alerts-*.

import { Agent, fetch } from 'undici';

const {
  WAZUH_INDEXER_URL = 'https://localhost:9200',
  WAZUH_INDEXER_USER = 'admin',
  WAZUH_INDEXER_PASS = 'changeme',
  WAZUH_INDEXER_INDEX = 'wazuh-alerts-*',
  WAZUH_INDEXER_VERIFY_SSL = 'false',
} = process.env;

// Wazuh ships with a self-signed cert by default — allow bypassing verification
// in dev. Set WAZUH_INDEXER_VERIFY_SSL=true once you install a trusted cert.
//
// IMPORTANT: this imports `fetch` from the `undici` package itself, NOT
// Node's global built-in fetch. Node's global fetch is also undici-based but
// bundles its OWN internal undici version, which is not guaranteed to match
// whatever `undici` you have in package.json (npm's undici@8.x vs. whatever
// Node 24 vendors internally, here). Passing an Agent built from the npm
// package into the global fetch throws `InvalidArgumentError: invalid
// onRequestStart method` — a dispatcher/fetch protocol mismatch, not a
// config problem. Using undici's own fetch keeps Agent and fetch on the same
// version, so this can't happen regardless of what Node version runs this.
const dispatcher = new Agent({
  connect: { rejectUnauthorized: WAZUH_INDEXER_VERIFY_SSL === 'true' },
});

const authHeader =
  'Basic ' + Buffer.from(`${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASS}`).toString('base64');

// Index-not-found is expected/benign until flow_consumer.py writes its first
// document (OpenSearch/Wazuh Indexer auto-creates the index on first write).
// Log it once instead of every poll interval so it doesn't spam the console.
let loggedMissingIndex = false;

/**
 * Fetch alerts newer than `sinceTimestamp` (ISO string), oldest-first.
 * @param {string|null} sinceTimestamp
 * @param {number} size max alerts to pull in one page
 * @returns {Promise<Array<object>>} raw alert documents (_source)
 */
export async function fetchNewAlerts(sinceTimestamp, size = 100) {
  const query = {
    size,
    sort: [{ '@timestamp': 'asc' }],
    query: sinceTimestamp
      ? { range: { '@timestamp': { gt: sinceTimestamp } } }
      : { match_all: {} },
  };

  const res = await fetch(`${WAZUH_INDEXER_URL}/${WAZUH_INDEXER_INDEX}/_search`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: authHeader,
    },
    body: JSON.stringify(query),
    dispatcher,
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    const parsed = (() => { try { return JSON.parse(body); } catch { return null; } })();

    if (res.status === 404 && parsed?.error?.type === 'index_not_found_exception') {
      if (!loggedMissingIndex) {
        console.warn(
          `[wazuhIndexerService] Index "${WAZUH_INDEXER_INDEX}" doesn't exist yet — waiting for ` +
            'ml-pipeline/flow_consumer.py to write its first document (auto-creates the index). ' +
            'Suppressing this message until then.'
        );
        loggedMissingIndex = true;
      }
      return [];
    }

    throw new Error(`Wazuh Indexer query failed: ${res.status} ${res.statusText} — ${body}`);
  }

  loggedMissingIndex = false;
  const data = await res.json();
  return (data.hits?.hits || []).map((hit) => ({ id: hit._id, ...hit._source }));
}

export default { fetchNewAlerts };
