// backend/services/wazuhIndexerService.js
//
// Talks to the Wazuh Indexer (OpenSearch, the storage layer behind Wazuh —
// this is the "Elasticsearch API" referenced in the work plan) to pull new
// alerts as they land from your Wazuh agents.

import { Agent } from 'undici';

const {
  WAZUH_INDEXER_URL = 'https://localhost:9200',
  WAZUH_INDEXER_USER = 'admin',
  WAZUH_INDEXER_PASS = 'changeme',
  WAZUH_INDEXER_INDEX = 'wazuh-alerts-*',
  WAZUH_INDEXER_VERIFY_SSL = 'false',
} = process.env;

// Wazuh ships with a self-signed cert by default — allow bypassing verification
// in dev. Set WAZUH_INDEXER_VERIFY_SSL=true once you install a trusted cert.
// Node's built-in fetch is undici-based and takes a `dispatcher`, not `agent`.
const dispatcher = new Agent({
  connect: { rejectUnauthorized: WAZUH_INDEXER_VERIFY_SSL === 'true' },
});

const authHeader =
  'Basic ' + Buffer.from(`${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASS}`).toString('base64');

/**
 * Fetch alerts newer than `sinceTimestamp` (ISO string), oldest-first.
 * @param {string|null} sinceTimestamp
 * @param {number} size max alerts to pull in one page
 * @returns {Promise<Array<object>>} raw Wazuh alert documents (_source)
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
    throw new Error(`Wazuh Indexer query failed: ${res.status} ${res.statusText} — ${body}`);
  }

  const data = await res.json();
  return (data.hits?.hits || []).map((hit) => ({ id: hit._id, ...hit._source }));
}

export default { fetchNewAlerts };
