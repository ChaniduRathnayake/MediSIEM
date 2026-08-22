// Minimal, standalone Wazuh Manager client for the AI chat assistant's
// get_agent_status tool. Deliberately NOT sharing code with routes/wazuh.js's own
// getToken()/wazuhCall() (duplicated, not imported) so this addition can't regress
// the already-working Wazuh dashboard routes — same auth flow, isolated blast radius.
//
// Unlike the assistant's other tools (AlertLog/MedicalDevice, both in Mongo), agent
// status only exists on the live Wazuh Manager, and this backend never stores Wazuh
// credentials — the browser holds them (localStorage 'medisiem_wazuh_cfg', see
// useWazuh.ts) and sends them per-request via x-wazuh-* headers, same as every other
// Wazuh-backed feature. If the browser never connected Wazuh, there's nothing to query.
import https from 'https';
import http from 'http';

// Without this, an unreachable/hung Wazuh Manager hangs the whole chat request (and
// the chatWithTools loop awaiting this tool call) indefinitely — same failure mode
// geminiClient.js's own FETCH_TIMEOUT_MS/AbortController guards against for the
// Gemini call itself.
const REQUEST_TIMEOUT_MS = 8_000;

function httpsGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const opts = { hostname: u.hostname, port: u.port, path: u.pathname + u.search, method: 'GET', rejectUnauthorized: false, headers };
    const proto = u.protocol === 'https:' ? https : http;
    const req = proto.request(opts, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    req.setTimeout(REQUEST_TIMEOUT_MS, () => {
      req.destroy(new Error(`Wazuh Manager did not respond within ${REQUEST_TIMEOUT_MS / 1000}s.`));
    });
    req.end();
  });
}

async function getToken({ host, port, username, password }) {
  const url = `${host}:${port}/security/user/authenticate?raw=true`;
  const basicAuth = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
  const { status, body } = await httpsGet(url, { Authorization: basicAuth });
  if (status >= 400) throw new Error(`Wazuh auth failed (HTTP ${status}): ${body.slice(0, 200)}`);
  const token = body.trim();
  if (!token) throw new Error('Wazuh returned an empty token');
  return token;
}

/** Live active/disconnected/total agent counts — same source /api/wazuh/stats already
 * uses for the dashboard's Agents overview, so the assistant's answer always matches
 * what an analyst sees there. */
export async function getAgentStatusSummary(wazuhConfig) {
  if (!wazuhConfig?.host || !wazuhConfig?.username || !wazuhConfig?.password) {
    return {
      connected: false,
      note: 'Wazuh is not connected in this browser session. Tell the analyst to connect it from the Wazuh Overview tab, then ask again — do not guess a number.',
    };
  }

  const token = await getToken(wazuhConfig);
  const url = `${wazuhConfig.host}:${wazuhConfig.port}/agents/summary/status`;
  const { status, body } = await httpsGet(url, { Authorization: `Bearer ${token}` });

  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error('Non-JSON response from Wazuh Manager.');
  }
  if (status >= 400) throw new Error(parsed?.detail || parsed?.message || `Wazuh API error ${status}`);

  const conn = parsed?.data?.connection ?? {};
  const active = conn.active ?? 0;
  const disconnected = conn.disconnected ?? 0;
  const neverConnected = conn.never_connected ?? 0;
  const pending = conn.pending ?? 0;
  return {
    connected: true,
    activeAgents: active,
    disconnectedAgents: disconnected,
    neverConnectedAgents: neverConnected,
    pendingAgents: pending,
    totalAgents: active + disconnected + neverConnected + pending,
  };
}
