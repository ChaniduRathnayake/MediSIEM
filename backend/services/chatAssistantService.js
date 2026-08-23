// Data-aware AI chat assistant — same Gemini backend as aiAssistantService.js's
// one-shot features, but with function-calling access to bounded, read-only queries
// over real alert/device data (see TOOLS below), so an analyst can ask "how many
// Immediate alerts in ICU today" and get a real answer instead of a guess. Every tool
// is read-only and capped — the model can query, never mutate, and never pull more
// than a bounded page of results.
import { chatWithTools } from './geminiClient.js';
import AlertLog from '../models/AlertLog.js';
import MedicalDevice from '../models/MedicalDevice.js';
import { getAgentStatusSummary } from './wazuhAgentStatus.js';

const SYSTEM_INSTRUCTION = [
  'You are the MediSIEM AI assistant, embedded in a hospital SIEM/IDS dashboard used by security analysts.',
  'You can call get_alert_summary, search_alerts, list_devices, and get_agent_status to answer with real data — always call one of them rather than guessing when a question is about counts, specific alerts, devices, or Wazuh agents.',
  'get_agent_status may report connected: false if Wazuh is not connected in this browser session — if so, tell the analyst to connect it from the Wazuh Overview tab rather than inventing a number.',
  'Keep answers short and factual — a sentence or two, or a compact list. No preamble like "Based on the data provided". If a tool returns zero results, say so plainly rather than inventing an answer.',
  'You are not a replacement for analyst judgement — for anything actionable (closing a case, escalating, changing a device), remind the analyst to do it from the dashboard rather than treating your answer as the action itself.',
].join(' ');

const MAX_LOOKBACK_HOURS = 24 * 30; // 30 days — bounds how far back any query can reach
const MAX_RESULTS = 20;

function clampHours(hours) {
  const n = Number(hours);
  if (!Number.isFinite(n) || n <= 0) return 24;
  return Math.min(n, MAX_LOOKBACK_HOURS);
}

// Every tool arg gets coerced to a plain string before use — Gemini's declared
// `type: STRING` schema is guidance to the model, not a runtime-enforced contract,
// and AlertLog.department/.action have no enum to catch a malformed value at the
// query layer. Also fixes a real bug: the model saying action: "immediate" (or any
// casing other than AlertLog's exact 'Immediate'/'Investigate'/'Monitor') used to
// silently match zero rows instead of the intended alerts.
const VALID_ACTIONS = ['Immediate', 'Investigate', 'Monitor'];
function asPlainString(value) {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}
function normalizeAction(value) {
  const s = asPlainString(value);
  if (!s) return undefined;
  return VALID_ACTIONS.find((a) => a.toLowerCase() === s.toLowerCase());
}

const TOOLS = [
  {
    functionDeclarations: [
      {
        name: 'get_alert_summary',
        description:
          'Counts of alerts by severity and action over a recent time window, optionally filtered by department. Use for "how many" / "how busy" questions.',
        parameters: {
          type: 'OBJECT',
          properties: {
            hours: { type: 'NUMBER', description: 'Look-back window in hours (default 24, max 720).' },
            department: { type: 'STRING', description: 'Filter to one hospital department, e.g. "ICU". Omit for all departments.' },
          },
        },
      },
      {
        name: 'search_alerts',
        description: 'Finds specific recent alerts matching filters, most recent first. Use for "show me" / "what happened" questions.',
        parameters: {
          type: 'OBJECT',
          properties: {
            department: { type: 'STRING' },
            severity: { type: 'STRING', description: 'CRITICAL, HIGH, MEDIUM, or LOW' },
            action: { type: 'STRING', description: 'Immediate, Investigate, or Monitor' },
            hours: { type: 'NUMBER', description: 'Look-back window in hours (default 24, max 720).' },
            limit: { type: 'NUMBER', description: 'Max results to return (default 5, max 20).' },
          },
        },
      },
      {
        name: 'list_devices',
        description: 'Lists onboarded medical devices from the asset inventory, optionally filtered by department or criticality.',
        parameters: {
          type: 'OBJECT',
          properties: {
            department: { type: 'STRING' },
            criticality: { type: 'STRING', description: 'low, medium, elevated, high, or critical' },
          },
        },
      },
      {
        name: 'get_agent_status',
        description:
          'Live count of active/disconnected/never-connected Wazuh agents (the endpoints reporting into this SIEM), from the Wazuh Manager itself — not the medical device inventory. Use this for any question about "agents", "connected hosts", or endpoint connectivity.',
        parameters: { type: 'OBJECT', properties: {} },
      },
    ],
  },
];

async function getAlertSummary(args) {
  const hours = clampHours(args.hours);
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);
  const match = { timestamp: { $gte: since } };
  const department = asPlainString(args.department);
  if (department) match.department = department;

  const rows = await AlertLog.aggregate([
    { $match: match },
    { $group: { _id: { severity: '$severity', action: '$action' }, count: { $sum: 1 } } },
  ]);

  const bySeverity = {};
  const byAction = {};
  let total = 0;
  for (const r of rows) {
    total += r.count;
    const sev = r._id.severity || 'UNKNOWN';
    const act = r._id.action || 'UNKNOWN';
    bySeverity[sev] = (bySeverity[sev] || 0) + r.count;
    byAction[act] = (byAction[act] || 0) + r.count;
  }
  return { hours, department: department || 'all', total, bySeverity, byAction };
}

async function searchAlerts(args) {
  const hours = clampHours(args.hours);
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);
  const query = { timestamp: { $gte: since } };
  const department = asPlainString(args.department);
  if (department) query.department = department;
  const severity = asPlainString(args.severity);
  if (severity) query.severity = severity.toUpperCase();
  const action = normalizeAction(args.action);
  if (action) query.action = action;
  const limit = Math.min(Math.max(Number(args.limit) || 5, 1), MAX_RESULTS);

  const docs = await AlertLog.find(query).sort({ timestamp: -1 }).limit(limit).lean();
  return {
    count: docs.length,
    alerts: docs.map((d) => ({
      timestamp: d.timestamp,
      agent: d.agent,
      department: d.department,
      label: d.label || d.ruleDescription,
      CAS: d.CAS,
      severity: d.severity,
      action: d.action,
    })),
  };
}

async function listDevices(args) {
  const query = {};
  const department = asPlainString(args.department);
  if (department) query.department = department;
  const criticality = asPlainString(args.criticality);
  if (criticality) query.criticality = criticality.toLowerCase();

  const docs = await MedicalDevice.find(query)
    .limit(MAX_RESULTS)
    .select('deviceName deviceType department criticality status location')
    .lean();
  return {
    count: docs.length,
    devices: docs.map((d) => ({
      deviceName: d.deviceName,
      deviceType: d.deviceType,
      department: d.department,
      criticality: d.criticality,
      status: d.status,
      location: d.location,
    })),
  };
}

async function executeToolCall(name, args, wazuhConfig) {
  if (name === 'get_alert_summary') return getAlertSummary(args);
  if (name === 'search_alerts') return searchAlerts(args);
  if (name === 'list_devices') return listDevices(args);
  if (name === 'get_agent_status') return getAgentStatusSummary(wazuhConfig);
  return { error: `Unknown tool: ${name}` };
}

// messages: [{ role: 'user'|'assistant', content: string }, ...] — the whole visible
// transcript, sent stateless from the frontend each turn (see AiChatWidget.tsx). Capped
// to the last 20 regardless of what the client sends, so a long-running chat can't
// grow the prompt (and the per-request token cost) without bound.
//
// wazuhConfig: forwarded from the browser's own x-wazuh-* headers (routes/assistant.js)
// — this backend never stores Wazuh credentials itself (see wazuhAgentStatus.js), so
// get_agent_status only has something to query when the caller's browser already
// connected Wazuh in this session.
export async function runChat(messages, wazuhConfig) {
  const contents = (messages || [])
    .filter((m) => m && typeof m.content === 'string' && m.content.trim())
    .slice(-20)
    .map((m) => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }] }));

  if (contents.length === 0) throw new Error('Message is empty.');

  return chatWithTools(
    { contents, tools: TOOLS, systemInstruction: SYSTEM_INSTRUCTION },
    (name, args) => executeToolCall(name, args, wazuhConfig)
  );
}
