// Six single-call, non-agentic AI-assistant uses — case-close drafting, investigation
// summaries, report narratives, plain-English rule authoring, and natural-language alert
// search. All backed by Google Gemini (services/geminiClient.js).
import { generateGeminiText, generateGeminiJson } from './geminiClient.js';
import { RULE_FIELDS, RULE_OPERATORS } from '../models/DetectionRule.js';

async function callText(prompt, maxTokens = 500) {
  return generateGeminiText(prompt, maxTokens);
}

async function callJson(prompt, maxTokens = 700) {
  return generateGeminiJson(prompt, maxTokens);
}

function alertSummaryLines(alert) {
  return [
    `Event: ${alert.label && alert.label !== 'Unclassified' ? alert.label : alert.ruleDescription || 'Unknown event'}`,
    `Device: ${alert.agent || 'unknown'} (type: ${alert.deviceType || 'unknown'}, criticality: ${alert.deviceCriticality || 'unknown'}) in ${alert.department || 'an unspecified department'}`,
    `Clinical Alert Score (CAS): ${alert.CAS ?? 'n/a'}/10 → recommended action: ${alert.action || 'n/a'}`,
    `Score breakdown — Threat Risk: ${alert.TR_score ?? 'n/a'}, Clinical Criticality: ${alert.CC_score ?? 'n/a'}, Time Sensitivity: ${alert.TS_score ?? 'n/a'}, Active Exploitation: ${alert.AE_score ?? 'n/a'}, Temporal Context: ${alert.TC_score ?? 'n/a'}.`,
    alert.explanation ? `Model explanation: ${alert.explanation}` : '',
    alert.mitre?.tactic?.length ? `MITRE ATT&CK tactic: ${alert.mitre.tactic.join(', ')}.` : '',
  ].filter(Boolean);
}

// ─── 1. Draft a close-case reason + evidence ───────────────────────────────────
export async function generateCloseDraft(alert, notes, relatedCount) {
  const noteLines = notes.length
    ? notes.map((n) => `- [${new Date(n.createdAt).toLocaleString()}] ${n.author.name}: ${n.text}`).join('\n')
    : '(no investigation notes were recorded)';

  const prompt = [
    'You are drafting a case-closure entry for a SOC analyst at a hospital, based on the alert data and investigation notes below. The analyst will review and edit this before submitting — do not invent facts not present in the data.',
    '',
    ...alertSummaryLines(alert),
    `Other alerts on this device within 2 hours: ${relatedCount}.`,
    '',
    'Investigation notes:',
    noteLines,
    '',
    'Respond with ONLY valid JSON (no markdown fences), matching exactly this shape:',
    '{"verdict": "true_positive" | "false_positive" | "benign" | "uncertain", "reason": "<one short sentence, under 100 chars>", "evidence": "<2-4 sentences citing the specific data/notes above that support the reason>"}',
    'If the notes are empty or inconclusive, prefer verdict "uncertain" rather than guessing.',
  ].join('\n');

  const json = await callJson(prompt);
  const VALID_VERDICTS = ['true_positive', 'false_positive', 'benign', 'uncertain'];
  if (!json.reason || !json.evidence || !VALID_VERDICTS.includes(json.verdict)) {
    throw new Error('AI assistant returned an unexpected shape — try again.');
  }
  return { verdict: json.verdict, reason: String(json.reason).slice(0, 500), evidence: String(json.evidence).slice(0, 5000) };
}

// ─── 2. Summarize a case's investigation notes ─────────────────────────────────
export async function generateCaseSummary(alert, notes) {
  const noteLines = notes.map((n) => `- [${new Date(n.createdAt).toLocaleString()}] ${n.author.name}: ${n.text}`).join('\n');
  const prompt = [
    'Summarize the investigation so far on this security case, for an analyst picking it up mid-shift who has not read the notes below.',
    '',
    ...alertSummaryLines(alert),
    '',
    'Investigation notes, in order:',
    noteLines,
    '',
    'In 3-5 short sentences: what has been checked, what was found, and what (if anything) is still outstanding. Do not restate the raw alert data — focus on what the notes actually say.',
  ].join('\n');
  return callText(prompt);
}

// ─── 3. Narrative for the Threat Summary report ────────────────────────────────
export async function generateThreatNarrative(summary) {
  const prompt = [
    'Turn this security alert-volume summary (JSON) into a short narrative for a hospital security report, readable by someone who is not a SOC analyst.',
    '',
    JSON.stringify(summary),
    '',
    'In 2-4 sentences: describe the overall volume/severity picture, call out the single most notable pattern (busiest department or device, or a severity skew), and avoid restating every number. Plain English, no bullet points, no preamble.',
  ].join('\n');
  return callText(prompt, 300);
}

// ─── 4. Narrative for the Compliance Evidence report ───────────────────────────
export async function generateComplianceNarrative(summary, framework) {
  const prompt = [
    `Turn this ${framework.toUpperCase()} compliance-activity summary (JSON) — which devices triggered alerts against which ${framework.toUpperCase()} controls — into a short paragraph suitable for an audit record.`,
    '',
    JSON.stringify(summary),
    '',
    'In 3-5 sentences: state the reporting window, how many devices/controls were involved, and name the most-triggered control(s) if any stand out. State plainly that this reflects observed alert activity, not a certified audit. No bullet points, no preamble.',
  ].join('\n');
  return callText(prompt, 350);
}

// ─── 5. Plain-English detection rule authoring ─────────────────────────────────
export async function draftDetectionRule(promptText) {
  const prompt = [
    'A security admin wants to create a detection rule for MediSIEM (a hospital SIEM) from this plain-English description:',
    '',
    `"${promptText}"`,
    '',
    `Allowed condition fields: ${RULE_FIELDS.join(', ')}.`,
    `Allowed operators: ${RULE_OPERATORS.join(', ')} (use gte/lte/gt/lt only for numeric fields like CAS or ruleLevel; use contains/equals for text fields).`,
    '',
    'Respond with ONLY valid JSON (no markdown fences), matching exactly this shape:',
    '{"name": "<short rule name, under 60 chars>", "description": "<one sentence>", "conditions": [{"field": "<one of the allowed fields>", "operator": "<one of the allowed operators>", "value": "<string or number>"}]}',
    'Use only the allowed fields/operators listed above — never invent a field or operator not in those lists. Conditions are combined with AND (no OR logic is supported).',
  ].join('\n');

  const json = await callJson(prompt);
  if (!json.name || !Array.isArray(json.conditions) || json.conditions.length === 0) {
    throw new Error('AI assistant returned an unexpected shape — try again.');
  }
  const conditions = json.conditions.filter((c) => RULE_FIELDS.includes(c.field) && RULE_OPERATORS.includes(c.operator) && c.value !== undefined && c.value !== '');
  if (conditions.length === 0) {
    throw new Error('AI assistant did not produce any valid conditions — try rephrasing.');
  }
  return { name: String(json.name).slice(0, 120), description: String(json.description || '').slice(0, 500), conditions };
}

// ─── 6. Natural-language alert search -> AlertsPanel filter shape ─────────────
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const ACTIONS = ['Immediate', 'Investigate', 'Monitor'];
const DETECTION_FILTERS = ['all', 'ml', 'rules', 'combined'];
const SORT_BY = ['cas', 'time'];

export async function parseAlertQuery(promptText, departments) {
  const prompt = [
    'Translate this SOC analyst\'s plain-English alert search into a structured filter for MediSIEM\'s Alerts table.',
    '',
    `Query: "${promptText}"`,
    '',
    `Known departments in the current data: ${departments.length ? departments.join(', ') : '(none loaded)'}.`,
    `Valid severity values: ${SEVERITIES.join(', ')}, or "all".`,
    `Valid action values: ${ACTIONS.join(', ')}, or "all".`,
    `Valid detection-source values: ${DETECTION_FILTERS.join(', ')} ("ml" = ML-only detections, "rules" = custom-rule-only, "combined" = both).`,
    `Valid sort values: ${SORT_BY.join(', ')} ("cas" = Clinical Alert Score, "time" = most recent).`,
    '',
    'Respond with ONLY valid JSON (no markdown fences), matching exactly this shape:',
    '{"severityFilter": "<severity or all>", "departmentFilter": "<a known department or all>", "actionFilter": "<action or all>", "detectionFilter": "<detection-source value>", "sortBy": "<sort value>", "search": "<any remaining free-text terms, or empty string>"}',
    'If the query does not mention a dimension, use "all" (or "cas" for sortBy, or "" for search). Only use a department from the known list above — if none match, use "all" and put the term in "search" instead.',
  ].join('\n');

  const json = await callJson(prompt, 400);
  return {
    severityFilter: SEVERITIES.includes(json.severityFilter) ? json.severityFilter : 'all',
    departmentFilter: departments.includes(json.departmentFilter) ? json.departmentFilter : 'all',
    actionFilter: ACTIONS.includes(json.actionFilter) ? json.actionFilter : 'all',
    detectionFilter: DETECTION_FILTERS.includes(json.detectionFilter) ? json.detectionFilter : 'all',
    sortBy: SORT_BY.includes(json.sortBy) ? json.sortBy : 'cas',
    search: typeof json.search === 'string' ? json.search.slice(0, 200) : '',
  };
}
