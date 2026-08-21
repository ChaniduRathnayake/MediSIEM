// A single, non-agentic AI-assistant call that turns an already-scored alert into a short
// plain-language explanation + recommended next step for a SOC analyst. Backed by Google
// Gemini (services/geminiClient.js).
import { isGeminiConfigured, generateGeminiText } from './geminiClient.js';

export const isTriageAssistantConfigured = isGeminiConfigured;

function formatShap(shapFeatures) {
  if (!Array.isArray(shapFeatures) || shapFeatures.length === 0) return null;
  return shapFeatures
    .map((f) => `${f.feature} (${f.direction} the score, contribution ${f.value > 0 ? '+' : ''}${f.value})`)
    .join('; ');
}

function buildPrompt(alert) {
  const shapText = formatShap(alert.shap_top_features);
  const lines = [
    'You are assisting a SOC analyst at a hospital triaging a security alert flagged by an automated detection system (MediSIEM). Use the structured data below — do not invent facts not present in it.',
    '',
    `Event: ${alert.label && alert.label !== 'Unclassified' ? alert.label : alert.ruleDescription || 'Unknown event'}`,
    `Device: ${alert.agent || 'unknown device'} (type: ${alert.deviceType || 'unknown'}, criticality: ${alert.deviceCriticality || 'unknown'}) in ${alert.department || 'an unspecified department'}`,
    `Clinical Alert Score (CAS): ${alert.CAS ?? 'n/a'}/10 → recommended action: ${alert.action || 'n/a'}`,
    `Score breakdown — Threat Risk: ${alert.TR_score ?? 'n/a'}, Clinical Criticality: ${alert.CC_score ?? 'n/a'}, Time Sensitivity: ${alert.TS_score ?? 'n/a'}, Active Exploitation: ${alert.AE_score ?? 'n/a'}, Temporal Context: ${alert.TC_score ?? 'n/a'} (each out of 10, weighted into the CAS).`,
    shapText
      ? `Top model signals driving the classification: ${shapText}.`
      : `Model explanation: ${alert.explanation || 'not available'}.`,
    alert.mitre?.tactic ? `MITRE ATT&CK tactic: ${alert.mitre.tactic}${alert.mitre.id ? ` (${alert.mitre.id})` : ''}.` : '',
    '',
    'In 3-4 short sentences: (1) explain in plain language why this alert scored the way it did, and (2) recommend a concrete next step for the analyst given the device context. Do not restate the raw numbers verbatim — interpret them. Do not include a preamble like "Based on the data provided".',
  ];
  return lines.filter(Boolean).join('\n');
}

export async function generateTriageExplanation(alert) {
  return generateGeminiText(buildPrompt(alert), 500);
}
