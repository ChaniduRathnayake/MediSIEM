// Google Gemini (Generative Language API) — MediSIEM's sole AI-assistant provider, used
// by aiAssistantService.js and triageAssistantService.js. Called directly over REST (no
// @google/genai SDK dependency, same pattern as caapService.js/ipReputationService.js's
// bare fetch() calls elsewhere in this codebase). Key is admin-configured in Settings →
// Integrations, never in backend/.env.
import SystemSettings from '../models/SystemSettings.js';

const GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta/models';
const GEMINI_MODEL = 'gemini-flash-latest';

export async function getGeminiApiKey() {
  const settings = await SystemSettings.findOne().select('+googleApiKey');
  return settings?.googleApiKey || null;
}

export async function isGeminiConfigured() {
  return !!(await getGeminiApiKey());
}

export function friendlyGeminiError({ status, message } = {}) {
  if (status === 401 || status === 403) {
    return 'The configured Google Gemini API key was rejected — check it in Settings → Integrations.';
  }
  if (status === 429) {
    return 'AI assistant is rate-limited right now — try again shortly.';
  }
  return 'AI assistant request failed: ' + (message || 'unknown error');
}

async function callGemini(prompt, { maxTokens, wantJson }) {
  const apiKey = await getGeminiApiKey();
  if (!apiKey) throw new Error('AI assistant is not configured — add a Google Gemini API key in Settings → Integrations.');

  const body = {
    contents: [{ parts: [{ text: prompt }] }],
    generationConfig: {
      maxOutputTokens: maxTokens,
      ...(wantJson ? { responseMimeType: 'application/json' } : {}),
    },
  };

  let res;
  try {
    res = await fetch(`${GEMINI_API_BASE}/${GEMINI_MODEL}:generateContent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
      body: JSON.stringify(body),
    });
  } catch (err) {
    throw new Error(friendlyGeminiError({ message: err.message }));
  }

  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    throw new Error(friendlyGeminiError({ status: res.status, message: errBody?.error?.message }));
  }

  const data = await res.json();
  const candidate = data?.candidates?.[0];
  if (candidate?.finishReason === 'SAFETY' || candidate?.finishReason === 'RECITATION') {
    throw new Error('The AI assistant declined to respond.');
  }
  const text = (candidate?.content?.parts || []).map((p) => p.text || '').join('').trim();
  if (!text) throw new Error('AI assistant returned an empty response.');
  return text;
}

export async function generateGeminiText(prompt, maxTokens = 500) {
  return callGemini(prompt, { maxTokens, wantJson: false });
}

// Requests JSON output mode directly (responseMimeType) rather than relying only on
// prompt instructions, then still strips a markdown fence defensively in case Gemini
// wraps the JSON in one despite that.
export async function generateGeminiJson(prompt, maxTokens = 700) {
  const text = await callGemini(prompt, { maxTokens, wantJson: true });
  const cleaned = text.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '').trim();
  try {
    return JSON.parse(cleaned);
  } catch {
    throw new Error('AI assistant returned malformed output — try again.');
  }
}
