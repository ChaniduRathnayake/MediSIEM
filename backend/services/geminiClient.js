// Google Gemini (Generative Language API) — MediSIEM's sole AI-assistant provider, used
// by aiAssistantService.js and triageAssistantService.js. Called directly over REST (no
// @google/genai SDK dependency, same pattern as caapService.js/ipReputationService.js's
// bare fetch() calls elsewhere in this codebase). Key is admin-configured in Settings →
// Integrations, never in backend/.env.
import SystemSettings from '../models/SystemSettings.js';

const GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta/models';
// NOTE: 'gemini-flash-latest' looks tempting (auto-tracks newest) but the alias
// itself hung indefinitely when tested directly against the real API, while this
// pinned version answered in ~2s — pin to a specific version, don't chase "-latest".
const GEMINI_MODEL = 'gemini-3.6-flash';
// Without this, an unreachable/slow Gemini endpoint hangs the request (and the
// frontend's "Asking AI assistant…" spinner) indefinitely — same guard
// ipReputationService.js already uses for its own outbound call.
const FETCH_TIMEOUT_MS = 20_000;

export async function getGeminiApiKey() {
  const settings = await SystemSettings.findOne().select('+googleApiKey');
  return settings?.googleApiKey || null;
}

export async function isGeminiConfigured() {
  return !!(await getGeminiApiKey());
}

// Gemini's 429 body carries a google.rpc.RetryInfo (a concrete retryDelay, e.g. "20s")
// and/or a QuotaFailure detail naming which specific limit was hit — surfacing those
// turns "rate-limited, try again shortly" (which looks identical whether it clears in
// 5 seconds or the key is out of quota for the day) into something actionable.
function parseRetryInfo(details) {
  const retryInfo = (details || []).find((d) => d['@type']?.includes('RetryInfo'));
  return retryInfo?.retryDelay || null;
}
function parseQuotaId(details) {
  const quotaFailure = (details || []).find((d) => d['@type']?.includes('QuotaFailure'));
  return quotaFailure?.violations?.[0]?.quotaId || null;
}

export function friendlyGeminiError({ status, message, details } = {}) {
  if (status === 401 || status === 403) {
    return 'The configured AI assistant API key was rejected — check it in Settings → Integrations.';
  }
  if (status === 429) {
    const retryDelay = parseRetryInfo(details);
    const quotaId = parseQuotaId(details);
    const perDay = quotaId?.toLowerCase().includes('day');
    if (perDay) {
      return "AI assistant has hit its daily free-tier quota for this API key — it won't recover until the quota resets (typically ~24h), or a higher-tier key is configured in Settings → Integrations.";
    }
    return retryDelay
      ? `AI assistant is rate-limited right now — try again in about ${retryDelay}.`
      : 'AI assistant is rate-limited right now — try again in about a minute.';
  }
  return 'AI assistant request failed: ' + (message || 'unknown error');
}

// Shared low-level call: POST generateContent with a timeout, and surface the raw
// candidate (not just text) so callGemini() can pull text and chatWithTools() can
// also inspect functionCall parts / feed the candidate straight back into the
// next turn's contents.
async function postGenerateContent(body, apiKey) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  let res;
  try {
    res = await fetch(`${GEMINI_API_BASE}/${GEMINI_MODEL}:generateContent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error('AI assistant request timed out — try again shortly.');
    }
    throw new Error(friendlyGeminiError({ message: err.message }));
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    throw new Error(friendlyGeminiError({ status: res.status, message: errBody?.error?.message, details: errBody?.error?.details }));
  }

  const data = await res.json();
  const candidate = data?.candidates?.[0];
  if (candidate?.finishReason === 'SAFETY' || candidate?.finishReason === 'RECITATION') {
    throw new Error('The AI assistant declined to respond.');
  }
  return candidate;
}

async function callGemini(prompt, { maxTokens, wantJson }) {
  const apiKey = await getGeminiApiKey();
  if (!apiKey) throw new Error('AI assistant is not configured — add an API key in Settings → Integrations.');

  const candidate = await postGenerateContent(
    {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        maxOutputTokens: maxTokens,
        ...(wantJson ? { responseMimeType: 'application/json' } : {}),
      },
    },
    apiKey
  );
  const text = (candidate?.content?.parts || []).map((p) => p.text || '').join('').trim();
  if (!text) throw new Error('AI assistant returned an empty response.');
  return text;
}

// Multi-turn function-calling loop for the data-aware chat assistant
// (chatAssistantService.js). Gemini's REST convention, verified empirically against
// the real API rather than assumed: a function-call turn comes back as
// {role:'model', parts:[{functionCall:{name,args}}]} — pushed back verbatim — and the
// executed result is fed in as {role:'user', parts:[{functionResponse:{name,response}}]}
// ('role:"function"' looks like the natural choice but the API rejects it outright:
// only SYSTEM/USER/MODEL/ASSISTANT/... are valid roles here).
export async function chatWithTools({ contents, tools, systemInstruction, maxTokens = 1000 }, executeToolCall, maxSteps = 4) {
  const apiKey = await getGeminiApiKey();
  if (!apiKey) throw new Error('AI assistant is not configured — add an API key in Settings → Integrations.');

  const workingContents = [...contents];

  for (let step = 0; step < maxSteps; step++) {
    const candidate = await postGenerateContent(
      {
        contents: workingContents,
        tools,
        ...(systemInstruction ? { systemInstruction: { parts: [{ text: systemInstruction }] } } : {}),
        generationConfig: { maxOutputTokens: maxTokens },
      },
      apiKey
    );

    const parts = candidate?.content?.parts || [];
    const functionCallPart = parts.find((p) => p.functionCall);

    if (!functionCallPart) {
      const text = parts.map((p) => p.text || '').join('').trim();
      if (!text) throw new Error('AI assistant returned an empty response.');
      return text;
    }

    const { name, args } = functionCallPart.functionCall;
    const result = await executeToolCall(name, args || {});
    workingContents.push(candidate.content);
    workingContents.push({ role: 'user', parts: [{ functionResponse: { name, response: result } }] });
  }

  throw new Error('AI assistant took too many steps to answer that — try rephrasing your question.');
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
