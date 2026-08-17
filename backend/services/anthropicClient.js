import Anthropic from '@anthropic-ai/sdk';
import SystemSettings from '../models/SystemSettings.js';

// Shared client cache for every Anthropic call site (triage, close-draft, case summary,
// report narratives, rule drafting, NL query parsing) — one place reads the
// admin-configured key from SystemSettings and re-creates the client only when it changes.
let cachedClient = null;
let cachedKey = null;

export async function getAnthropicClient() {
  const settings = await SystemSettings.findOne().select('+anthropicApiKey');
  const apiKey = settings?.anthropicApiKey;
  if (!apiKey) return null;

  if (!cachedClient || cachedKey !== apiKey) {
    cachedClient = new Anthropic({ apiKey });
    cachedKey = apiKey;
  }
  return cachedClient;
}

export async function isAnthropicConfigured() {
  return !!(await getAnthropicClient());
}

export function friendlyAnthropicError(err) {
  if (err instanceof Anthropic.AuthenticationError) {
    return 'The configured Anthropic API key was rejected — check it in Settings → Integrations.';
  }
  if (err instanceof Anthropic.RateLimitError) {
    return 'AI assistant is rate-limited right now — try again shortly.';
  }
  return 'AI assistant request failed: ' + (err.message || 'unknown error');
}

// Every structured-output call site asks for strict JSON and parses it the same way.
export function extractText(response) {
  if (response.stop_reason === 'refusal') throw new Error('The AI assistant declined to respond.');
  const text = response.content.find((block) => block.type === 'text')?.text?.trim();
  if (!text) throw new Error('AI assistant returned an empty response.');
  return text;
}

export function extractJson(response) {
  const text = extractText(response);
  // Strip a markdown fence if the model wraps its JSON in one despite instructions not to.
  const cleaned = text.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '').trim();
  try {
    return JSON.parse(cleaned);
  } catch {
    throw new Error('AI assistant returned malformed output — try again.');
  }
}
