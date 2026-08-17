// Optional IP-reputation signal for CAAP's Active Exploitation (AE)
// dimension, alongside cveIntelService.js's CISA KEV check — checks a raw
// alert's source IP against AbuseIPDB's abuse-confidence score. With no
// AbuseIPDB key configured (Settings -> Integrations), degrades to "no
// reputation data available" rather than blocking scoring.
import SystemSettings from '../models/SystemSettings.js';

const ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check';
const FETCH_TIMEOUT_MS = 5_000;
// AbuseIPDB's free tier is rate-limited (1000 checks/day) and an IP's
// reputation doesn't meaningfully change minute to minute — cache each
// lookup for an hour rather than re-querying on every alert from the same
// (likely repeat-offender) source IP.
const CACHE_TTL_MS = 60 * 60 * 1000;
// AbuseIPDB's own 0-100 "confidence of abuse" scale — 50+ is their commonly
// cited threshold for "likely malicious", not an arbitrary pick here.
const MALICIOUS_SCORE_THRESHOLD = 50;

const cache = new Map(); // ip -> { score, checkedAt }

async function fetchWithTimeout(url, options, ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

// RFC1918 / loopback / link-local — never worth an external lookup, and the
// lab network this pipeline runs against is entirely private-range IPs, so
// skip the API call (and don't burn free-tier quota) for every internal hop.
function isPrivateOrInvalid(ip) {
  if (!ip || typeof ip !== 'string') return true;
  return /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
}

/**
 * Best-effort AbuseIPDB lookup for a source IP. Returns null (not "clean")
 * when there's nothing to say — no key configured, the IP is private, or
 * the API call failed — so callers can tell "no signal" apart from
 * "confirmed clean" (score 0) rather than treating both the same.
 */
export async function checkIpReputation(ip) {
  if (isPrivateOrInvalid(ip)) return null;

  const cached = cache.get(ip);
  if (cached && Date.now() - cached.checkedAt < CACHE_TTL_MS) return cached.score;

  const settings = await SystemSettings.findOne().select('+abuseIpdbApiKey');
  if (!settings?.abuseIpdbApiKey) return null;

  try {
    const res = await fetchWithTimeout(
      `${ABUSEIPDB_URL}?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      { headers: { Key: settings.abuseIpdbApiKey, Accept: 'application/json' } },
      FETCH_TIMEOUT_MS
    );
    if (!res.ok) throw new Error(`AbuseIPDB responded ${res.status}`);
    const json = await res.json();
    const score = Number(json?.data?.abuseConfidenceScore ?? 0);
    cache.set(ip, { score, checkedAt: Date.now() });
    return score;
  } catch (err) {
    console.warn(`[ipReputation] AbuseIPDB lookup failed for ${ip}: ${err.message}`);
    return null;
  }
}

export function isMalicious(score) {
  return typeof score === 'number' && score >= MALICIOUS_SCORE_THRESHOLD;
}

export { MALICIOUS_SCORE_THRESHOLD };
