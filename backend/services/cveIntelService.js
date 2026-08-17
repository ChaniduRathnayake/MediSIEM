// "Is this actively exploited in the wild" signal for the CAS Active
// Exploitation (AE) dimension, sourced from CISA's Known Exploited
// Vulnerabilities (KEV) catalog. The lab network this runs against may have
// no internet route to CISA, so every failure mode here degrades to "no
// known-exploited match" rather than throwing.
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const REFRESH_MS = 24 * 60 * 60 * 1000; // KEV is updated at most a few times a day
const FETCH_TIMEOUT_MS = 10_000;

let kevSet = new Set(); // uppercased "CVE-YYYY-NNNN..." strings
let lastUpdated = null; // Date the catalog was last successfully fetched
let lastError = null;
let refreshHandle = null;
let refreshingPromise = null;

async function fetchWithTimeout(url, ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function refreshKev() {
  if (refreshingPromise) return refreshingPromise;

  refreshingPromise = (async () => {
    try {
      const res = await fetchWithTimeout(KEV_URL, FETCH_TIMEOUT_MS);
      if (!res.ok) throw new Error(`CISA KEV responded ${res.status}`);
      const json = await res.json();
      const vulns = Array.isArray(json?.vulnerabilities) ? json.vulnerabilities : [];

      const next = new Set();
      for (const v of vulns) {
        if (v?.cveID) next.add(String(v.cveID).toUpperCase());
      }

      if (next.size > 0) {
        kevSet = next;
        lastUpdated = new Date();
        lastError = null;
        console.log(`[cveIntel] Loaded ${kevSet.size} known-exploited CVEs from CISA KEV`);
      } else {
        throw new Error('CISA KEV response had no vulnerabilities — keeping previous catalog');
      }
    } catch (err) {
      lastError = err.message;
      // Deliberately not `console.error` — a firewalled/offline lab network
      // is an expected, routine condition here, not an operational fault.
      console.warn(`[cveIntel] KEV refresh failed (${err.message}) — AE scoring falls back to the MITRE-technique heuristic until this succeeds.`);
    } finally {
      refreshingPromise = null;
    }
  })();

  return refreshingPromise;
}

/** Call once at server startup — fires an initial fetch, then refreshes on a timer. Never throws. */
export function initCveIntel() {
  if (refreshHandle) return; // already running
  refreshKev();
  refreshHandle = setInterval(refreshKev, REFRESH_MS);
}

export function stopCveIntel() {
  if (refreshHandle) clearInterval(refreshHandle);
  refreshHandle = null;
}

const CVE_PATTERN = /CVE-\d{4}-\d{4,7}/gi;

/**
 * Pull every CVE ID a raw Wazuh/flow alert doc references, from whichever
 * field actually carries one on this deployment's ruleset/decoders:
 *   - data.vulnerability.cve      (Wazuh vulnerability-detector alerts)
 *   - rule.cve / rule.info.cve    (some custom rules tag this directly)
 *   - rule.description/full_log  (free-text mentions, e.g. "CVE-2021-44228 ...")
 */
export function extractCveIds(rawAlert = {}) {
  const found = new Set();

  const direct = rawAlert?.data?.vulnerability?.cve || rawAlert?.rule?.cve;
  if (direct) String(direct).toUpperCase().match(CVE_PATTERN)?.forEach((id) => found.add(id));

  const haystack = `${rawAlert?.rule?.description || ''} ${rawAlert?.full_log || ''}`;
  haystack.toUpperCase().match(CVE_PATTERN)?.forEach((id) => found.add(id));

  return [...found];
}

/** True if any of the given CVE IDs are in CISA's actively-exploited catalog. */
export function isKnownExploited(cveIds = []) {
  return cveIds.some((id) => kevSet.has(String(id).toUpperCase()));
}

/**
 * Best-effort "is this alert tied to active exploitation" signal:
 *   1. A real CVE on the alert that's in the KEV catalog — strongest signal.
 *   2. No CVE present, but the rule carries a MITRE ATT&CK technique — a
 *      weaker fallback (categorized adversary behavior, not confirmed
 *      exploitation of a specific flaw), kept for alerts that legitimately
 *      have no CVE to check (most HIDS/behavioral rules).
 * Returns both the boolean AE input and which path produced it, so callers
 * can be honest in `explanation` about which one fired.
 */
export function assessExploitation(rawAlert = {}) {
  const cveIds = extractCveIds(rawAlert);
  if (cveIds.length > 0 && kevSet.size > 0) {
    return { exploited: isKnownExploited(cveIds), basis: 'cve', cveIds };
  }
  const hasMitre = Boolean(rawAlert?.rule?.mitre?.id?.length);
  return { exploited: hasMitre, basis: hasMitre ? 'mitre' : 'none', cveIds };
}

export function getKevStatus() {
  return { loaded: kevSet.size > 0, count: kevSet.size, lastUpdated, lastError };
}
