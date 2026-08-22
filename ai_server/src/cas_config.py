# Thin loader over ../../shared/cas_config.json — the single source of truth
# for CAS scoring config, shared with backend/services/caapService.js (Node).
# Do not hardcode weights/device-profiles/AE tables anywhere else; import
# them from here (app.py, cas_engine.py) so the live and offline-research
# engines can no longer silently drift apart the way they previously did.
import json
import os
import re

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_SCRIPT_DIR, "..", ".."))
CONFIG_PATH = os.path.join(_REPO_ROOT, "shared", "cas_config.json")

with open(CONFIG_PATH, "r", encoding="utf-8") as _f:
    _CFG = json.load(_f)

# ── Weights (fractions — identical regardless of the 1-5 vs 1-10 dimension
#    scale, since they're multiplied against whichever scale is in use) ──────
DEFAULT_WEIGHTS = dict(_CFG["default_weights"])

# ── CC (Clinical Criticality) — 1-10 scale, matches app.py's live convention.
#    cas_engine.py derives its own 1-5 view by dividing these by 2. ─────────
CRITICALITY_TO_CC = dict(_CFG["criticality_to_cc"])
CC_LOOKUP = dict(_CFG["cc_lookup_by_device_type"])
DEFAULT_CC = float(_CFG["default_cc"])

DEVICE_PROFILES = {}
for _p in _CFG["device_profiles"]:
    _key = (int(_p["dst_port"]), str(_p["protocol"]).strip().lower())
    DEVICE_PROFILES[_key] = {
        "device_name": _p["device_name"],
        "fda_class": _p["fda_class"],
        "cc": float(_p["cc"]),
        "patient_dep": int(_p["patient_dep"]),
        "dept": _p["dept"],
        "notes": _p["notes"],
    }

DEFAULT_DEVICE_PROFILE = {
    "device_name": "Unknown Networked Device",
    "fda_class": "I",
    "cc": DEFAULT_CC,
    "patient_dep": 0,
    "dept": "Unknown",
    "notes": "Default: FDA Class I per 21 CFR 860.3 - no specific classification found",
}


def lookup_device_profile(dst_port, protocol: str = "tcp") -> dict:
    """Port/protocol -> device profile (device_name, fda_class, cc [1-10],
    patient_dep, dept, notes). Falls back to DEFAULT_DEVICE_PROFILE."""
    if dst_port is None:
        return dict(DEFAULT_DEVICE_PROFILE)
    try:
        key = (int(dst_port), str(protocol).strip().lower())
    except (TypeError, ValueError):
        return dict(DEFAULT_DEVICE_PROFILE)
    if key in DEVICE_PROFILES:
        return DEVICE_PROFILES[key]
    key_any = (key[0], "any")
    if key_any in DEVICE_PROFILES:
        return DEVICE_PROFILES[key_any]
    return dict(DEFAULT_DEVICE_PROFILE)


# ── AE (Active Exploitation) — attack-type base severity, 1-10 scale ───────
AE_TABLE = dict(_CFG["ae_table"])
DEFAULT_AE = float(_CFG["default_ae"])


# ── CVSS-equivalent baseline — shown alongside CAS in the live dashboard so the
#    CAS-vs-CVSS comparison isn't confined to the offline evaluation notebook.
#    Same values hospital_scenarios.py uses (that module now imports these
#    instead of keeping its own copy, so the live demo and the formal
#    evaluation can never silently drift apart). ─────────────────────────────
CVSS_BASE_BY_LABEL = dict(_CFG["cvss_base_by_label"])
DEFAULT_CVSS = float(_CFG["default_cvss"])


def lookup_cvss(predicted_label: str) -> float:
    """CVSS-equivalent base score for an attack label — a representative
    CVSS v3.1 base-score band per attack technique's general CWE class, not a
    real per-CVE score (no CVE field exists anywhere in this dataset). Purely
    a comparison baseline: unlike CAS, it never varies by device or time."""
    return float(CVSS_BASE_BY_LABEL.get(predicted_label, DEFAULT_CVSS))


def lookup_ae(predicted_label: str, cve_known_exploited: bool = False) -> float:
    """Attack-type base severity, boosted (not overridden) by an independent
    known-exploited-CVE/IP-reputation signal — so a real CVE hit still always
    reaches the ceiling, but every other alert varies by attack type instead
    of collapsing to one flat non-CVE value."""
    base = float(AE_TABLE.get(predicted_label, DEFAULT_AE))
    boosted = 10.0 if cve_known_exploited else 0.0
    return max(base, boosted)


# ── TC (Temporal Context) — 3-tier shift, 1-10 scale ────────────────────────
TC_TABLE = dict(_CFG["tc_table"])
SHIFT_HOURS = dict(_CFG["shift_hours"])


def shift_for_hour(hour_of_day) -> str:
    """Mirrors test.py's current_shift() hour boundaries exactly (day 07-15,
    evening 15-23, else night) so every consumer agrees on the same clock."""
    try:
        h = int(hour_of_day) % 24
    except (TypeError, ValueError):
        return "day"
    day_start, day_end = SHIFT_HOURS["day"]
    eve_start, eve_end = SHIFT_HOURS["evening"]
    if day_start <= h < day_end:
        return "day"
    if eve_start <= h < eve_end:
        return "evening"
    return "night"


def lookup_tc(hour_of_day) -> float:
    return float(TC_TABLE.get(shift_for_hour(hour_of_day), TC_TABLE["day"]))


# ── Protocol normalisation — ported from test.py's normalise_protocol() ────
PROTO_MAP = {int(k): v for k, v in _CFG["proto_map"].items()}


def normalise_protocol(val) -> str:
    try:
        return PROTO_MAP.get(int(float(val)), "tcp")
    except (TypeError, ValueError):
        s = str(val).strip().lower()
        return s if s in ("tcp", "udp", "icmp", "igmp", "mqtt") else "tcp"


# ── Scenario-adaptive weight profiles ───────────────────────────────────────
SCENARIO_WEIGHT_PROFILES = {k: dict(v) for k, v in _CFG["scenario_weight_profiles"].items()}
SCENARIO_DEPARTMENT_MAP = {k: list(v) for k, v in _CFG["scenario_department_map"].items()}

_DEPT_TO_SCENARIO = {}
for _scenario_key, _depts in SCENARIO_DEPARTMENT_MAP.items():
    for _d in _depts:
        _DEPT_TO_SCENARIO[_d.strip().lower()] = _scenario_key


def resolve_scenario_key(department: str) -> str:
    """MedicalDevice.department (free text) -> one of SCENARIO_WEIGHT_PROFILES'
    keys. Exact match first, then whole-token match on compound strings (e.g.
    'ICU / General Ward' -> tokens 'icu','general','ward') so short
    abbreviations like 'IT'/'ENT' can't false-positive as a raw substring of
    an unrelated word (e.g. 'ent' inside 'department'), else the blended
    hospital-wide default."""
    if not department:
        return "hospital_wide_mixed"
    dept_l = str(department).strip().lower()
    if dept_l in _DEPT_TO_SCENARIO:
        return _DEPT_TO_SCENARIO[dept_l]
    for token in re.split(r"[^a-z0-9]+", dept_l):
        if token and token in _DEPT_TO_SCENARIO:
            return _DEPT_TO_SCENARIO[token]
    return "hospital_wide_mixed"


def weights_sum_valid(weights: dict, tol: float = 0.01) -> bool:
    try:
        total = sum(float(weights[k]) for k in ("TR", "CC", "TS", "AE", "TC"))
    except (KeyError, TypeError, ValueError):
        return False
    return abs(total - 1.0) <= tol


def resolve_weights(posted_weights: dict = None, scenario: str = None):
    """Returns (weights_dict, source_label). Prefers an explicitly posted
    vector (e.g. forwarded by caapService.js from SystemSettings) if it's
    valid; otherwise the named scenario profile; otherwise the AHP-justified
    default. `source_label` is echoed back in /predict's response so an
    analyst/researcher can see which vector actually produced a score."""
    if posted_weights and weights_sum_valid(posted_weights):
        return {k: float(posted_weights[k]) for k in ("TR", "CC", "TS", "AE", "TC")}, (scenario or "custom")
    key = scenario if scenario in SCENARIO_WEIGHT_PROFILES else "default"
    return dict(SCENARIO_WEIGHT_PROFILES[key]), key
