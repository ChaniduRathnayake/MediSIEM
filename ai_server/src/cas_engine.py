# Clinical Alert Score (CAS) engine. Formula: CAS = 2 x (0.25*TR + 0.30*CC +
# 0.25*TS + 0.10*AE + 0.10*TC), dimension inputs 1-5, doubled to the 0-10 range
# the rest of the system uses (CAS >= 8 = Immediate).
# CC (1-5) is derived from FDA 21 CFR Part 860 device-class definitions (Class
# III=5, II=3-4, I=1-2) and FDA's 2023 medical-device-cybersecurity guidance
# (risk-based, class-aware scoring) via port/protocol lookup at inference time.
#
# Every table below is DERIVED from ../shared/cas_config.json — the single
# source of truth also used live by app.py and backend/services/caapService.js.
# This module only rescales that shared 1-10 data onto its own 1-5 public
# convention (kept for every existing caller — hospital_scenarios.py, test.py,
# the notebook, this file's own self-test below); it no longer hardcodes its
# own independent copy of any weight/device-profile/AE/TC value.
# Author: R.M.C.B. Rathnayake | IT22061270 | SLIIT Cyber Security
import os
import sys

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)
import cas_config as _cfg  # noqa: E402

# ── DIMENSION WEIGHTS (fractions — same on the 1-5 and 1-10 conventions) ─────
WEIGHTS = dict(_cfg.DEFAULT_WEIGHTS)

# ── DEVICE PROFILES (1-10 shared scale -> this module's 1-5 convention) ─────
DEVICE_PROFILES = {
    key: {**profile, "cc": profile["cc"] / 2.0}
    for key, profile in _cfg.DEVICE_PROFILES.items()
}

# ── ACTIVE EXPLOITATION TABLE ─────────────────────────────────────────────────
AE_TABLE = {label: score / 2.0 for label, score in _cfg.AE_TABLE.items()}

# ── SHIFT → TC SCORE ─────────────────────────────────────────────────────────
TC_TABLE = {shift: score / 2.0 for shift, score in _cfg.TC_TABLE.items()}

# ── DEFAULT PROFILE ───────────────────────────────────────────────────────────
_DEFAULT_PROFILE = {**_cfg.DEFAULT_DEVICE_PROFILE, "cc": _cfg.DEFAULT_DEVICE_PROFILE["cc"] / 2.0}


# ══════════════════════════════════════════════════════════════════════════════
#  LOOKUP FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def lookup_device_profile(dst_port: int, protocol: str = "tcp") -> dict:
    proto = str(protocol).strip().lower()
    key = (int(dst_port), proto)
    if key in DEVICE_PROFILES:
        return DEVICE_PROFILES[key]
    key_any = (int(dst_port), "any")
    if key_any in DEVICE_PROFILES:
        return DEVICE_PROFILES[key_any]
    return _DEFAULT_PROFILE.copy()


def get_cc_score(dst_port: int = None, protocol: str = "tcp",
                 cc_raw: float = None) -> float:
    """
    Derive CC (1–5) from FDA 21 CFR §860.3 device class via port lookup.
    Falls back to normalised dataset column if port unknown.
    """
    if dst_port is not None:
        profile = lookup_device_profile(dst_port, protocol)
        return float(profile["cc"])
    if cc_raw is not None:
        try:
            return round(max(1.0, min(5.0, float(cc_raw) / 2.0)), 2)
        except (TypeError, ValueError):
            pass
    return 2.0


def get_tr_score(confidence: float) -> float:
    if confidence >= 0.95: return 5.0
    if confidence >= 0.85: return 4.0
    if confidence >= 0.70: return 3.0
    if confidence >= 0.50: return 2.0
    return 1.0


def get_ts_score(iso_score: float, is_anomaly: bool, ts_col_val: int = 3) -> float:
    ts_base = min(5, max(1, int(ts_col_val)))
    if is_anomaly:
        if iso_score < -0.25:
            return 5.0
        return float(max(4.0, ts_base))
    return min(3.0, float(ts_base))


def get_ae_score(predicted_label: str) -> float:
    return float(AE_TABLE.get(predicted_label, 1))


def get_tc_score(shift: str = "day") -> float:
    return float(TC_TABLE.get(str(shift).strip().lower(), 2))


def compute_cas(tr, cc, ts, ae, tc) -> float:
    raw = (WEIGHTS["TR"] * tr + WEIGHTS["CC"] * cc +
           WEIGHTS["TS"] * ts + WEIGHTS["AE"] * ae + WEIGHTS["TC"] * tc)
    return round(raw * 2, 2)


def get_action(cas: float, label: str) -> str:
    if label == "Benign":
        return "Monitor"
    if cas >= 8.0:
        return "Immediate"
    if cas >= 5.0:
        return "Investigate"
    return "Monitor"


def score_alert(
    predicted_label: str,
    confidence: float,
    iso_score: float,
    is_anomaly: bool,
    dst_port: int = None,
    protocol: str = "tcp",
    cc_raw: float = None,
    shift: str = "day",
    ts_col_val: int = 3,
) -> dict:
    """
    Full CAS pipeline. CC derived from FDA 21 CFR §860.3 via dst_port lookup.
    No synthetic columns required in the CIC IoMT 2024 dataset.
    """
    profile = lookup_device_profile(dst_port, protocol) if dst_port is not None \
        else _DEFAULT_PROFILE.copy()

    tr  = get_tr_score(confidence)
    cc  = get_cc_score(dst_port, protocol, cc_raw)
    ts  = get_ts_score(iso_score, is_anomaly, ts_col_val)
    ae  = get_ae_score(predicted_label)
    tc  = get_tc_score(shift)
    cas = compute_cas(tr, cc, ts, ae, tc)

    return {
        "TR":          tr,
        "CC":          cc,
        "TS":          ts,
        "AE":          ae,
        "TC":          tc,
        "CAS":         cas,
        "action":      get_action(cas, predicted_label),
        "device_name": profile["device_name"],
        "fda_class":   profile["fda_class"],
        "dept":        profile["dept"],
        "patient_dep": profile["patient_dep"],
    }


# ── SELF-TEST ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 100)
    print("  CAS Engine v2.0 | CAAP SLIIT | IT22061270")
    print("  CC Source: FDA 21 CFR Part 860 §860.3 (05/06/2026) + FDA Cybersecurity Guidance 2023")
    print("=" * 100)

    scenarios = [
        ("DoS_TCP",            0.98, -0.45, True,  4000, "tcp",  "night",   5),
        ("MQTT_Brute_Force",   0.92, -0.28, True,  4034, "tcp",  "night",   5),
        ("ARP_Spoofing",       0.87, -0.32, True,  4001, "tcp",  "night",   4),
        ("DoS_TCP",            0.95, -0.40, True,  4015, "tcp",  "evening", 5),
        ("MQTT_Publish_Flood", 0.90, -0.22, True,  4016, "tcp",  "night",   5),
        ("ARP_Spoofing",       0.88, -0.28, True,  1883, "mqtt", "evening", 4),
        ("MQTT_Publish_Flood", 0.85, -0.20, True,  4002, "tcp",  "day",     4),
        ("Replay",             0.73, -0.08, True,  4006, "tcp",  "night",   4),
        ("Recon",              0.65,  0.05, False, 4038, "tcp",  "evening", 3),
        ("ARP_Spoofing",       0.82, -0.18, True,  4039, "tcp",  "night",   4),
        ("DoS_TCP",            0.91, -0.35, True,  4031, "tcp",  "day",     5),
        ("MQTT_Brute_Force",   0.89, -0.25, True,  4059, "tcp",  "evening", 5),
        ("ARP_Spoofing",       0.86, -0.30, True,  4060, "tcp",  "day",     5),
        ("Recon",              0.65,  0.08, False, 11112,"tcp",  "day",     2),
        ("DoS_TCP",            0.91, -0.35, True,  4010, "tcp",  "day",     3),
        ("Recon",              0.60,  0.10, False, 80,   "tcp",  "day",     1),
        ("Benign",             0.99,  0.22, False, 4054, "tcp",  "day",     1),
    ]

    print(f"\n  {'Label':<25} {'Device':<40} {'Class':>5} {'TR':>4} {'CC':>4} {'TS':>4} {'AE':>4} {'TC':>4}  {'CAS':>6}  Action")
    print("  " + "─" * 110)
    for lbl, conf, iso, anom, port, proto, sh, ts in scenarios:
        r = score_alert(lbl, conf, iso, anom, port, proto, None, sh, ts)
        dev = r["device_name"][:38]
        print(f"  {lbl:<25} {dev:<40} {r['fda_class']:>5} "
              f"{r['TR']:>4.1f} {r['CC']:>4.1f} {r['TS']:>4.1f} "
              f"{r['AE']:>4.1f} {r['TC']:>4.1f}  {r['CAS']:>6.2f}  {r['action']}")

    print(f"\n  Total device profiles: {len(DEVICE_PROFILES)}")
    print(f"  CC Source 1: FDA 21 CFR Part 860 §860.3 (up to date 05/06/2026)")
    print(f"  CC Source 2: FDA Cybersecurity in Medical Devices Guidance (Sept 2023)")
    print()
