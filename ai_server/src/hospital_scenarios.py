# CAAP vs CVSS-equivalent baseline on 3 simulated hospital alert scenarios.
# REAL: flow feature rows (sampled from held-out data/test/*.csv) and every
# RF/IsolationForest/K-Means prediction + CAS score computed from real trained
# models. SIMULATED: no real hospital dataset exists for this — each row's
# destination port is drawn from cas_engine.DEVICE_PROFILES to stand in for
# "which device this came from". Patient-dependency tier (life_critical/low/
# none) is set at generation time from that port, since cas_engine's own
# patient_dep field is binary and can't distinguish the 3-tier split.
import os
import random
import sys

import numpy as np
import pandas as pd
from scipy.stats import spearmanr

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import cas_config  # noqa: E402
import cas_engine  # noqa: E402
import eval_utils  # noqa: E402

RANDOM_SEED = 42

# ── Group cas_engine's real device profiles by FDA class, once ─────────────────
_PORTS_BY_CLASS = {"I": [], "II": [], "III": []}
for (_port, _proto), _profile in cas_engine.DEVICE_PROFILES.items():
    _PORTS_BY_CLASS.setdefault(_profile["fda_class"], []).append((_port, _proto))


def _sample_port_for_tier(tier: str, rng: random.Random):
    if tier == "life_critical":
        return rng.choice(_PORTS_BY_CLASS["III"])
    if tier == "low":
        pool = _PORTS_BY_CLASS["I"] + _PORTS_BY_CLASS["II"]
        return rng.choice(pool)
    # "none" — a port deliberately absent from DEVICE_PROFILES, so
    # cas_engine.lookup_device_profile() falls through to _DEFAULT_PROFILE.
    while True:
        port = rng.randint(20000, 40000)
        if (port, "tcp") not in cas_engine.DEVICE_PROFILES:
            return (port, "tcp")


# ── CVSS-equivalent baseline ────────────────────────────────────────────────────
# No CVSS field exists anywhere in this dataset, so per the task's own fallback
# instruction this is a simple derived base-severity score: representative
# CVSS v3.1 base-score bands (NVD qualitative severity rating scale) for the
# GENERAL vulnerability class each attack technique corresponds to — not a
# specific CVE. This is the whole point of the comparison: CVSS-style scoring
# is blind to which device/patient context the alert hit; CAS is not.
#   DoS_TCP / MQTT_Publish_Flood : CWE-400 resource exhaustion  -> High  (7.5)
#   MQTT_Brute_Force             : CWE-307 improper auth        -> High  (8.1)
#   ARP_Spoofing                 : CWE-300 MITM/spoofing        -> Medium(6.5)
#   Recon                        : informational/scanning       -> Low   (3.1)
#   Benign                       : n/a                          -> 0.0
# Sourced from cas_config (shared/cas_config.json) rather than kept as a local
# copy, so this offline evaluation and the live dashboard's CAS-vs-CVSS column
# (app.py's lookup_cvss()) can never silently drift apart.
CVSS_BASE_BY_LABEL = cas_config.CVSS_BASE_BY_LABEL


def cvss_equivalent_score(predicted_label: str) -> float:
    return cas_config.lookup_cvss(predicted_label)


# ── Scenario definitions ────────────────────────────────────────────────────────
SCENARIOS = {
    "icu_critical_care": {
        "display_name": "ICU / Critical Care Ward",
        "description": "Device mix dominated by life-sustaining bedside equipment "
                        "(ventilators, infusion pumps, defibrillators, ECMO, dialysis, "
                        "cardiac/SpO2 monitors); traffic skewed toward an active-incident mix.",
        "tier_weights": {"life_critical": 0.50, "low": 0.35, "none": 0.15},
        "attack_fraction": 0.60,
    },
    "general_ward_admin": {
        "display_name": "General Ward / Radiology / Administration",
        "description": "Device mix dominated by imaging, records, and administrative "
                        "systems (DICOM, EHR, RIS/LIS, admin workstations); routine "
                        "day-to-day traffic mix.",
        "tier_weights": {"life_critical": 0.10, "low": 0.70, "none": 0.20},
        "attack_fraction": 0.25,
    },
    "hospital_wide_mixed": {
        "display_name": "Hospital-Wide Mixed Alert Stream",
        "description": "Proportional cross-section of every device class in "
                        "cas_engine.DEVICE_PROFILES, representing a whole-hospital SOC feed.",
        "tier_weights": {"life_critical": 0.25, "low": 0.45, "none": 0.30},
        "attack_fraction": 0.50,
    },
}

N_PER_SCENARIO = 200
SHIFT_CHOICES = ["day", "evening", "night"]


def _sample_traffic_rows(iomt_df: pd.DataFrame, n: int, attack_fraction: float, rng: np.random.Generator) -> pd.DataFrame:
    """Sample n feature rows from the real held-out IoMT test set, mixing
    benign + attack rows in the given proportion, attack categories sampled
    proportionally to their natural representation in the test set."""
    benign_pool = iomt_df[iomt_df["label"] == "Benign"]
    attack_pool = iomt_df[iomt_df["label"] != "Benign"]

    n_attack = int(round(n * attack_fraction))
    n_benign = n - n_attack

    benign_sample = benign_pool.sample(n=min(n_benign, len(benign_pool)), replace=len(benign_pool) < n_benign,
                                        random_state=rng.integers(0, 2**31 - 1))
    attack_sample = attack_pool.sample(n=min(n_attack, len(attack_pool)), replace=len(attack_pool) < n_attack,
                                        random_state=rng.integers(0, 2**31 - 1))
    combined = pd.concat([benign_sample, attack_sample], ignore_index=True)
    return combined.sample(frac=1.0, random_state=rng.integers(0, 2**31 - 1)).reset_index(drop=True)


def build_scenario(scenario_key: str, iomt_df: pd.DataFrame, artifacts: dict, n: int = N_PER_SCENARIO,
                    seed: int = RANDOM_SEED) -> pd.DataFrame:
    """Build one simulated hospital scenario: sample real traffic rows, assign
    simulated device ports per the scenario's tier mix, run the real trained
    RF+IF+KMeans pipeline, score each alert with the real cas_engine.py, and
    compute the CVSS-equivalent baseline score alongside it."""
    cfg = SCENARIOS[scenario_key]
    rng_np = np.random.default_rng(seed)
    rng_py = random.Random(seed)

    rows = _sample_traffic_rows(iomt_df, n, cfg["attack_fraction"], rng_np)

    X_scaled = eval_utils.prepare_features(rows, artifacts["feature_cols"], artifacts["scaler"])
    model_out, _timing = eval_utils.run_full_pipeline(X_scaled, artifacts)

    tiers = rng_py.choices(
        population=list(cfg["tier_weights"].keys()),
        weights=list(cfg["tier_weights"].values()),
        k=len(rows),
    )
    shifts = [rng_py.choice(SHIFT_CHOICES) for _ in range(len(rows))]

    records = []
    for i in range(len(rows)):
        tier = tiers[i]
        port, proto = _sample_port_for_tier(tier, rng_py)
        cas_result = cas_engine.score_alert(
            predicted_label=model_out.loc[i, "predicted_label"],
            confidence=float(model_out.loc[i, "confidence"]),
            iso_score=float(model_out.loc[i, "iso_score"]),
            is_anomaly=bool(model_out.loc[i, "is_anomaly"]),
            dst_port=port,
            protocol=proto,
            shift=shifts[i],
            ts_col_val=3,
        )
        # Scenario-adaptive comparison: same TR/CC/TS/AE/TC dimension values
        # cas_result already computed with the fixed AHP default weights,
        # recombined with this scenario's own weight profile (see
        # cas_config.SCENARIO_WEIGHT_PROFILES) via the sensitivity-analysis
        # helper below (_weighted_cas) — isolates the effect of adaptive
        # WEIGHTING from everything else (device, attack type, shift all
        # identical between CAS and CAS_adaptive for the same row).
        adaptive_weights = cas_config.SCENARIO_WEIGHT_PROFILES.get(scenario_key, cas_config.DEFAULT_WEIGHTS)
        cas_adaptive = _weighted_cas(
            cas_result["TR"], cas_result["CC"], cas_result["TS"], cas_result["AE"], cas_result["TC"],
            adaptive_weights,
        )
        records.append({
            "scenario": scenario_key,
            "true_label": rows.loc[i, "label"],
            "source_file": rows.loc[i, "__source_file"],
            "predicted_label": model_out.loc[i, "predicted_label"],
            "confidence": model_out.loc[i, "confidence"],
            "iso_score": model_out.loc[i, "iso_score"],
            "is_anomaly": model_out.loc[i, "is_anomaly"],
            "cluster": model_out.loc[i, "cluster"],
            "dst_port": port,
            "protocol": proto,
            "shift": shifts[i],
            "patient_dependency": tier,  # ground truth for THIS simulated scenario
            **cas_result,
            "CVSS": cvss_equivalent_score(model_out.loc[i, "predicted_label"]),
            "CAS_adaptive": cas_adaptive,
            "action_adaptive": cas_engine.get_action(cas_adaptive, model_out.loc[i, "predicted_label"]),
        })

    return pd.DataFrame(records)


def build_all_scenarios(iomt_df: pd.DataFrame, artifacts: dict) -> pd.DataFrame:
    frames = [build_scenario(key, iomt_df, artifacts) for key in SCENARIOS]
    return pd.concat(frames, ignore_index=True)


# ── ARA / MTCAI / FPR / Fatigue Reduction ───────────────────────────────────────
def _ranks(df: pd.DataFrame, score_col: str) -> pd.Series:
    """1-indexed rank, descending by score. Ties broken by original row order
    (stable) — CVSS in particular produces many ties (see markdown note in the
    notebook: this is itself part of the finding, not an artifact to hide)."""
    return df[score_col].rank(method="first", ascending=False).astype(int)


def alert_ranking_accuracy(df: pd.DataFrame, score_col: str, n_values=(5, 10, 20)) -> dict:
    ranks = _ranks(df, score_col)
    lc_mask = df["patient_dependency"] == "life_critical"
    total_lc = int(lc_mask.sum())
    return {
        n: (100.0 * int(((ranks <= n) & lc_mask).sum()) / total_lc if total_lc else float("nan"))
        for n in n_values
    }


def mean_time_to_critical(df: pd.DataFrame, score_col: str) -> float:
    ranks = _ranks(df, score_col)
    lc_ranks = ranks[df["patient_dependency"] == "life_critical"]
    return float(lc_ranks.mean()) if len(lc_ranks) else float("nan")


def false_positive_rate_top_n(df: pd.DataFrame, score_col: str, n: int = 10) -> float:
    ranks = _ranks(df, score_col)
    top_n_mask = ranks <= n
    low_risk_mask = df["patient_dependency"].isin(["low", "none"])
    return 100.0 * int((top_n_mask & low_risk_mask).sum()) / n


def build_caap_vs_cvss_table(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for scenario_key in list(SCENARIOS.keys()) + ["__all__"]:
        sub = df if scenario_key == "__all__" else df[df["scenario"] == scenario_key]
        ara_caap = alert_ranking_accuracy(sub, "CAS")
        ara_cvss = alert_ranking_accuracy(sub, "CVSS")
        mtcai_caap = mean_time_to_critical(sub, "CAS")
        mtcai_cvss = mean_time_to_critical(sub, "CVSS")
        fpr_caap = false_positive_rate_top_n(sub, "CAS", 10)
        fpr_cvss = false_positive_rate_top_n(sub, "CVSS", 10)
        fatigue_reduction_pts = fpr_cvss - fpr_caap
        fatigue_reduction_pct = (100.0 * fatigue_reduction_pts / fpr_cvss) if fpr_cvss > 0 else float("nan")

        row = {
            "scenario": "ALL SCENARIOS COMBINED" if scenario_key == "__all__" else SCENARIOS[scenario_key]["display_name"],
            "n_alerts": len(sub),
            "n_life_critical": int((sub["patient_dependency"] == "life_critical").sum()),
        }
        for n in (5, 10, 20):
            row[f"ARA_CAAP_top{n}_%"] = round(ara_caap[n], 2)
            row[f"ARA_CVSS_top{n}_%"] = round(ara_cvss[n], 2)
        row["MTCAI_CAAP_rank"] = round(mtcai_caap, 2)
        row["MTCAI_CVSS_rank"] = round(mtcai_cvss, 2)
        row["FPR_CAAP_top10_%"] = round(fpr_caap, 2)
        row["FPR_CVSS_top10_%"] = round(fpr_cvss, 2)
        row["AlertFatigueReduction_pts"] = round(fatigue_reduction_pts, 2)
        row["AlertFatigueReduction_%"] = round(fatigue_reduction_pct, 2) if not np.isnan(fatigue_reduction_pct) else np.nan
        rows.append(row)
    return pd.DataFrame(rows)


# ── Static AHP weights vs. scenario-adaptive weights ────────────────────────
# A second, independent comparison alongside CAAP-vs-CVSS above: does letting
# the weight VECTOR itself vary by deployment scenario (see
# cas_config.SCENARIO_WEIGHT_PROFILES / resolve_scenario_key) improve
# alert-ranking accuracy over the single fixed AHP-derived default, using the
# exact same TR/CC/TS/AE/TC dimension values for both (built_scenario() already
# computes CAS with the fixed default and CAS_adaptive with this row's own
# scenario profile side by side) — isolates the effect of adaptive weighting
# from every other variable.
def build_static_vs_adaptive_table(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for scenario_key in list(SCENARIOS.keys()) + ["__all__"]:
        sub = df if scenario_key == "__all__" else df[df["scenario"] == scenario_key]
        ara_static = alert_ranking_accuracy(sub, "CAS")
        ara_adaptive = alert_ranking_accuracy(sub, "CAS_adaptive")
        mtcai_static = mean_time_to_critical(sub, "CAS")
        mtcai_adaptive = mean_time_to_critical(sub, "CAS_adaptive")
        fpr_static = false_positive_rate_top_n(sub, "CAS", 10)
        fpr_adaptive = false_positive_rate_top_n(sub, "CAS_adaptive", 10)
        fatigue_reduction_pts = fpr_static - fpr_adaptive
        fatigue_reduction_pct = (100.0 * fatigue_reduction_pts / fpr_static) if fpr_static > 0 else float("nan")

        row = {
            "scenario": "ALL SCENARIOS COMBINED" if scenario_key == "__all__" else SCENARIOS[scenario_key]["display_name"],
            "n_alerts": len(sub),
            "n_life_critical": int((sub["patient_dependency"] == "life_critical").sum()),
        }
        for n in (5, 10, 20):
            row[f"ARA_static_top{n}_%"] = round(ara_static[n], 2)
            row[f"ARA_adaptive_top{n}_%"] = round(ara_adaptive[n], 2)
        row["MTCAI_static_rank"] = round(mtcai_static, 2)
        row["MTCAI_adaptive_rank"] = round(mtcai_adaptive, 2)
        row["FPR_static_top10_%"] = round(fpr_static, 2)
        row["FPR_adaptive_top10_%"] = round(fpr_adaptive, 2)
        row["AdaptiveFatigueReduction_pts"] = round(fatigue_reduction_pts, 2)
        row["AdaptiveFatigueReduction_%"] = round(fatigue_reduction_pct, 2) if not np.isnan(fatigue_reduction_pct) else np.nan
        rows.append(row)
    return pd.DataFrame(rows)


# ── Sensitivity analysis ────────────────────────────────────────────────────────
def _weighted_cas(tr, cc, ts, ae, tc, weights: dict) -> float:
    raw = weights["TR"] * tr + weights["CC"] * cc + weights["TS"] * ts + weights["AE"] * ae + weights["TC"] * tc
    return round(raw * 2, 2)


def sensitivity_analysis(df: pd.DataFrame, delta: float = 0.05) -> pd.DataFrame:
    """Perturb each CAS weight by +-delta (renormalized back to sum=1), recompute
    CAS from each alert's already-computed TR/CC/TS/AE/TC components, and report
    score-shift stability + Spearman rank-order stability vs the baseline CAS."""
    base_weights = dict(cas_engine.WEIGHTS)
    base_cas = df["CAS"].values.astype(float)

    results = []
    for dim in ("TR", "CC", "TS", "AE", "TC"):
        for signed_delta in (+delta, -delta):
            perturbed = dict(base_weights)
            perturbed[dim] = perturbed[dim] + signed_delta
            total = sum(perturbed.values())
            perturbed = {k: v / total for k, v in perturbed.items()}  # renormalize to sum=1

            new_cas = df.apply(
                lambda r: _weighted_cas(r["TR"], r["CC"], r["TS"], r["AE"], r["TC"], perturbed), axis=1
            ).values.astype(float)

            shift = new_cas - base_cas
            corr, _ = spearmanr(base_cas, new_cas)
            results.append({
                "dimension": dim,
                "delta": signed_delta,
                "perturbed_weight": round(perturbed[dim], 4),
                "mean_abs_score_shift": round(float(np.mean(np.abs(shift))), 4),
                "std_score_shift": round(float(np.std(shift)), 4),
                "max_abs_score_shift": round(float(np.max(np.abs(shift))), 4),
                "spearman_rank_corr_vs_baseline": round(float(corr), 4),
            })
    return pd.DataFrame(results)
