# Compares recently captured live flow features against the training-set
# baseline saved by train.py (models/model_meta.json). Run ad hoc when
# detection quality looks off — doesn't retrain or block the pipeline, just
# writes reports/drift_report_<date>.json. Uses saved mean/std only (no
# access to the full training set), so out_of_range_fraction is a cheap
# distribution-shape signal, not a real PSI.
# Usage: python check_drift.py [--input path/to/flows.csv] [--min-rows 20]

import argparse
import datetime
import json
import os
import sys

import numpy as np
import pandas as pd

# Windows consoles default stdout to the system codepage (cp1252), which
# can't encode the ✓/✗/⚠/✅ markers this script prints — crashes on a stock
# Windows shell (this project's primary platform) instead of just displaying
# oddly.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(SCRIPT_DIR, "models")
REPORT_DIR = os.path.join(SCRIPT_DIR, "reports")
DEFAULT_INPUT = os.path.join(SCRIPT_DIR, "..", "ml-pipeline", "cicflowmeter_output", "live_flows.csv")

# A live batch mean this many training-stdevs away from the training mean
# is flagged — 3 sigma is the conventional "this isn't just noise" cutoff.
Z_THRESHOLD = 3.0
# A feature is also flagged if this share of live rows individually falls
# outside training mean +/- 3*std, independent of where the batch mean sits
# (catches a bimodal/heavy-tailed shift a mean-only z-score can miss).
OUT_OF_RANGE_THRESHOLD = 0.20
# Share of features that must be individually flagged before the *run* counts
# as drifted overall — also gates the exit code (see EXIT CODES below), so a
# scheduler/cron job can act on this without parsing the JSON report itself.
DRIFT_RATE_THRESHOLD = 0.20

# EXIT CODES (for scheduled_drift_check.py / cron / Task Scheduler / CI use):
#   0 = ran successfully, drift_rate below DRIFT_RATE_THRESHOLD
#   1 = couldn't run at all (no baseline / no input CSV — see load_baseline())
#   2 = ran successfully, drift_rate AT/ABOVE DRIFT_RATE_THRESHOLD
#   3 = ran, but too few live rows to trust a drift signal (inconclusive)
EXIT_OK, EXIT_ERROR, EXIT_DRIFTED, EXIT_INSUFFICIENT_ROWS = 0, 1, 2, 3


def load_baseline():
    meta_path = os.path.join(MODEL_DIR, "model_meta.json")
    if not os.path.exists(meta_path):
        sys.exit(
            f"\n  ✗ {meta_path} not found.\n"
            f"  → Run train.py first — Step 9b saves the per-feature mean/std baseline\n"
            f"    this script compares live traffic against.\n"
        )
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    stats = meta.get("feature_stats")
    if not stats:
        sys.exit(f"\n  ✗ {meta_path} has no 'feature_stats' — retrain with the current train.py to regenerate it.\n")
    return meta, stats


def load_live_batch(input_path: str, feature_columns: list[str]) -> pd.DataFrame:
    if not os.path.exists(input_path):
        sys.exit(
            f"\n  ✗ No captured-flow CSV found at: {os.path.abspath(input_path)}\n"
            f"  → Run 'ml-pipeline/live_feature_extractor.py' (or point --input at a\n"
            f"    different captured-flow CSV, e.g. from replay_test_flows.py) first.\n"
        )
    df = pd.read_csv(input_path, low_memory=False)
    df.columns = df.columns.str.strip()
    present = [c for c in feature_columns if c in df.columns]
    missing = [c for c in feature_columns if c not in df.columns]
    if missing:
        print(f"  ⚠  {len(missing)} baseline feature column(s) not present in the input CSV, skipped: {missing[:10]}{'...' if len(missing) > 10 else ''}")
    for col in present:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    return df[present].dropna(how="all")


def z_score(live_mean: float, train_mean: float, train_std: float) -> float:
    """How many training-set standard deviations the live batch's mean sits
    from the training mean. A large |z| means the live traffic's *typical*
    value for this feature has shifted, even if individual rows still look
    plausible — the classic "average moved" drift signal."""
    std = train_std if train_std > 1e-9 else 1e-9
    return (live_mean - train_mean) / std


def out_of_range_fraction(live_values: pd.Series, train_mean: float, train_std: float) -> float:
    """Share of live rows individually farther than 3 training-stdevs from
    the training mean — catches a shift in spread/shape (e.g. a new bimodal
    cluster of outliers) that a mean-only z-score can average away."""
    std = train_std if train_std > 1e-9 else 1e-9
    lower, upper = train_mean - 3 * std, train_mean + 3 * std
    if len(live_values) == 0:
        return 0.0
    return float(((live_values < lower) | (live_values > upper)).mean())


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Captured-flow CSV to check (default: ml-pipeline/cicflowmeter_output/live_flows.csv)")
    parser.add_argument("--min-rows", type=int, default=20, help="Minimum live rows required before computing drift (fewer = too noisy to trust)")
    args = parser.parse_args()

    print("\n" + "=" * 68)
    print("  CAAP IoMT IDS — DRIFT CHECK")
    print("=" * 68)

    meta, feature_stats = load_baseline()
    feature_columns = meta.get("feature_columns", list(feature_stats.keys()))
    print(f"  Baseline trained_at        : {meta.get('trained_at', 'unknown')}")
    print(f"  Baseline feature columns   : {len(feature_columns)}")

    live_df = load_live_batch(args.input, feature_columns)
    print(f"  Input file                 : {os.path.abspath(args.input)}")
    print(f"  Live rows loaded           : {len(live_df):,}")

    if len(live_df) < args.min_rows:
        print(f"\n  ⚠  Only {len(live_df)} usable live row(s), below --min-rows={args.min_rows} — "
              f"too few to trust a drift signal. Capture more traffic and re-run.")
        report = {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "input_file": os.path.abspath(args.input),
            "input_rows": int(len(live_df)),
            "baseline_trained_at": meta.get("trained_at"),
            "status": "insufficient_rows",
            "min_rows_required": args.min_rows,
        }
        os.makedirs(REPORT_DIR, exist_ok=True)
        report_path = os.path.join(REPORT_DIR, f"drift_report_{datetime.date.today().isoformat()}.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\n  ✓ Saved → {report_path}\n")
        sys.exit(EXIT_INSUFFICIENT_ROWS)
    else:
        print(f"\n  {'Feature':<20} {'Train mean':>12} {'Live mean':>12} {'Z-score':>9} {'Out-of-range':>13}  {'Status'}")
        print("  " + "-" * 88)

        features_report = {}
        drifted = []
        for col in feature_columns:
            if col not in live_df.columns or col not in feature_stats:
                continue
            train_mean = feature_stats[col]["mean"]
            train_std = feature_stats[col]["std"]
            live_values = live_df[col].dropna()
            if len(live_values) == 0:
                continue
            live_mean = float(live_values.mean())
            live_std = float(live_values.std()) if len(live_values) > 1 else 0.0
            z = z_score(live_mean, train_mean, train_std)
            oor = out_of_range_fraction(live_values, train_mean, train_std)
            is_drifted = abs(z) >= Z_THRESHOLD or oor >= OUT_OF_RANGE_THRESHOLD
            if is_drifted:
                drifted.append(col)

            features_report[col] = {
                "train_mean": train_mean,
                "train_std": train_std,
                "live_mean": live_mean,
                "live_std": live_std,
                "z_score": round(z, 3),
                "out_of_range_fraction": round(oor, 3),
                "drifted": is_drifted,
            }

            status = "⚠️  DRIFTED" if is_drifted else "✅"
            print(f"  {col:<20} {train_mean:>12.3f} {live_mean:>12.3f} {z:>9.2f} {oor:>12.1%}  {status}")

        drift_rate = len(drifted) / len(features_report) if features_report else 0.0
        print("\n" + "=" * 68)
        print(f"  {len(drifted)} / {len(features_report)} feature(s) flagged as drifted ({drift_rate:.1%})")
        if drift_rate >= DRIFT_RATE_THRESHOLD:
            print("  ⚠️  20%+ of features drifted — consider retraining with recent captured traffic")
            print("     appended to data/train/ (see GET /api/alerts/training-feedback-export for")
            print("     analyst-confirmed labels), or re-examine whether live_feature_extractor.py's")
            print("     capture window/interface still matches how the model was trained.")
        else:
            print("  ✅  No widespread drift detected.")
        print("=" * 68)

        report = {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "input_file": os.path.abspath(args.input),
            "input_rows": int(len(live_df)),
            "baseline_trained_at": meta.get("trained_at"),
            "status": "ok",
            "z_threshold": Z_THRESHOLD,
            "out_of_range_threshold": OUT_OF_RANGE_THRESHOLD,
            "drift_rate": round(drift_rate, 4),
            "drifted_features": drifted,
            "features": features_report,
        }

    os.makedirs(REPORT_DIR, exist_ok=True)
    report_path = os.path.join(REPORT_DIR, f"drift_report_{datetime.date.today().isoformat()}.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n  ✓ Saved → {report_path}\n")
    sys.exit(EXIT_DRIFTED if drift_rate >= DRIFT_RATE_THRESHOLD else EXIT_OK)


if __name__ == "__main__":
    main()
