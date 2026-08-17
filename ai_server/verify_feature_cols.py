# Fast pass/fail check for feature-column alignment: to_feature_frame() in
# src/app.py silently zero-fills any column a live capture tool doesn't
# produce instead of erroring, quietly degrading predictions. Run this before
# a demo, not after predictions look wrong.
# Usage: python verify_feature_cols.py [--against path/to/live_capture_output.csv | "col1,col2,..."]
# Exit code: 0 if every trained column is present in --against (or if omitted), 1 otherwise.

import argparse
import csv
import os
import sys

import joblib

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FEATURE_COLS_PATH = os.path.join(SCRIPT_DIR, "models", "feature_cols.pkl")


def load_trained_columns():
    if not os.path.exists(FEATURE_COLS_PATH):
        print(f"[FAIL] {FEATURE_COLS_PATH} not found.")
        sys.exit(1)
    cols = joblib.load(FEATURE_COLS_PATH)
    return list(cols)


def load_candidate_columns(against: str):
    """--against is either a path to a CSV (read its header row) or a
    literal comma-separated column list."""
    if os.path.exists(against):
        with open(against, newline="", encoding="utf-8-sig") as f:
            header = next(csv.reader(f))
        return [h.strip() for h in header]
    return [c.strip() for c in against.split(",")]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--against", help="CSV file (its header row) or comma-separated column list to diff against")
    args = parser.parse_args()

    trained = load_trained_columns()
    print(f"[verify_feature_cols] {len(trained)} trained columns (from feature_cols.pkl):")
    for c in trained:
        print(f"  - {c!r}")

    if not args.against:
        print("\nNo --against given -- informational mode only. Pass a live capture CSV/header to diff.")
        sys.exit(0)

    candidate = load_candidate_columns(args.against)
    candidate_set = set(candidate)
    trained_set = set(trained)

    matched = [c for c in trained if c in candidate_set]
    missing = [c for c in trained if c not in candidate_set]
    extra = [c for c in candidate if c not in trained_set]

    print(f"\n[verify_feature_cols] Comparing against: {args.against}")
    print(f"  Matched:  {len(matched)}/{len(trained)}")
    print(f"  Missing (will be zero-filled -- silently wrong predictions): {len(missing)}")
    for c in missing:
        print(f"    x {c!r}")
    if extra:
        print(f"  Extra (present in source, unused by the model): {len(extra)}")
        for c in extra:
            print(f"    - {c!r}")

    if missing:
        pct = 100 * len(missing) / len(trained)
        print(
            f"\n[FAIL] {len(missing)}/{len(trained)} ({pct:.0f}%) trained columns are missing from this source. "
            "Do NOT trust predictions fed from it -- every missing column becomes 0.0, not a real value."
        )
        sys.exit(1)

    print("\n[PASS] Every trained column is present in this source.")
    sys.exit(0)


if __name__ == "__main__":
    main()
