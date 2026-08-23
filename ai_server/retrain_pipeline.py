# Scripts the manual "export -> drop CSV into data/train/ -> rerun train.py
# -> eyeball the numbers -> copy models/*.pkl over" loop into one command with
# a validation gate: trains a CANDIDATE model into a staging directory (never
# touches the live models/reports in place), compares its Random Forest test
# accuracy against the currently deployed model's (models/model_meta.json),
# and only promotes the candidate if it doesn't regress beyond
# --max-regression-pct. A blocked candidate's artifacts are left in the
# staging directory for inspection, not deleted. (Thesis roadmap 15.2,
# "automated retrain pipeline ... with a validation gate".)
#
# This does NOT touch data/train/ — point --train-dir/--test-dir at wherever
# your training data already lives (defaults to the real data/train,
# data/test, same as a plain `python train.py`).
#
# Usage:
#   python retrain_pipeline.py [--train-dir data/train] [--test-dir data/test]
#                               [--max-regression-pct 2.0] [--metric test_pct]
#                               [--force]
#
# Exit codes: 0 = promoted, 1 = blocked by the regression gate, 2 = training
# itself failed (train.py's own exit code).

import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Env-var overrides so this can be smoke-tested end to end (including the
# promote() step) against throwaway directories with zero risk to the real
# deployed models — same pattern as train.py's TRAIN_DATA_DIR etc.
LIVE_MODEL_DIR = os.environ.get("LIVE_MODEL_DIR", os.path.join(SCRIPT_DIR, "models"))
LIVE_REPORT_DIR = os.environ.get("LIVE_REPORT_DIR", os.path.join(SCRIPT_DIR, "reports"))
STAGING_MODEL_DIR = os.environ.get("STAGING_MODEL_DIR", os.path.join(SCRIPT_DIR, "models_staging"))
STAGING_REPORT_DIR = os.environ.get("STAGING_REPORT_DIR", os.path.join(SCRIPT_DIR, "reports_staging"))


def load_meta(model_dir: str):
    path = os.path.join(model_dir, "model_meta.json")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_training(train_dir: str, test_dir: str) -> int:
    """Runs the real train.py, writing into the staging dirs via the same
    env-var overrides the CI reproducibility job uses — never the live
    models/reports."""
    if os.path.isdir(STAGING_MODEL_DIR):
        shutil.rmtree(STAGING_MODEL_DIR)
    if os.path.isdir(STAGING_REPORT_DIR):
        shutil.rmtree(STAGING_REPORT_DIR)

    env = os.environ.copy()
    env["TRAIN_DATA_DIR"] = train_dir
    env["TEST_DATA_DIR"] = test_dir
    env["MODEL_OUT_DIR"] = STAGING_MODEL_DIR
    env["REPORT_OUT_DIR"] = STAGING_REPORT_DIR

    print(f"[retrain_pipeline] Training candidate: {train_dir} / {test_dir} -> {STAGING_MODEL_DIR}")
    result = subprocess.run([sys.executable, os.path.join(SCRIPT_DIR, "train.py")], env=env)
    return result.returncode


def promote():
    """Backs up the current live models/reports (if any), then moves staging
    into their place. Backup lets a bad promotion be rolled back by hand."""
    if os.path.isdir(LIVE_MODEL_DIR):
        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        backup_dir = os.path.join(SCRIPT_DIR, f"models_backup_{ts}")
        shutil.move(LIVE_MODEL_DIR, backup_dir)
        print(f"[retrain_pipeline] Backed up previous models/ -> {os.path.basename(backup_dir)}/")
    if os.path.isdir(LIVE_REPORT_DIR):
        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        backup_dir = os.path.join(SCRIPT_DIR, f"reports_backup_{ts}")
        shutil.move(LIVE_REPORT_DIR, backup_dir)

    shutil.move(STAGING_MODEL_DIR, LIVE_MODEL_DIR)
    shutil.move(STAGING_REPORT_DIR, LIVE_REPORT_DIR)
    print(f"[retrain_pipeline] Promoted candidate -> {LIVE_MODEL_DIR}/")
    print("[retrain_pipeline] Restart the Flask AI server (ai_server/src/app.py) to pick up the new models.")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--train-dir", default=os.path.join(SCRIPT_DIR, "data", "train"))
    parser.add_argument("--test-dir", default=os.path.join(SCRIPT_DIR, "data", "test"))
    parser.add_argument("--metric", default="test_pct", choices=["test_pct", "overall_pct", "train_pct"],
                         help="Which random_forest metric in model_meta.json to gate on (default: test_pct — held-out accuracy, the honest one)")
    parser.add_argument("--max-regression-pct", type=float, default=2.0,
                         help="Candidate may score up to this many percentage points BELOW the live model before being blocked (default: 2.0)")
    parser.add_argument("--force", action="store_true", help="Promote even if the regression gate would otherwise block it")
    args = parser.parse_args()

    code = run_training(args.train_dir, args.test_dir)
    if code != 0:
        print(f"[retrain_pipeline] train.py failed (exit {code}) — nothing to promote, live models/ untouched.")
        sys.exit(2)

    candidate_meta = load_meta(STAGING_MODEL_DIR)
    if candidate_meta is None:
        print("[retrain_pipeline] train.py exited 0 but no model_meta.json was produced — refusing to promote.")
        sys.exit(2)
    candidate_score = candidate_meta["models"]["random_forest"][args.metric]

    live_meta = load_meta(LIVE_MODEL_DIR)
    if live_meta is None:
        print(f"[retrain_pipeline] No currently deployed model_meta.json — nothing to regress against, promoting candidate ({args.metric}={candidate_score:.2f}%).")
        promote()
        sys.exit(0)

    live_score = live_meta["models"]["random_forest"][args.metric]
    delta = candidate_score - live_score
    print(f"[retrain_pipeline] Live RF {args.metric}: {live_score:.2f}%   Candidate RF {args.metric}: {candidate_score:.2f}%   Delta: {delta:+.2f}pp")

    if delta < -args.max_regression_pct and not args.force:
        print(f"[retrain_pipeline] BLOCKED — candidate regresses by {-delta:.2f}pp, exceeding --max-regression-pct={args.max_regression_pct}.")
        print(f"[retrain_pipeline] Candidate artifacts left in place for inspection: {STAGING_MODEL_DIR}/, {STAGING_REPORT_DIR}/")
        print("[retrain_pipeline] Re-run with --force to promote anyway, once you've reviewed why.")
        sys.exit(1)

    if delta < -args.max_regression_pct and args.force:
        print("[retrain_pipeline] --force set — promoting despite the regression.")
    promote()
    sys.exit(0)


if __name__ == "__main__":
    main()
