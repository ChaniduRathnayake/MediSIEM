# Wraps check_drift.py for unattended (cron / Windows Task Scheduler / CI) use:
# runs it, reads its exit code, and writes models/retrain_status.json — a
# small persistent status file app.py's /health endpoint surfaces directly,
# so "the model needs retraining" shows up on the running system itself
# instead of living only in a reports/drift_report_<date>.json a human has
# to remember to go open. That's the actual automation gap this closes (see
# thesis roadmap 15.2, "wire check_drift.py's drift_rate output into an
# actual trigger").
#
# This script does NOT retrain anything by itself — by default it only ever
# writes/updates the status flag. Pass --auto-retrain to also invoke
# retrain_pipeline.py when drift is detected; left off by default since
# unattended retraining is a bigger decision (time/compute cost, and it
# changes the deployed model) than unattended status reporting.
#
# Usage:
#   python scheduled_drift_check.py [--input path/to/flows.csv] [--min-rows 20] [--auto-retrain]
#
# To actually schedule this (not done automatically — register only when
# you're ready):
#   Windows Task Scheduler (daily at 03:00):
#     schtasks /create /tn "CAAP Drift Check" /sc daily /st 03:00 ^
#       /tr "\"<path to venv>\Scripts\python.exe\" \"<path to this file>\""
#   cron (daily at 03:00):
#     0 3 * * * /path/to/venv/bin/python /path/to/ai_server/scheduled_drift_check.py

import argparse
import datetime
import json
import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(SCRIPT_DIR, "models")
REPORT_DIR = os.path.join(SCRIPT_DIR, "reports")
STATUS_PATH = os.path.join(MODEL_DIR, "retrain_status.json")

# Mirrors check_drift.py's EXIT_* constants — duplicated rather than imported
# so this script can invoke check_drift.py as a subprocess (its main() calls
# sys.exit() internally on several paths, which would kill an importing
# caller too) while still speaking its exit-code contract by name.
EXIT_OK, EXIT_ERROR, EXIT_DRIFTED, EXIT_INSUFFICIENT_ROWS = 0, 1, 2, 3


def latest_drift_report():
    """Best-effort read of today's drift_report_<date>.json for extra detail
    (drift_rate, drifted_features) in the status file — never fatal if
    missing/unparseable, the exit code alone is already the source of truth."""
    path = os.path.join(REPORT_DIR, f"drift_report_{datetime.date.today().isoformat()}.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def write_status(needs_retrain: bool, reason: str, extra: dict | None = None):
    status = {
        "needs_retrain": needs_retrain,
        "reason": reason,
        "checked_at": datetime.datetime.utcnow().isoformat() + "Z",
    }
    if extra:
        status.update(extra)
    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(STATUS_PATH, "w", encoding="utf-8") as f:
        json.dump(status, f, indent=2)
    print(f"[scheduled_drift_check] wrote {STATUS_PATH}: needs_retrain={needs_retrain} ({reason})")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", default=None, help="Passed through to check_drift.py --input")
    parser.add_argument("--min-rows", type=int, default=None, help="Passed through to check_drift.py --min-rows")
    parser.add_argument("--auto-retrain", action="store_true",
                         help="On drift detection, also invoke retrain_pipeline.py (off by default)")
    args = parser.parse_args()

    cmd = [sys.executable, os.path.join(SCRIPT_DIR, "check_drift.py")]
    if args.input:
        cmd += ["--input", args.input]
    if args.min_rows is not None:
        cmd += ["--min-rows", str(args.min_rows)]

    result = subprocess.run(cmd)
    code = result.returncode
    report = latest_drift_report()

    if code == EXIT_OK:
        write_status(False, "no_drift", {"drift_rate": report.get("drift_rate") if report else None})
    elif code == EXIT_DRIFTED:
        write_status(True, "drift_detected", {
            "drift_rate": report.get("drift_rate") if report else None,
            "drifted_features": report.get("drifted_features") if report else None,
        })
        if args.auto_retrain:
            print("[scheduled_drift_check] --auto-retrain set — invoking retrain_pipeline.py")
            subprocess.run([sys.executable, os.path.join(SCRIPT_DIR, "retrain_pipeline.py")])
    elif code == EXIT_INSUFFICIENT_ROWS:
        # Inconclusive, not a verdict either way — leave any existing status
        # file untouched rather than overwriting a real signal with "unknown".
        print("[scheduled_drift_check] insufficient live rows to trust a drift signal — status file left unchanged")
    else:
        print(f"[scheduled_drift_check] check_drift.py failed to run (exit {code}) — status file left unchanged")

    sys.exit(code)


if __name__ == "__main__":
    main()
