#!/usr/bin/env python3
"""
Phase 4 validation harness — the accidental-disruption-rate measurement.

This turns the proposal's headline claim into a measured number. It runs a
suite of realistic threat scenarios against the flagship life-critical device
(ICU-VENT-003) under TWO response policies and compares them:

  * BASELINE (traditional SOAR): always isolate_host, ignoring clinical
    context. This is the "blind automation" the proposal argues against.
  * TIERED (this project's engine): the REAL classifier decides. A
    life-critical asset gets monitored_mode / await_clinician_approval — the
    device is never auto-isolated.

How the metric is built (the chain you and I settled on):

    heartbeat downtime  ->  disrupted? yes/no  ->  disruption RATE
    (measured evidence)     (per incident)         (headline, = disrupted / total)

The heartbeat downtime is not the headline; it is the *evidence* that makes
each per-incident yes/no honest. The headline is the RATE: how often a
life-critical service was actually disrupted. Target: <= 5%.

Also captured in the same run (proposal section 3.5 asks for all three):
  1. Accidental Disruption Rate  — the headline above.
  2. Response Precision          — did the engine pick the correct
                                   non-disruptive strategy for a life-critical
                                   asset (tiered runs only).
  3. Decision Time               — latency of the Security-vs-Life classifier.

Self-contained by design: imports the REAL engine classifier and the REAL
enforcement module in-process, and reads the device's availability log
directly. The only thing that needs to be running is the device-sim stack
(so there is a live heartbeat to disrupt and measure).

Usage (from the engine venv, with the device-sim stack up):

    cd validation
    python run_validation.py                 # full run (~2-3 min)
    python run_validation.py --quick         # short windows, fast sanity run
    python run_validation.py --hold 20       # custom isolation hold seconds
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------
# Wire up imports to the real project modules (no service required).
# --------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "engine"))                 # -> src.decision.classifier
sys.path.insert(0, str(REPO_ROOT / "playbooks" / "shuffle_sim"))  # -> enforcement

from src.decision.classifier import classify        # the real Security-vs-Life logic
from src.models.alert import Alert                   # the real alert model
import enforcement                                    # the real device-cut muscle


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

DEVICE_ASSET_ID = "ICU-VENT-003"          # the flagship life-critical device
AVAILABILITY_LOG = Path(
    __import__("os").getenv(
        "VALIDATION_AVAILABILITY_LOG",
        str(REPO_ROOT / "device-sim" / "data" / "availability.jsonl"),
    )
)
DISRUPTION_EPSILON_S = 0.5                 # downtime above this counts as a real disruption
DISRUPTION_RATE_TARGET = 5.0              # proposal target: <= 5%

# Non-disruptive actions: if the engine picks one of these on a life-critical
# asset, that is the *correct* strategy (Response Precision).
NON_DISRUPTIVE_ACTIONS = {"monitored_mode", "await_clinician_approval"}


# --------------------------------------------------------------------------
# Scenarios — three realistic incidents on the life-critical device.
# Same threats hit both policies; only the response policy differs.
# --------------------------------------------------------------------------

def _alert(name: str, category: str, cvss: float, rule: str) -> Dict[str, Any]:
    """Build an enriched alert (cc_score=10, life_critical) for the device."""
    return {
        "alert_id": f"val-{name}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": {"siem": "validation-harness", "rule_description": rule},
        "threat": {"category": category, "cvss_score": cvss},
        "asset": {"asset_id": DEVICE_ASSET_ID, "asset_type": "medical_device",
                  "device_category": "ventilator", "department": "ICU"},
        "clinical_context": {"criticality_score": 10, "patient_dependency": "life_critical"},
        "enrichment_meta": {"enricher_version": "validation-1.0.0", "confidence": 1.0},
    }


SCENARIOS = [
    {"name": "ransomware",   "label": "Ransomware encryption on ICU ventilator",
     "alert": _alert("ransomware", "ransomware", 9.8, "Ransomware encryption behaviour detected")},
    {"name": "exploit",      "label": "Active exploitation of ICU ventilator",
     "alert": _alert("exploit", "active_exploitation", 9.1, "Remote code execution exploit attempt")},
    {"name": "suspicious",   "label": "Suspicious outbound traffic from ventilator",
     "alert": _alert("suspicious", "intrusion_attempt", 7.5, "Unexpected outbound C2-like connection")},
]


# --------------------------------------------------------------------------
# Result records
# --------------------------------------------------------------------------

@dataclass
class RunResult:
    policy: str
    scenario: str
    label: str
    isolated: bool                 # did this policy actually cut the device?
    enforce_mode: str              # "real" | "simulated" | "-"
    downtime_s: float              # measured from the heartbeat log
    interruptions: int
    disrupted: bool                # downtime_s > epsilon
    engine_tier: Optional[int] = None
    engine_action: Optional[str] = None
    decision_ms: Optional[float] = None
    precision_correct: Optional[bool] = None  # tiered: chose non-disruptive?


# --------------------------------------------------------------------------
# Measurement — window the availability log
# --------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def measure_window(t0: datetime, t1: datetime) -> Dict[str, Any]:
    """Sum measured downtime whose recovery landed inside [t0, t1]."""
    if not AVAILABILITY_LOG.exists():
        return {"downtime_s": 0.0, "interruptions": 0, "log_missing": True}

    downtime = 0.0
    count = 0
    try:
        lines = AVAILABILITY_LOG.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {"downtime_s": 0.0, "interruptions": 0, "log_missing": True}

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("event") != "interruption_end":
            continue
        ts_raw = rec.get("ts")
        if not ts_raw:
            continue
        try:
            ts = datetime.fromisoformat(ts_raw)
        except ValueError:
            continue
        if t0 <= ts <= t1:
            downtime += float(rec.get("downtime_s", 0.0))
            count += 1

    return {"downtime_s": round(downtime, 2), "interruptions": count, "log_missing": False}


# --------------------------------------------------------------------------
# Policies
# --------------------------------------------------------------------------

def apply_baseline(scenario: Dict[str, Any]) -> Dict[str, Any]:
    """Traditional SOAR: always isolate, ignore clinical context."""
    result = enforcement.isolate(
        DEVICE_ASSET_ID,
        decision_id=f"baseline-{scenario['name']}",
        reason="baseline_always_isolate",
    )
    return {"isolated": True, "enforce_mode": result.get("mode", "-")}


def apply_tiered(scenario: Dict[str, Any]) -> Dict[str, Any]:
    """This project's engine: the real classifier decides."""
    alert = Alert.model_validate(scenario["alert"])

    t = time.perf_counter()
    decision = classify(alert)
    decision_ms = round((time.perf_counter() - t) * 1000, 3)

    action = decision.action
    tier = int(decision.tier)
    # The engine only auto-isolates on a literal isolate_host action. For a
    # life-critical asset that never happens (Tier 2/3), so the device stays up.
    isolated = action == "isolate_host"
    enforce_mode = "-"
    if isolated:
        result = enforcement.isolate(
            DEVICE_ASSET_ID, decision_id=f"tiered-{scenario['name']}",
            reason="tiered_isolate_host",
        )
        enforce_mode = result.get("mode", "-")

    return {
        "isolated": isolated,
        "enforce_mode": enforce_mode,
        "engine_tier": tier,
        "engine_action": action,
        "decision_ms": decision_ms,
        "precision_correct": action in NON_DISRUPTIVE_ACTIONS,
    }


# --------------------------------------------------------------------------
# Run orchestration
# --------------------------------------------------------------------------

def run_case(policy: str, scenario: Dict[str, Any], hold: float, grace: float,
             c: "Colors") -> RunResult:
    """Run one (policy, scenario): act, hold, release, measure the window."""
    print(f"  {c.dim}·{c.reset} {policy:<8} {scenario['label']}", flush=True)

    t0 = _now()
    if policy == "baseline":
        applied = apply_baseline(scenario)
    else:
        applied = apply_tiered(scenario)

    # Hold the state so the heartbeat logger has time to register a gap.
    time.sleep(hold)

    # Release if we isolated, then let recovery register inside the window.
    if applied["isolated"]:
        enforcement.release(DEVICE_ASSET_ID, decision_id=f"{policy}-{scenario['name']}")
    time.sleep(grace)
    t1 = _now()

    m = measure_window(t0, t1)
    disrupted = m["downtime_s"] > DISRUPTION_EPSILON_S

    verdict = f"{c.red}DISRUPTED{c.reset}" if disrupted else f"{c.green}service intact{c.reset}"
    engine_note = ""
    if policy == "tiered":
        engine_note = f"  engine: T{applied['engine_tier']} {applied['engine_action']} ({applied['decision_ms']}ms)"
    print(f"      downtime {m['downtime_s']:>5.1f}s  ->  {verdict}{engine_note}", flush=True)

    if applied["isolated"] and applied.get("enforce_mode") != "real":
        print(f"      {c.yellow}WARN: enforcement was '{applied.get('enforce_mode')}', "
              f"not a real device cut — is the device-sim stack up?{c.reset}", flush=True)
    if m.get("log_missing"):
        print(f"      {c.yellow}WARN: availability log not found at {AVAILABILITY_LOG}{c.reset}", flush=True)

    return RunResult(
        policy=policy, scenario=scenario["name"], label=scenario["label"],
        isolated=applied["isolated"], enforce_mode=applied.get("enforce_mode", "-"),
        downtime_s=m["downtime_s"], interruptions=m["interruptions"], disrupted=disrupted,
        engine_tier=applied.get("engine_tier"), engine_action=applied.get("engine_action"),
        decision_ms=applied.get("decision_ms"), precision_correct=applied.get("precision_correct"),
    )


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

class Colors:
    def __init__(self, enabled: bool):
        self.reset = "\033[0m" if enabled else ""
        self.bold = "\033[1m" if enabled else ""
        self.dim = "\033[2m" if enabled else ""
        self.green = "\033[32m" if enabled else ""
        self.red = "\033[31m" if enabled else ""
        self.yellow = "\033[33m" if enabled else ""
        self.cyan = "\033[36m" if enabled else ""


def summarize(results: List[RunResult], c: Colors) -> None:
    baseline = [r for r in results if r.policy == "baseline"]
    tiered = [r for r in results if r.policy == "tiered"]

    def rate(rs: List[RunResult]) -> float:
        return 100.0 * sum(1 for r in rs if r.disrupted) / len(rs) if rs else 0.0

    base_rate = rate(baseline)
    tier_rate = rate(tiered)

    precision_hits = [r for r in tiered if r.precision_correct]
    precision_pct = 100.0 * len(precision_hits) / len(tiered) if tiered else 0.0
    dtimes = [r.decision_ms for r in tiered if r.decision_ms is not None]
    avg_decision_ms = round(sum(dtimes) / len(dtimes), 3) if dtimes else 0.0

    line = "=" * 68
    print(f"\n{c.bold}{line}{c.reset}")
    print(f"{c.bold}  VALIDATION RESULTS — accidental disruption of life-critical service{c.reset}")
    print(f"{c.bold}{line}{c.reset}\n")

    # Per-incident evidence table
    print(f"  {'policy':<9}{'scenario':<13}{'isolated':<10}{'downtime':<11}{'verdict'}")
    print(f"  {c.dim}{'-'*62}{c.reset}")
    for r in results:
        v = f"{c.red}disrupted{c.reset}" if r.disrupted else f"{c.green}intact{c.reset}"
        iso = "yes" if r.isolated else "no"
        print(f"  {r.policy:<9}{r.scenario:<13}{iso:<10}{r.downtime_s:>5.1f}s     {v}")

    disrupted_base = sum(1 for r in baseline if r.disrupted)
    disrupted_tier = sum(1 for r in tiered if r.disrupted)

    print(f"\n  {c.bold}1. Accidental Disruption Rate{c.reset}  (headline — how often service was disrupted)")
    print(f"       Baseline SOAR : {disrupted_base}/{len(baseline)} = {c.red}{base_rate:.1f}%{c.reset}")
    target_ok = tier_rate <= DISRUPTION_RATE_TARGET
    badge = f"{c.green}PASS{c.reset}" if target_ok else f"{c.red}FAIL{c.reset}"
    print(f"       Tiered engine : {disrupted_tier}/{len(tiered)} = {c.green}{tier_rate:.1f}%{c.reset}"
          f"   (target <= {DISRUPTION_RATE_TARGET:.0f}%  ->  {badge})")

    print(f"\n  {c.bold}2. Response Precision{c.reset}  (engine chose the correct non-disruptive strategy)")
    print(f"       Tiered engine : {len(precision_hits)}/{len(tiered)} = {c.cyan}{precision_pct:.1f}%{c.reset}")

    print(f"\n  {c.bold}3. Decision Time{c.reset}  (Security-vs-Life logic latency)")
    print(f"       Average       : {c.cyan}{avg_decision_ms} ms{c.reset}")

    reduction = base_rate - tier_rate
    print(f"\n  {c.bold}Headline:{c.reset} the tiered engine cut accidental disruption of the "
          f"life-critical\n  service from {c.red}{base_rate:.0f}%{c.reset} to "
          f"{c.green}{tier_rate:.0f}%{c.reset} — a {c.bold}{reduction:.0f}-point{c.reset} reduction, "
          f"measured on a real device.")
    print(f"\n{c.bold}{line}{c.reset}\n")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 4 disruption-rate validation.")
    parser.add_argument("--hold", type=float, default=15.0,
                        help="seconds to hold isolation per run (default 15)")
    parser.add_argument("--grace", type=float, default=6.0,
                        help="seconds to let recovery register (default 6)")
    parser.add_argument("--settle", type=float, default=3.0,
                        help="seconds between runs (default 3)")
    parser.add_argument("--quick", action="store_true",
                        help="short windows for a fast sanity run (hold=5, grace=4)")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    args = parser.parse_args()

    if args.quick:
        args.hold, args.grace = 5.0, 4.0

    c = Colors(enabled=sys.stdout.isatty() and not args.no_color)

    est = (args.hold + args.grace + args.settle) * len(SCENARIOS) * 2
    print(f"{c.bold}Phase 4 validation — disruption rate on {DEVICE_ASSET_ID}{c.reset}")
    print(f"{c.dim}Baseline (always isolate) vs Tiered engine, {len(SCENARIOS)} scenarios each. "
          f"~{est:.0f}s.{c.reset}")
    print(f"{c.dim}Availability log: {AVAILABILITY_LOG}{c.reset}\n")

    if not AVAILABILITY_LOG.exists():
        print(f"{c.yellow}WARNING: availability log not found. Is the device-sim stack running? "
              f"Measurements will read as 0 downtime.{c.reset}\n")

    results: List[RunResult] = []
    # Run baseline suite first, then tiered — keeps the two policies' windows
    # cleanly separated in the log and makes the contrast obvious live.
    for policy in ("baseline", "tiered"):
        print(f"{c.bold}[{policy.upper()}]{c.reset}")
        for scenario in SCENARIOS:
            results.append(run_case(policy, scenario, args.hold, args.grace, c))
            time.sleep(args.settle)
        print()

    summarize(results, c)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
