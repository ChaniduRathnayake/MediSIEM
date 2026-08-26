# CAS-vs-CVSS scenario regression tests — the executable counterpart of
# CAS_vs_CVSS_Test_Cases.md in this same folder. Every check below calls the
# REAL scoring engine (ai_server/src/cas_engine.score_alert + cas_config.lookup_cvss)
# with concrete inputs, so a future change to shared/cas_config.json or the
# scoring formula that silently breaks one of the report's worked examples
# fails loudly here instead of only being caught when someone re-reads the report.
#
# TC1-TC4 isolate one CAS dimension at a time against a CVSS baseline that (by
# design) never moves, since CVSS has no concept of device, time, or detection
# confidence. TC6/TC7 are correctness guards the other four depend on. TC5
# (aggregate ranking-accuracy/fatigue-reduction table) and TC8 (weight-perturbation
# rank stability) are the batch-level companions — those need real trained model
# artifacts + held-out data, so they stay notebook-driven
# (ai_server/05_evaluation.ipynb) rather than being reproduced here; their output
# artifacts are archived in this same folder.
#
# Plain-assert script, same convention as ai_server/test_cas_config.py (no
# pytest in ai_server/venv). Pure-stdlib — no model artifacts needed.
# Run with: python Extra_Material/Test_Cases/test_cas_vs_cvss_scenarios.py
import os
import sys

# Windows consoles default stdout to the system codepage (cp1252), which can't
# encode the em dashes used throughout this file's print statements — see
# ai_server/test.py's identical guard for the same reason.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_AI_SERVER_SRC = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "..", "ai_server", "src"))
if _AI_SERVER_SRC not in sys.path:
    sys.path.insert(0, _AI_SERVER_SRC)

import cas_config  # noqa: E402
import cas_engine  # noqa: E402

_checks = 0
_failed = []


def check(label: str, condition: bool, detail: str = ""):
    global _checks
    _checks += 1
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {label}")
    if not condition:
        if detail:
            print(f"         {detail}")
        _failed.append(label)


print("=" * 78)
print("  TC1 — Device criticality (CC) sensitivity")
print("  Same attack, same confidence, same time — only the device differs.")
print("=" * 78)

ventilator = cas_engine.score_alert("DoS_TCP", 0.95, -0.40, True, dst_port=4000, protocol="tcp", shift="day", ts_col_val=5)
workstation = cas_engine.score_alert("DoS_TCP", 0.95, -0.40, True, dst_port=4054, protocol="tcp", shift="day", ts_col_val=5)
cvss_dos = cas_config.lookup_cvss("DoS_TCP")

check("CVSS is identical regardless of device (7.5 == 7.5)", cvss_dos == 7.5)
check("CAS(ICU Ventilator, port 4000) == 9.2 -> Immediate",
      ventilator["CAS"] == 9.2 and ventilator["action"] == "Immediate",
      f"got CAS={ventilator['CAS']} action={ventilator['action']}")
check("CAS(Admin Workstation, port 4054) == 6.8 -> Investigate",
      workstation["CAS"] == 6.8 and workstation["action"] == "Investigate",
      f"got CAS={workstation['CAS']} action={workstation['action']}")
check("device criticality alone opens a >= 2.0-point CAS gap that CVSS can't show",
      round(ventilator["CAS"] - workstation["CAS"], 2) >= 2.0)

print()
print("=" * 78)
print("  TC2 — Temporal context (TC) sensitivity")
print("  Same attack, same device — only the shift (day vs night) differs.")
print("=" * 78)

day = cas_engine.score_alert("ARP_Spoofing", 0.90, -0.20, True, dst_port=4002, protocol="tcp", shift="day", ts_col_val=4)
night = cas_engine.score_alert("ARP_Spoofing", 0.90, -0.20, True, dst_port=4002, protocol="tcp", shift="night", ts_col_val=4)
cvss_arp = cas_config.lookup_cvss("ARP_Spoofing")

check("CVSS is identical regardless of shift (6.5 == 6.5)", cvss_arp == 6.5)
check("CAS(day shift) == 7.4 -> Investigate",
      day["CAS"] == 7.4 and day["action"] == "Investigate",
      f"got CAS={day['CAS']} action={day['action']}")
check("CAS(night shift) == 8.2 -> Immediate",
      night["CAS"] == 8.2 and night["action"] == "Immediate",
      f"got CAS={night['CAS']} action={night['action']}")
check("shift alone crosses the Investigate -> Immediate action boundary",
      day["action"] != night["action"])

print()
print("=" * 78)
print("  TC3 — Detection confidence (TR) sensitivity")
print("  Same attack, same device, same time — only model confidence differs.")
print("=" * 78)

high_conf = cas_engine.score_alert("MQTT_Brute_Force", 0.97, -0.30, True, dst_port=1883, protocol="tcp", shift="evening", ts_col_val=3)
low_conf = cas_engine.score_alert("MQTT_Brute_Force", 0.55, -0.30, True, dst_port=1883, protocol="tcp", shift="evening", ts_col_val=3)
cvss_mqtt_bf = cas_config.lookup_cvss("MQTT_Brute_Force")

check("CVSS is identical regardless of detection confidence (8.1 == 8.1)", cvss_mqtt_bf == 8.1)
check("CAS(confidence=0.97) == 8.8 -> Immediate",
      high_conf["CAS"] == 8.8 and high_conf["action"] == "Immediate",
      f"got CAS={high_conf['CAS']} action={high_conf['action']}")
check("CAS(confidence=0.55) == 7.3 -> Investigate",
      low_conf["CAS"] == 7.3 and low_conf["action"] == "Investigate",
      f"got CAS={low_conf['CAS']} action={low_conf['action']}")
check("a barely-above-threshold detection is discounted relative to a near-certain one",
      high_conf["CAS"] > low_conf["CAS"])

print()
print("=" * 78)
print("  TC4 — Alert ranking inversion")
print("  A weaker-CVSS attack on a life-critical device should still outrank a")
print("  stronger-CVSS attack on a low-criticality one, under CAS.")
print("=" * 78)

alert_x = cas_engine.score_alert("Recon", 0.75, 0.05, False, dst_port=4000, protocol="tcp", shift="night", ts_col_val=3)
alert_y = cas_engine.score_alert("DoS_TCP", 0.95, -0.40, True, dst_port=4054, protocol="tcp", shift="day", ts_col_val=3)
cvss_x = cas_config.lookup_cvss("Recon")
cvss_y = cas_config.lookup_cvss("DoS_TCP")

check("CVSS ranks Y (DoS_TCP) above X (Recon): 3.1 < 7.5",
      cvss_x < cvss_y, f"got cvss_x={cvss_x} cvss_y={cvss_y}")
check("CAS ranks X (Recon-on-ventilator) above Y (DoS-on-workstation): 7.4 > 6.8",
      alert_x["CAS"] > alert_y["CAS"],
      f"got CAS_x={alert_x['CAS']} CAS_y={alert_y['CAS']}")
check("this is a genuine rank inversion versus CVSS, not just a smaller gap",
      (cvss_x < cvss_y) and (alert_x["CAS"] > alert_y["CAS"]))

print()
print("=" * 78)
print("  TC6 — Benign convergence (no cry-wolf)")
print("  Benign traffic on the most critical device/time combination must still")
print("  resolve to Monitor, matching CVSS's 0.0 baseline for Benign.")
print("=" * 78)

benign = cas_engine.score_alert("Benign", 0.99, 0.20, False, dst_port=4000, protocol="tcp", shift="night", ts_col_val=1)
cvss_benign = cas_config.lookup_cvss("Benign")

check("CVSS(Benign) == 0.0", cvss_benign == 0.0)
check("action(Benign on ICU Ventilator, worst-case time) == Monitor regardless of numeric CAS",
      benign["action"] == "Monitor", f"got CAS={benign['CAS']} action={benign['action']}")

print()
print("=" * 78)
print("  TC7 — Action-threshold boundary correctness")
print("  Guards the two constants (8.0, 5.0) every test case above relies on.")
print("=" * 78)

check("CAS=8.0  -> Immediate",   cas_engine.get_action(8.0, "DoS_TCP") == "Immediate")
check("CAS=7.99 -> Investigate", cas_engine.get_action(7.99, "DoS_TCP") == "Investigate")
check("CAS=5.0  -> Investigate", cas_engine.get_action(5.0, "DoS_TCP") == "Investigate")
check("CAS=4.99 -> Monitor",     cas_engine.get_action(4.99, "DoS_TCP") == "Monitor")
check("CAS=0.0  -> Monitor",     cas_engine.get_action(0.0, "DoS_TCP") == "Monitor")

print()
print("=" * 78)
if _failed:
    print(f"  RESULT: {len(_failed)} of {_checks} checks FAILED")
    for label in _failed:
        print(f"    - {label}")
    print("=" * 78)
    sys.exit(1)
else:
    print(f"  RESULT: all {_checks} checks passed")
    print("=" * 78)
