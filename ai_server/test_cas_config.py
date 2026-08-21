# Fast, no-model-loading drift guard for the CAS scoring config unification:
# confirms cas_engine.py's 1-5-scale tables are exactly shared/cas_config.json's
# 1-10-scale tables halved (so the offline research engine and the live
# app.py/caapService.js path can never silently diverge again), that every
# seeded weight profile sums to 1.0, and that scenario resolution behaves
# sanely. Plain-assert script (no pytest in ai_server/venv), same convention
# as test.py/test_real_rows.py — run with: python test_cas_config.py
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "src"))

import cas_config  # noqa: E402
import cas_engine  # noqa: E402

_checks = 0
_failed = []


def check(label: str, condition: bool):
    global _checks
    _checks += 1
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {label}")
    if not condition:
        _failed.append(label)


print("=" * 72)
print("  CAS config parity checks (cas_config.json <-> cas_engine.py 1-5 view)")
print("=" * 72)

check("cas_engine.WEIGHTS == cas_config.DEFAULT_WEIGHTS (fractions, unscaled)",
      cas_engine.WEIGHTS == cas_config.DEFAULT_WEIGHTS)

_cc_mismatches = [
    key for key, profile in cas_config.DEVICE_PROFILES.items()
    if abs(cas_engine.DEVICE_PROFILES[key]["cc"] - profile["cc"] / 2.0) > 1e-9
]
check(f"cas_engine.DEVICE_PROFILES cc == cas_config cc / 2 for all {len(cas_config.DEVICE_PROFILES)} entries",
      not _cc_mismatches)
if _cc_mismatches:
    print(f"         mismatches: {_cc_mismatches[:5]}{'...' if len(_cc_mismatches) > 5 else ''}")

_ae_mismatches = [
    label for label, score in cas_config.AE_TABLE.items()
    if abs(cas_engine.AE_TABLE[label] - score / 2.0) > 1e-9
]
check("cas_engine.AE_TABLE == cas_config.AE_TABLE / 2 for every label", not _ae_mismatches)

_tc_mismatches = [
    shift for shift, score in cas_config.TC_TABLE.items()
    if abs(cas_engine.TC_TABLE[shift] - score / 2.0) > 1e-9
]
check("cas_engine.TC_TABLE == cas_config.TC_TABLE / 2 for every shift", not _tc_mismatches)

check("cas_engine's total device-profile count matches cas_config's",
      len(cas_engine.DEVICE_PROFILES) == len(cas_config.DEVICE_PROFILES))

print()
print("=" * 72)
print("  Scenario weight profile checks")
print("=" * 72)

for key, profile in cas_config.SCENARIO_WEIGHT_PROFILES.items():
    total = sum(profile[k] for k in ("TR", "CC", "TS", "AE", "TC"))
    check(f"profile '{key}' sums to 1.00 (got {total:.4f})", abs(total - 1.0) <= 0.001)

check("'default' profile exactly equals the AHP-justified DEFAULT_WEIGHTS",
      cas_config.SCENARIO_WEIGHT_PROFILES["default"] == cas_config.DEFAULT_WEIGHTS)

print()
print("=" * 72)
print("  Scenario resolution checks")
print("=" * 72)

check("resolve_scenario_key('ICU') -> icu_critical_care",
      cas_config.resolve_scenario_key("ICU") == "icu_critical_care")
check("resolve_scenario_key('Administration') -> general_ward_admin",
      cas_config.resolve_scenario_key("Administration") == "general_ward_admin")
check("resolve_scenario_key(compound 'ICU / General Ward') -> icu_critical_care",
      cas_config.resolve_scenario_key("ICU / General Ward") == "icu_critical_care")
check("resolve_scenario_key(unrecognised text) doesn't false-positive on an embedded abbreviation",
      cas_config.resolve_scenario_key("Some New Department") == "hospital_wide_mixed")
check("resolve_scenario_key(None) -> hospital_wide_mixed rather than raising",
      cas_config.resolve_scenario_key(None) == "hospital_wide_mixed")

# Every DEVICE_PROFILES dept string must resolve without raising, whatever
# the result — this catches a crash, not a specific mapping.
_dept_crash = None
for profile in cas_config.DEVICE_PROFILES.values():
    try:
        cas_config.resolve_scenario_key(profile["dept"])
    except Exception as exc:  # pragma: no cover - failure path only
        _dept_crash = (profile["dept"], exc)
        break
check("resolve_scenario_key() never raises for any real DEVICE_PROFILES dept string",
      _dept_crash is None)

print()
print("=" * 72)
print("  Weight resolution + validation checks")
print("=" * 72)

w, src = cas_config.resolve_weights(None, "icu_critical_care")
check("resolve_weights(None, scenario) returns the named profile", src == "icu_critical_care")

valid_vector = {"TR": 0.2, "CC": 0.2, "TS": 0.2, "AE": 0.2, "TC": 0.2}
w, src = cas_config.resolve_weights(valid_vector, None)
check("resolve_weights(valid posted weights, no scenario) labels the source 'custom'", src == "custom")
w, src = cas_config.resolve_weights(valid_vector, "icu_critical_care")
check("resolve_weights(valid posted weights, WITH a scenario) keeps that scenario as the label "
      "(caapService.js always posts both together — the label should say which named profile the "
      "explicit vector represents, not fall back to a generic 'custom')", src == "icu_critical_care")
check("resolve_weights(valid posted weights) uses the posted values, not the named profile's own",
      w == valid_vector)

w, src = cas_config.resolve_weights({"TR": 5, "CC": 5, "TS": 5, "AE": 5, "TC": 5}, "icu_critical_care")
check("resolve_weights(invalid posted weights) falls back to the named scenario safely",
      src == "icu_critical_care" and abs(sum(w.values()) - 1.0) <= 0.001)

print()
print("=" * 72)
if _failed:
    print(f"  RESULT: {len(_failed)} of {_checks} checks FAILED")
    for label in _failed:
        print(f"    - {label}")
    print("=" * 72)
    sys.exit(1)
else:
    print(f"  RESULT: all {_checks} checks passed")
    print("=" * 72)
