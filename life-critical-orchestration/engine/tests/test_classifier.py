"""
Classifier tests.

Verifies that every stub alert from data/sample-alerts/ is classified into
the tier its filename advertises. If these tests pass, the engine's decision
logic is at least minimally correct for the curated demo cases.

Edge-case tests cover:
  - the fail-safe rule (missing criticality_score -> life_critical / 10)
  - the full 12-cell decision matrix (3 criticality bands x 4 CVSS bands)
  - the engine's "extreme threat" detection (CVSS >= 9, category in extreme set,
    or technical_severity == "critical" with no CVSS)
  - that display-only metadata (patient_dependency, time_sensitivity, shift)
    does NOT influence the engine's decision
  - new v1.0 audit fields on Decision (effective_criticality_score,
    extreme_threat, proposed_action_if_approved)
  - light rationale-text checks (key phrases survive future edits)
"""

from datetime import datetime, timezone
import pytest

from src.models.alert import Alert
from src.models.decision import Tier
from src.decision import classify


# ---------- Bulk tests across the stub dataset ----------

def test_all_tier1_alerts_classify_as_tier1(tier1_alerts):
    for raw in tier1_alerts:
        alert = Alert.model_validate(raw)
        decision = classify(alert)
        assert decision.tier == Tier.TIER_1, (
            f"{alert.alert_id}: expected Tier 1, got {decision.tier}. "
            f"Rationale: {decision.rationale}"
        )
        # Tier 1 has three graduated actions in v1.0
        assert decision.action in ("log_only", "block_port", "isolate_host")


def test_all_tier2_alerts_classify_as_tier2(tier2_alerts):
    for raw in tier2_alerts:
        alert = Alert.model_validate(raw)
        decision = classify(alert)
        assert decision.tier == Tier.TIER_2, (
            f"{alert.alert_id}: expected Tier 2, got {decision.tier}. "
            f"Rationale: {decision.rationale}"
        )
        # F-4 selector: Tier 2 applies throttle when the SIEM flagged a
        # destination, else monitored_mode — both non-disruptive Tier 2 responses.
        assert decision.action in ("monitored_mode", "throttle")
        assert (decision.action == "throttle") == bool(decision.block_dest)


def test_all_tier3_alerts_classify_as_tier3(tier3_alerts):
    for raw in tier3_alerts:
        alert = Alert.model_validate(raw)
        decision = classify(alert)
        assert decision.tier == Tier.TIER_3, (
            f"{alert.alert_id}: expected Tier 3, got {decision.tier}. "
            f"Rationale: {decision.rationale}"
        )
        assert decision.action == "await_clinician_approval"
        # New in v1.0: Tier 3 always proposes isolate_host as the
        # post-approval action.
        assert decision.proposed_action_if_approved == "isolate_host"


def test_every_decision_has_a_rationale_and_matched_rule(all_alerts):
    for tier_num, alerts in all_alerts.items():
        for raw in alerts:
            decision = classify(Alert.model_validate(raw))
            assert decision.rationale, f"{raw['alert_id']}: empty rationale"
            assert decision.matched_rule, f"{raw['alert_id']}: no matched_rule"
            assert decision.alert_id == raw["alert_id"]
            assert decision.asset_id == raw["asset"]["asset_id"]


# ---------- Helpers ----------

def _minimal_alert(**clinical_overrides) -> Alert:
    """Build a minimal valid alert with overridable clinical_context."""
    return Alert.model_validate({
        "alert_id": "test-edge-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": {"siem": "test", "rule_id": "0"},
        "threat": {"cvss_score": 7.0},
        "asset": {"asset_id": "TEST-ASSET-001"},
        "clinical_context": clinical_overrides,
    })


def _alert_with(score=None, cvss=None, category=None, technical_severity=None, cas=None) -> Alert:
    """Build a minimal alert with the specific fields needed by a matrix test."""
    threat = {}
    if cvss is not None:
        threat["cvss_score"] = cvss
    if cas is not None:
        threat["cas_score"] = cas
    if category is not None:
        threat["category"] = category
    if technical_severity is not None:
        threat["technical_severity"] = technical_severity

    clinical = {}
    if score is not None:
        clinical["criticality_score"] = score

    return Alert.model_validate({
        "alert_id": "test-matrix-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": {"siem": "test", "rule_id": "0"},
        "threat": threat,
        "asset": {"asset_id": "TEST-ASSET-MATRIX"},
        "clinical_context": clinical,
    })


# ---------- Decision matrix: all 12 cells (3 bands x 4 CVSS bands) ----------

@pytest.mark.parametrize(
    "score, cvss, expected_tier, expected_action",
    [
        # non_critical (1-4) x 4 CVSS bands
        (2,  2.0, Tier.TIER_1, "log_only"),       # low
        (2,  5.5, Tier.TIER_1, "block_port"),     # medium
        (2,  7.5, Tier.TIER_1, "isolate_host"),   # high
        (2,  9.5, Tier.TIER_1, "isolate_host"),   # extreme (CVSS-driven)

        # clinical_support (5-7) x 4 CVSS bands
        (6,  2.0, Tier.TIER_2, "monitored_mode"),
        (6,  5.5, Tier.TIER_2, "monitored_mode"),
        (6,  7.5, Tier.TIER_2, "monitored_mode"),
        (6,  9.5, Tier.TIER_3, "await_clinician_approval"),

        # life_critical (8-10) x 4 CVSS bands
        (9,  2.0, Tier.TIER_2, "monitored_mode"),
        (9,  5.5, Tier.TIER_2, "monitored_mode"),
        (9,  7.5, Tier.TIER_2, "monitored_mode"),
        (9,  9.5, Tier.TIER_3, "await_clinician_approval"),
    ],
)
def test_decision_matrix_all_12_cells(score, cvss, expected_tier, expected_action):
    """The full 3 x 4 decision matrix from docs/alert-schema.md."""
    decision = classify(_alert_with(score=score, cvss=cvss))
    assert decision.tier == expected_tier, (
        f"score={score}, cvss={cvss}: expected {expected_tier}, "
        f"got {decision.tier}. Rationale: {decision.rationale}"
    )
    assert decision.action == expected_action, (
        f"score={score}, cvss={cvss}: expected action={expected_action}, "
        f"got {decision.action}"
    )


# ---------- Fail-safe rule ----------

def test_failsafe_when_criticality_score_completely_missing():
    """No criticality_score at all -> substitute score=10, band=life_critical."""
    alert = _minimal_alert()  # empty clinical_context
    decision = classify(alert)

    assert decision.fail_safe_applied is True
    assert decision.effective_criticality == "life_critical"
    assert decision.effective_criticality_score == 10  # the substituted value
    # CVSS in the helper is 7.0 -> not extreme -> Tier 2, not Tier 3
    assert decision.tier == Tier.TIER_2
    assert decision.action == "monitored_mode"


def test_failsafe_then_extreme_threat_yields_tier3():
    """Fail-safe substitutes life_critical; extreme threat then escalates to Tier 3."""
    alert = Alert.model_validate({
        "alert_id": "test-edge-failsafe-extreme",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": {"siem": "test"},
        "threat": {"category": "ransomware", "cvss_score": 4.0},
        "asset": {"asset_id": "TEST-ASSET-FAILSAFE"},
        "clinical_context": {},  # no score -> fail-safe
    })
    decision = classify(alert)

    assert decision.fail_safe_applied is True
    assert decision.effective_criticality == "life_critical"
    assert decision.tier == Tier.TIER_3
    assert decision.action == "await_clinician_approval"


# ---------- Score-band derivation ----------

def test_score_8_maps_to_life_critical_band():
    decision = classify(_minimal_alert(criticality_score=8))
    assert decision.fail_safe_applied is False
    assert decision.effective_criticality == "life_critical"
    assert decision.effective_criticality_score == 8


def test_score_5_maps_to_clinical_support_band():
    decision = classify(_minimal_alert(criticality_score=5))
    assert decision.effective_criticality == "clinical_support"
    assert decision.effective_criticality_score == 5


def test_score_4_maps_to_non_critical_band():
    decision = classify(_minimal_alert(criticality_score=4))
    assert decision.effective_criticality == "non_critical"
    assert decision.effective_criticality_score == 4
    assert decision.tier == Tier.TIER_1


# ---------- Extreme-threat detection ----------

def test_extreme_threat_via_category_overrides_low_cvss():
    """A ransomware alert on a life-critical asset is Tier 3 even if CVSS is low."""
    alert = Alert.model_validate({
        "alert_id": "test-edge-002",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": {"siem": "test"},
        "threat": {"category": "ransomware", "cvss_score": 4.0},
        "asset": {"asset_id": "TEST-ASSET-002"},
        "clinical_context": {"criticality_score": 9},
    })
    decision = classify(alert)

    assert decision.tier == Tier.TIER_3
    assert decision.action == "await_clinician_approval"
    assert decision.extreme_threat is True


def test_extreme_threat_via_critical_severity_no_cvss():
    """If CVSS is absent and technical_severity == 'critical', treat as extreme."""
    alert = Alert.model_validate({
        "alert_id": "test-edge-003",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": {"siem": "test"},
        "threat": {"technical_severity": "critical"},
        "asset": {"asset_id": "TEST-ASSET-003"},
        "clinical_context": {"criticality_score": 9},
    })
    decision = classify(alert)

    assert decision.tier == Tier.TIER_3
    assert decision.extreme_threat is True


def test_active_exploitation_category_qualifies_as_extreme():
    """The other extreme category in the set, on a clinical_support asset."""
    alert = _alert_with(score=6, cvss=5.0, category="active_exploitation")
    decision = classify(alert)

    assert decision.tier == Tier.TIER_3
    assert decision.extreme_threat is True


# ---------- Display-only metadata fields don't influence the decision ----------

def test_metadata_fields_do_not_change_decision():
    """patient_dependency, time_sensitivity, shift are display-only.

    Two alerts with identical criticality_score and threat but very different
    metadata must produce the same tier and action.
    """
    base = {
        "alert_id": "test-meta-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": {"siem": "test"},
        "threat": {"cvss_score": 6.0, "category": "brute_force"},
        "asset": {"asset_id": "TEST-ASSET-META"},
    }

    alert_a = Alert.model_validate({
        **base,
        "clinical_context": {
            "criticality_score": 6,
            "patient_dependency": "low",
            "time_sensitivity": 1.0,
            "shift": "day",
        },
    })
    alert_b = Alert.model_validate({
        **base,
        "alert_id": "test-meta-002",
        "clinical_context": {
            "criticality_score": 6,
            "patient_dependency": "life_sustaining",
            "time_sensitivity": 5.0,
            "shift": "night",
        },
    })

    da = classify(alert_a)
    db = classify(alert_b)

    assert da.tier == db.tier
    assert da.action == db.action
    assert da.effective_criticality == db.effective_criticality
    assert da.effective_criticality_score == db.effective_criticality_score
    assert da.extreme_threat == db.extreme_threat


# ---------- New v1.0 audit fields on Decision ----------

def test_extreme_threat_field_false_for_low_severity():
    decision = classify(_alert_with(score=9, cvss=2.0))
    assert decision.extreme_threat is False


def test_extreme_threat_field_true_for_cvss_above_9():
    decision = classify(_alert_with(score=9, cvss=9.5))
    assert decision.extreme_threat is True


def test_proposed_action_is_none_for_tier1():
    decision = classify(_alert_with(score=2, cvss=5.5))
    assert decision.tier == Tier.TIER_1
    assert decision.proposed_action_if_approved is None


def test_proposed_action_is_none_for_tier2():
    decision = classify(_alert_with(score=9, cvss=6.0))
    assert decision.tier == Tier.TIER_2
    assert decision.proposed_action_if_approved is None


def test_proposed_action_is_isolate_host_for_tier3():
    decision = classify(_alert_with(score=9, cvss=9.5))
    assert decision.tier == Tier.TIER_3
    assert decision.proposed_action_if_approved == "isolate_host"


# ---------- Light rationale-text checks ----------
# Cheap insurance against future edits accidentally gutting the rationale.
# These check that key phrases SURVIVE; they don't pin down the exact wording.

def test_tier2_rationale_mentions_monitored_mode_and_telemetry():
    decision = classify(_alert_with(score=9, cvss=6.0))
    text = decision.rationale.lower()
    assert "monitored mode" in text
    assert "deep telemetry" in text


def test_tier3_rationale_mentions_two_phase_flow():
    """Tier 3 rationale must describe both phases of the flow.

    Phase A: Monitored Mode applied immediately, with deep telemetry as part
    of it (Monitored Mode is composite, not just observation).
    Phase B: clinician decides; if approved -> isolate_host; if denied,
    asset stays in Monitored Mode per FR-06.
    """
    decision = classify(_alert_with(score=9, cvss=9.5))
    text = decision.rationale.lower()
    # Phase A — Monitored Mode applied immediately, with its components named
    assert "monitored mode" in text
    assert "deep telemetry" in text
    # Phase B — what gets escalated to if approved, and the denial fallback
    assert "isolate_host" in text
    assert "fr-06" in text or "denied" in text


def test_failsafe_rationale_says_so_loudly():
    decision = classify(_minimal_alert())
    assert "fail-safe applied" in decision.rationale.lower()


def test_tier1_log_only_rationale_explains_why():
    decision = classify(_alert_with(score=2, cvss=2.0))
    text = decision.rationale.lower()
    assert "log_only" in text
    assert "non-critical" in text


# ---------- F-1.5: detected network indicator flows onto the decision ----------

def _alert_with_indicators(indicators):
    """Minimal life-critical alert carrying the given threat.indicators."""
    return {
        "alert_id": "test-f15",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": {"siem": "wazuh"},
        "threat": {"category": "intrusion_attempt", "cvss_score": 7.5,
                   "indicators": indicators},
        "asset": {"asset_id": "ICU-VENT-003", "device_category": "ventilator"},
        "clinical_context": {"criticality_score": 10},
    }


def test_block_target_extracted_from_indicators():
    d = classify(Alert.model_validate(_alert_with_indicators(
        {"dst_ip": "185.220.101.45", "dst_port": 443, "protocol": "TLS"})))
    assert d.block_dest == "185.220.101.45"
    assert d.block_ports == [443]


def test_block_target_absent_when_no_network_indicator():
    d = classify(Alert.model_validate(_alert_with_indicators({"protocol": "TLS"})))
    assert d.block_dest is None
    assert d.block_ports is None


def test_block_target_alternate_field_names():
    # Real integrations vary the field names (dstip / dest_port, port as string).
    d = classify(Alert.model_validate(_alert_with_indicators(
        {"dstip": "203.0.113.9", "dest_port": "8443"})))
    assert d.block_dest == "203.0.113.9"
    assert d.block_ports == [8443]


# ---------- cas_score: MediSIEM CAAP integration ----------
# cas_score is preferred over cvss_score whenever a producer supplies one —
# same 0-10 scale, same "9+ is extreme" / same Tier-1 bands.

def test_cas_score_drives_extreme_threat_when_present():
    """A low CVSS but high CAS still escalates protected assets to Tier 3.

    CAS is MediSIEM's blended score (folds in TR/AE/TC on top of raw attack
    severity) — it's meant to override a stale/low CVSS baseline exactly
    like this.
    """
    d = classify(_alert_with(score=9, cvss=2.0, cas=9.5))
    assert d.tier == Tier.TIER_3
    assert d.extreme_threat is True


def test_low_cas_does_not_escalate_even_with_high_cvss():
    """The inverse: once cas_score is present, it fully replaces cvss_score
    for the numeric severity call — a high CVSS alongside a low CAS does
    NOT escalate (CAS is the validated signal; CVSS is just the baseline
    it was built to beat)."""
    d = classify(_alert_with(score=9, cvss=9.8, cas=3.0))
    assert d.tier == Tier.TIER_2
    assert d.extreme_threat is False


def test_cas_score_drives_tier1_banding():
    """Non-critical asset: cas_score picks the Tier 1 action, not cvss_score."""
    d = classify(_alert_with(score=2, cvss=2.0, cas=8.0))  # cvss alone -> log_only
    assert d.tier == Tier.TIER_1
    assert d.action == "isolate_host"  # cas=8.0 -> high band
    assert "cas" in d.matched_rule


def test_category_override_fires_independently_of_low_cas_score():
    """Keep-the-hard-override decision: ransomware/active_exploitation always
    escalates a protected asset, even when cas_score itself is well under
    the extreme threshold."""
    d = classify(_alert_with(score=9, cas=3.0, category="ransomware"))
    assert d.tier == Tier.TIER_3
    assert d.extreme_threat is True


def test_cvss_fallback_unchanged_when_no_cas_score_supplied():
    """Sanity check: omitting cas_score entirely falls back to the original
    cvss_score-driven behavior byte-for-byte (regression guard for every
    pre-existing test above, expressed as its own explicit case)."""
    d = classify(_alert_with(score=9, cvss=9.5))
    assert d.tier == Tier.TIER_3
    assert d.extreme_threat is True


# ---------- F-4: response-selection layer ----------

def test_f4_tier2_with_dest_selects_throttle():
    """Protected + non-extreme + a SIEM-flagged dest → throttle that flow."""
    d = classify(Alert.model_validate(_alert_with_indicators(
        {"dst_ip": "185.220.101.45", "dst_port": 443})))
    assert d.tier == Tier.TIER_2
    assert d.action == "throttle"
    assert d.block_dest == "185.220.101.45"
    assert d.matched_rule.endswith("throttle_flagged_flow")


def test_f4_tier2_no_dest_selects_monitored_mode():
    """Protected + non-extreme + no actionable dest → monitored_mode only."""
    d = classify(Alert.model_validate(_alert_with_indicators({"protocol": "TLS"})))
    assert d.tier == Tier.TIER_2
    assert d.action == "monitored_mode"
    assert d.block_dest is None


def test_f4_engine_never_auto_selects_drop_or_isolate():
    """selective_block / isolate are escalations, never auto-chosen at Tier 2/3."""
    for indicators in ({"dst_ip": "185.220.101.45"}, {"protocol": "TLS"}):
        d = classify(Alert.model_validate(_alert_with_indicators(indicators)))
        assert d.action not in ("selective_block", "isolate_host")
