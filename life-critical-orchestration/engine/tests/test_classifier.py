"""
Classifier tests.

Verifies that every stub alert from data/sample-alerts/ is classified into
the tier its filename advertises. If these tests pass, the engine's decision
logic is at least minimally correct for the curated demo cases.

Edge-case tests cover:
  - the fail-safe rule (missing criticality_score -> life_critical / 10)
  - the full 9-cell decision matrix (3 criticality bands x 3 CAS bands — v1.2
    merged the old "high" and "extreme" CAS bands into one: Tier 1's
    isolate_host cutoff and the extreme-threat trigger share the same 8.0
    threshold, so there's no longer a "high but not extreme" zone)
  - the engine's "extreme threat" detection (CAS >= 8, category in extreme set,
    or technical_severity == "critical" with no cas_score)
  - v1.1: cvss_score is retired from decision-making entirely — accepted and
    parsed, but never read by the classifier, even when present and extreme
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
        "threat": {"cas_score": 7.0},
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


# ---------- Decision matrix: all 9 cells (3 criticality bands x 3 CAS bands) ----------
# v1.2: CAS_MEDIUM_MAX and EXTREME_CAS_THRESHOLD are both 8.0 (see
# classifier.py) — Tier 1's isolate_host band and the Tier 2/3 extreme trigger
# fire off the exact same cutoff, so a fourth "high but not extreme" sample
# would just duplicate one of the other three rows.

@pytest.mark.parametrize(
    "score, cas, expected_tier, expected_action",
    [
        # non_critical (1-4) x 3 CAS bands
        (2,  2.0, Tier.TIER_1, "log_only"),       # low
        (2,  5.5, Tier.TIER_1, "block_port"),     # medium
        (2,  9.5, Tier.TIER_1, "isolate_host"),   # extreme (CAS-driven)

        # clinical_support (5-7) x 3 CAS bands
        (6,  2.0, Tier.TIER_2, "monitored_mode"),
        (6,  5.5, Tier.TIER_2, "monitored_mode"),
        (6,  9.5, Tier.TIER_3, "await_clinician_approval"),

        # life_critical (8-10) x 3 CAS bands
        (9,  2.0, Tier.TIER_2, "monitored_mode"),
        (9,  5.5, Tier.TIER_2, "monitored_mode"),
        (9,  9.5, Tier.TIER_3, "await_clinician_approval"),
    ],
)
def test_decision_matrix_all_9_cells(score, cas, expected_tier, expected_action):
    """The full 3 x 3 decision matrix from docs/alert-schema.md, driven by CAS."""
    decision = classify(_alert_with(score=score, cas=cas))
    assert decision.tier == expected_tier, (
        f"score={score}, cas={cas}: expected {expected_tier}, "
        f"got {decision.tier}. Rationale: {decision.rationale}"
    )
    assert decision.action == expected_action, (
        f"score={score}, cas={cas}: expected action={expected_action}, "
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
    # CAS in the helper is 7.0 -> not extreme -> Tier 2, not Tier 3
    assert decision.tier == Tier.TIER_2
    assert decision.action == "monitored_mode"


def test_failsafe_then_extreme_threat_yields_tier3():
    """Fail-safe substitutes life_critical; extreme threat then escalates to Tier 3."""
    alert = Alert.model_validate({
        "alert_id": "test-edge-failsafe-extreme",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": {"siem": "test"},
        "threat": {"category": "ransomware", "cas_score": 4.0},
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

def test_extreme_threat_via_category_overrides_low_cas():
    """A ransomware alert on a life-critical asset is Tier 3 even if CAS is low."""
    alert = Alert.model_validate({
        "alert_id": "test-edge-002",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": {"siem": "test"},
        "threat": {"category": "ransomware", "cas_score": 4.0},
        "asset": {"asset_id": "TEST-ASSET-002"},
        "clinical_context": {"criticality_score": 9},
    })
    decision = classify(alert)

    assert decision.tier == Tier.TIER_3
    assert decision.action == "await_clinician_approval"
    assert decision.extreme_threat is True


def test_extreme_threat_via_critical_severity_no_cas():
    """If cas_score is absent and technical_severity == 'critical', treat as extreme."""
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
    alert = _alert_with(score=6, cas=5.0, category="active_exploitation")
    decision = classify(alert)

    assert decision.tier == Tier.TIER_3
    assert decision.extreme_threat is True


# ---------- v1.1: cvss_score is fully retired from decision-making ----------

def test_cvss_score_is_never_read_even_when_extreme():
    """The definitive regression guard for 'replace CVSS entirely with CAS':
    a cvss_score of 10.0 (would have been extreme under the old logic) on a
    protected asset, with no cas_score and no technical_severity, must NOT
    escalate to Tier 3. Only cas_score / technical_severity / category can."""
    alert = _alert_with(score=9, cvss=10.0)
    decision = classify(alert)

    assert decision.extreme_threat is False
    assert decision.tier == Tier.TIER_2
    assert decision.action == "monitored_mode"


def test_cvss_score_ignored_for_tier1_banding_too():
    """Same guard for the Tier 1 CVSS/CAS band selector: a non-critical asset
    with only a high cvss_score (no cas_score, no technical_severity) gets
    the 'no severity signal' cautious default, not a CVSS-derived band."""
    alert = _alert_with(score=2, cvss=9.8)
    decision = classify(alert)

    assert decision.tier == Tier.TIER_1
    assert decision.matched_rule.endswith("no_severity_signal")


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
        "threat": {"cas_score": 6.0, "category": "brute_force"},
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
    decision = classify(_alert_with(score=9, cas=2.0))
    assert decision.extreme_threat is False


def test_extreme_threat_field_true_for_cas_above_threshold():
    decision = classify(_alert_with(score=9, cas=8.5))
    assert decision.extreme_threat is True


def test_proposed_action_is_none_for_tier1():
    decision = classify(_alert_with(score=2, cas=5.5))
    assert decision.tier == Tier.TIER_1
    assert decision.proposed_action_if_approved is None


def test_proposed_action_is_none_for_tier2():
    decision = classify(_alert_with(score=9, cas=6.0))
    assert decision.tier == Tier.TIER_2
    assert decision.proposed_action_if_approved is None


def test_proposed_action_is_isolate_host_for_tier3():
    decision = classify(_alert_with(score=9, cas=9.5))
    assert decision.tier == Tier.TIER_3
    assert decision.proposed_action_if_approved == "isolate_host"


# ---------- Light rationale-text checks ----------
# Cheap insurance against future edits accidentally gutting the rationale.
# These check that key phrases SURVIVE; they don't pin down the exact wording.

def test_tier2_rationale_mentions_monitored_mode_and_telemetry():
    decision = classify(_alert_with(score=9, cas=6.0))
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
    decision = classify(_alert_with(score=9, cas=9.5))
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
    decision = classify(_alert_with(score=2, cas=2.0))
    text = decision.rationale.lower()
    assert "log_only" in text
    assert "non-critical" in text


def test_rationale_never_mentions_cvss():
    """The rationale text must never cite CVSS as a decision basis (v1.1) —
    even when cvss_score is present and would have been extreme under the
    old logic."""
    decision = classify(_alert_with(score=9, cvss=9.9, cas=2.0))
    assert "cvss" not in decision.rationale.lower()


# ---------- F-1.5: detected network indicator flows onto the decision ----------

def _alert_with_indicators(indicators):
    """Minimal life-critical alert carrying the given threat.indicators."""
    return {
        "alert_id": "test-f15",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": {"siem": "wazuh"},
        "threat": {"category": "intrusion_attempt", "cas_score": 7.5,
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


# ---------- cas_score: MediSIEM CAAP integration (v1.1: sole numeric signal) ----------
# cvss_score is retired from decision-making entirely — cas_score is the only
# numeric severity the classifier reads, full stop. It is never combined with,
# nor falls back to, cvss_score; technical_severity is the only fallback for a
# producer that hasn't computed a cas_score at all.

def test_cas_score_drives_extreme_threat_when_present():
    """High CAS escalates protected assets to Tier 3, independent of any
    cvss_score on the same alert.

    CAS is MediSIEM's blended score (folds in TR/AE/TC on top of raw attack
    severity) — the validated signal, not a raw CVSS baseline.
    """
    d = classify(_alert_with(score=9, cvss=2.0, cas=9.5))
    assert d.tier == Tier.TIER_3
    assert d.extreme_threat is True


def test_low_cas_does_not_escalate_even_with_high_cvss():
    """A high cvss_score alongside a low cas_score must NOT escalate — CVSS
    is never read, full stop, regardless of which field carries the higher
    number."""
    d = classify(_alert_with(score=9, cvss=9.8, cas=3.0))
    assert d.tier == Tier.TIER_2
    assert d.extreme_threat is False


def test_cas_score_drives_tier1_banding():
    """Non-critical asset: cas_score picks the Tier 1 action; cvss_score on
    the same alert is not read at all."""
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


def test_no_numeric_score_falls_back_to_technical_severity():
    """With neither cas_score nor cvss_score, technical_severity is the only
    fallback — this is the one remaining fallback path (v1.1)."""
    d = classify(_alert_with(score=9, technical_severity="critical"))
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
