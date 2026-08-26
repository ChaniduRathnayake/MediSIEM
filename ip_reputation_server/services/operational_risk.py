from typing import Any, Dict, List, Optional


# =========================================================
# MEDSHIELD OPERATIONAL RISK ENGINE
# =========================================================
#
# Operational Risk is kept separate from:
#
# 1. External Reputation Risk
# 2. Local ML / Context Risk
# 3. Wazuh / Suricata SIEM Evidence
# 4. Internal Analyst Lists
# 5. Analyst Verdict
#
# These are provisional transparent policy rules and should
# later be experimentally evaluated/calibrated.
# =========================================================


RISK_ORDER = {
    "Unknown": -1,
    "Minimal": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}


def _normalize_risk(
    value: Optional[str],
) -> str:

    if not value:
        return "Unknown"

    mapping = {
        "unknown": "Unknown",
        "minimal": "Minimal",
        "low": "Low",
        "medium": "Medium",
        "high": "High",
        "critical": "Critical",
    }

    return mapping.get(
        str(value).strip().lower(),
        "Unknown",
    )


def _max_risk(
    first: str,
    second: str,
) -> str:

    if (
        RISK_ORDER.get(second, -1)
        > RISK_ORDER.get(first, -1)
    ):
        return second

    return first


def _raise_one_level(
    risk: str,
) -> str:

    sequence = [
        "Minimal",
        "Low",
        "Medium",
        "High",
        "Critical",
    ]

    if risk not in sequence:
        return risk

    index = sequence.index(risk)

    return sequence[
        min(
            index + 1,
            len(sequence) - 1,
        )
    ]


# =========================================================
# LOCAL ML / CONTEXT RISK
# =========================================================


def _local_risk(
    correlation: Optional[Dict[str, Any]],
) -> str:

    if not correlation:
        return "Unknown"

    if not correlation.get("available"):
        return "Unknown"

    if correlation.get(
        "matched_event_count",
        0,
    ) <= 0:
        return "Unknown"

    result = "Minimal"

    summary = (
        correlation.get("summary")
        or {}
    )

    result = _max_risk(
        result,
        _normalize_risk(
            summary.get(
                "latest_context_risk_level"
            )
        ),
    )

    result = _max_risk(
        result,
        _normalize_risk(
            summary.get(
                "latest_operational_priority"
            )
        ),
    )

    for event in (
        correlation.get("events")
        or []
    ):

        result = _max_risk(
            result,
            _normalize_risk(
                event.get(
                    "context_risk_level"
                )
            ),
        )

        result = _max_risk(
            result,
            _normalize_risk(
                event.get(
                    "risk_level"
                )
            ),
        )

        result = _max_risk(
            result,
            _normalize_risk(
                event.get(
                    "operational_priority"
                )
            ),
        )

    return result


# =========================================================
# WAZUH / SURICATA RISK
# =========================================================


def _wazuh_rule_level_to_risk(
    level: Optional[int],
) -> str:

    try:
        value = int(level)
    except (TypeError, ValueError):
        return "Unknown"

    if value >= 12:
        return "Critical"

    if value >= 8:
        return "High"

    if value >= 5:
        return "Medium"

    if value >= 1:
        return "Low"

    return "Unknown"


def _suricata_severity_to_risk(
    severity: Any,
) -> str:

    try:
        value = int(severity)
    except (TypeError, ValueError):
        return "Unknown"

    # Suricata severity:
    # 1 = highest
    # 2 = medium
    # 3 = lowest
    if value == 1:
        return "High"

    if value == 2:
        return "Medium"

    if value == 3:
        return "Low"

    return "Unknown"


def _wazuh_risk(
    wazuh_evidence: Optional[Dict[str, Any]],
) -> str:

    if not wazuh_evidence:
        return "Unknown"

    if not wazuh_evidence.get(
        "available"
    ):
        return "Unknown"

    if wazuh_evidence.get(
        "matched_alert_count",
        0,
    ) <= 0:
        return "Unknown"

    result = _wazuh_rule_level_to_risk(
        wazuh_evidence.get(
            "highest_rule_level"
        )
    )

    for alert in (
        wazuh_evidence.get("alerts")
        or []
    ):

        wazuh_rule = (
            alert.get("wazuh_rule")
            or {}
        )

        result = _max_risk(
            result,
            _wazuh_rule_level_to_risk(
                wazuh_rule.get("level")
            ),
        )

        suricata_alert = (
            alert.get("suricata_alert")
            or {}
        )

        result = _max_risk(
            result,
            _suricata_severity_to_risk(
                suricata_alert.get(
                    "severity"
                )
            ),
        )

    return result


# =========================================================
# MAIN OPERATIONAL RISK ENGINE
# =========================================================


def evaluate_operational_risk(
    external_risk: Optional[str],
    local_correlation: Optional[Dict[str, Any]],
    wazuh_evidence: Optional[Dict[str, Any]],
    internal_intelligence: Optional[Dict[str, Any]],
    analyst_intelligence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    reasons: List[str] = []

    external_level = _normalize_risk(
        external_risk
    )

    local_level = _local_risk(
        local_correlation
    )

    wazuh_level = _wazuh_risk(
        wazuh_evidence
    )

    final_risk = "Minimal"


    # -----------------------------------------------------
    # External reputation
    # -----------------------------------------------------

    if external_level != "Unknown":

        final_risk = _max_risk(
            final_risk,
            external_level,
        )

        reasons.append(
            f"External reputation risk is "
            f"{external_level}."
        )


    # -----------------------------------------------------
    # Local ML / context
    # -----------------------------------------------------

    local_evidence_found = bool(
        local_correlation
        and local_correlation.get(
            "available"
        )
        and local_correlation.get(
            "matched_event_count",
            0,
        ) > 0
    )

    if local_evidence_found:

        final_risk = _max_risk(
            final_risk,
            local_level,
        )

        reasons.append(
            "Local MedShield ML/context evidence "
            f"reached {local_level} risk."
        )

    else:

        reasons.append(
            "No matching local ML/context evidence "
            "was available for this IP."
        )


    # -----------------------------------------------------
    # Wazuh / Suricata SIEM evidence
    # -----------------------------------------------------

    wazuh_evidence_found = bool(
        wazuh_evidence
        and wazuh_evidence.get(
            "available"
        )
        and wazuh_evidence.get(
            "matched_alert_count",
            0,
        ) > 0
    )

    if wazuh_evidence_found:

        final_risk = _max_risk(
            final_risk,
            wazuh_level,
        )

        matched = wazuh_evidence.get(
            "matched_alert_count",
            0,
        )

        suricata_count = (
            wazuh_evidence.get(
                "suricata_alert_count",
                0,
            )
        )

        highest_rule = (
            wazuh_evidence.get(
                "highest_rule_level"
            )
        )

        reasons.append(
            "Wazuh correlation found "
            f"{matched} matching alert(s), "
            f"including {suricata_count} "
            "Suricata alert(s). "
            f"The strongest SIEM evidence maps "
            f"to {wazuh_level} operational risk "
            f"(highest Wazuh rule level: "
            f"{highest_rule})."
        )

        reasons.append(
            "Alert quantity alone does not increase "
            "the Wazuh risk classification; severity "
            "and rule level determine this dimension."
        )

    else:

        reasons.append(
            "No matching Wazuh/Suricata alert "
            "evidence was available for this IP."
        )


    # -----------------------------------------------------
    # Internal intelligence
    # -----------------------------------------------------

    internal_status = "none"

    if internal_intelligence:

        internal_status = (
            internal_intelligence.get(
                "effective_status"
            )
            or "none"
        ).lower()


    if internal_status == "watch":

        final_risk = _max_risk(
            final_risk,
            "Medium",
        )

        reasons.append(
            "Internal watchlist membership imposes "
            "a minimum Medium operational risk."
        )

    elif internal_status == "block":

        final_risk = _max_risk(
            final_risk,
            "High",
        )

        reasons.append(
            "Internal blocklist membership imposes "
            "a minimum High operational risk."
        )

    elif internal_status == "conflict":

        final_risk = _max_risk(
            final_risk,
            "High",
        )

        reasons.append(
            "Conflicting internal intelligence "
            "requires manual analyst review and "
            "imposes a minimum High operational risk."
        )

    elif internal_status == "allow":

        reasons.append(
            "The IP is internally allowlisted. "
            "This does not suppress external, ML, "
            "or SIEM security evidence."
        )


    # -----------------------------------------------------
    # Analyst verdict
    # -----------------------------------------------------

    analyst_verdict = None

    if analyst_intelligence:

        current = (
            analyst_intelligence.get(
                "current_verdict"
            )
            or {}
        )

        analyst_verdict = current.get(
            "verdict"
        )

    if analyst_verdict:

        analyst_verdict = (
            analyst_verdict
            .strip()
            .lower()
        )


    if analyst_verdict == "malicious":

        final_risk = _max_risk(
            final_risk,
            "High",
        )

        reasons.append(
            "The current analyst verdict is "
            "malicious, imposing a minimum High "
            "operational risk."
        )

    elif analyst_verdict == "suspicious":

        final_risk = _max_risk(
            final_risk,
            "Medium",
        )

        reasons.append(
            "The current analyst verdict is "
            "suspicious, imposing a minimum Medium "
            "operational risk."
        )

    elif analyst_verdict == "benign":

        reasons.append(
            "The current analyst verdict is benign. "
            "MedShield preserves automated evidence "
            "rather than lowering risk automatically."
        )

    elif analyst_verdict == "undetermined":

        reasons.append(
            "The analyst verdict remains "
            "undetermined."
        )


    # -----------------------------------------------------
    # Cross-signal escalation
    # -----------------------------------------------------
    #
    # Only external reputation + local ML/context are
    # currently used for escalation.
    #
    # Wazuh and local ML may originate from the same
    # underlying Suricata flow, so they are NOT treated
    # as statistically independent corroborating signals.
    # -----------------------------------------------------

    cross_signal_escalation = False

    if (
        RISK_ORDER.get(
            external_level,
            -1,
        ) >= RISK_ORDER["Medium"]
        and
        RISK_ORDER.get(
            local_level,
            -1,
        ) >= RISK_ORDER["Medium"]
        and
        local_evidence_found
    ):

        previous = final_risk

        final_risk = _raise_one_level(
            final_risk
        )

        cross_signal_escalation = (
            final_risk != previous
        )

        if cross_signal_escalation:

            reasons.append(
                "External reputation and local "
                "ML/context both independently "
                "reached at least Medium risk, so "
                "operational risk was escalated by "
                "one level."
            )


    # -----------------------------------------------------
    # Evidence dimensions / confidence
    # -----------------------------------------------------

    evidence_dimensions = 0

    if (
        external_level != "Unknown"
        and external_level != "Minimal"
    ):
        evidence_dimensions += 1

    if local_evidence_found:
        evidence_dimensions += 1

    if wazuh_evidence_found:
        evidence_dimensions += 1

    if internal_status not in {
        "none",
        "",
    }:
        evidence_dimensions += 1

    if analyst_verdict in {
        "benign",
        "suspicious",
        "malicious",
    }:
        evidence_dimensions += 1


    if evidence_dimensions >= 3:
        confidence = "high"

    elif evidence_dimensions == 2:
        confidence = "medium"

    elif evidence_dimensions == 1:
        confidence = "low"

    else:
        confidence = "low"


    # -----------------------------------------------------
    # Operational decision
    # -----------------------------------------------------

    if final_risk == "Critical":

        decision = (
            "immediate_soc_escalation"
        )

        recommended_action = (
            "Escalate immediately for SOC review. "
            "Correlate affected assets, recent events, "
            "Wazuh/Suricata evidence, analyst context "
            "and external intelligence before "
            "containment or blocking."
        )

    elif final_risk == "High":

        decision = (
            "priority_investigation"
        )

        recommended_action = (
            "Prioritize analyst investigation and "
            "review local flows, ML evidence, "
            "Wazuh/Suricata alerts, affected assets "
            "and internal intelligence."
        )

    elif final_risk == "Medium":

        decision = (
            "investigate_and_monitor"
        )

        recommended_action = (
            "Investigate supporting evidence and "
            "apply enhanced monitoring."
        )

    elif final_risk == "Low":

        decision = "monitor"

        recommended_action = (
            "Continue monitoring and correlate "
            "with future MedShield evidence."
        )

    else:

        decision = (
            "normal_monitoring"
        )

        recommended_action = (
            "No significant operational threat "
            "signal is currently present. "
            "Continue normal monitoring."
        )


    return {

        "operational_risk_level":
            final_risk,

        "decision":
            decision,

        "confidence":
            confidence,

        "evidence_dimensions":
            evidence_dimensions,

        "cross_signal_escalation":
            cross_signal_escalation,

        "dimensions": {

            "external_reputation":
                external_level,

            "local_ml_context":
                local_level,

            "wazuh_suricata":
                wazuh_level,

            "internal_intelligence":
                internal_status,

            "analyst_verdict":
                analyst_verdict
                or "none",
        },

        "reasons":
            reasons,

        "recommended_action":
            recommended_action,
    }
