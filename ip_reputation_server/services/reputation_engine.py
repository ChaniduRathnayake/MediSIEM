from typing import Any, Dict, List, Optional


# =========================================================
# MEDSHIELD REPUTATION ENGINE
# =========================================================
#
# IMPORTANT:
# This engine uses transparent/provisional policy rules.
#
# The continuous score is intentionally kept separate from
# evidence-based risk floors.
#
# Example:
#
# Score = 15.37
# Score-based risk = Minimal
# VirusTotal malicious detections = 12
# Evidence floor = Medium
# Final risk = Medium
#
# This avoids artificially inflating the numeric score while
# still preventing strong raw provider evidence from being
# misclassified as Minimal.
#
# These thresholds must later be calibrated experimentally.
#
# External reputation evidence alone does NOT prove that an
# IP is malicious.
# =========================================================


RISK_ORDER = {
    "Minimal": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4
}


# =========================================================
# HELPERS
# =========================================================

def _clamp(
    value: float,
    minimum: float = 0.0,
    maximum: float = 100.0
) -> float:

    return max(
        minimum,
        min(
            maximum,
            value
        )
    )


def _max_risk(
    first: str,
    second: str
) -> str:

    if (
        RISK_ORDER.get(second, 0)
        > RISK_ORDER.get(first, 0)
    ):
        return second

    return first


# =========================================================
# ABUSEIPDB SIGNAL
# =========================================================

def _abuseipdb_signal(
    provider_result: Dict[str, Any]
) -> Optional[Dict[str, Any]]:

    if not provider_result.get(
        "available"
    ):
        return None


    evidence = (
        provider_result.get(
            "evidence"
        )
        or {}
    )


    score = float(
        evidence.get(
            "abuse_confidence_score",
            0
        )
        or 0
    )


    score = _clamp(
        score
    )


    return {

        "provider":
            "AbuseIPDB",

        "signal":
            round(
                score,
                2
            ),

        "evidence": {

            "abuse_confidence_score":
                evidence.get(
                    "abuse_confidence_score"
                ),

            "total_reports":
                evidence.get(
                    "total_reports"
                ),

            "distinct_reporters":
                evidence.get(
                    "distinct_reporters"
                ),

            "last_reported_at":
                evidence.get(
                    "last_reported_at"
                ),

            "is_tor":
                evidence.get(
                    "is_tor"
                )
        }
    }


# =========================================================
# VIRUSTOTAL SIGNAL
# =========================================================

def _virustotal_signal(
    provider_result: Dict[str, Any]
) -> Optional[Dict[str, Any]]:

    if not provider_result.get(
        "available"
    ):
        return None


    evidence = (
        provider_result.get(
            "evidence"
        )
        or {}
    )


    stats = (
        evidence.get(
            "last_analysis_stats"
        )
        or {}
    )


    malicious = int(
        stats.get(
            "malicious",
            0
        )
        or 0
    )


    suspicious = int(
        stats.get(
            "suspicious",
            0
        )
        or 0
    )


    total = int(
        stats.get(
            "total",
            0
        )
        or 0
    )


    if total <= 0:

        signal = 0.0

    else:

        # -------------------------------------------------
        # Transparent normalized VirusTotal signal
        #
        # Malicious vote   = full contribution
        # Suspicious vote  = half contribution
        # -------------------------------------------------

        signal = (

            (
                malicious
                + (
                    0.5
                    * suspicious
                )
            )

            / total

        ) * 100.0


    signal = _clamp(
        signal
    )


    return {

        "provider":
            "VirusTotal",

        "signal":
            round(
                signal,
                2
            ),

        "evidence": {

            "malicious":
                malicious,

            "suspicious":
                suspicious,

            "total_engines":
                total,

            "reputation":
                evidence.get(
                    "reputation"
                ),

            "asn":
                evidence.get(
                    "asn"
                ),

            "as_owner":
                evidence.get(
                    "as_owner"
                )
        }
    }


# =========================================================
# SCORE-BASED RISK BAND
# =========================================================

def _risk_level_from_score(
    score: float
) -> str:

    if score >= 80:
        return "Critical"

    if score >= 60:
        return "High"

    if score >= 40:
        return "Medium"

    if score >= 20:
        return "Low"

    return "Minimal"


# =========================================================
# RAW-EVIDENCE RISK FLOOR
# =========================================================

def _evidence_risk_floor(
    signals: List[Dict[str, Any]]
) -> Dict[str, Any]:

    floor = "Minimal"

    reasons: List[str] = []


    for signal in signals:

        provider = signal.get(
            "provider"
        )

        evidence = (
            signal.get(
                "evidence"
            )
            or {}
        )


        # -------------------------------------------------
        # VirusTotal absolute-detection floors
        # -------------------------------------------------

        if provider == "VirusTotal":

            malicious = int(
                evidence.get(
                    "malicious",
                    0
                )
                or 0
            )

            suspicious = int(
                evidence.get(
                    "suspicious",
                    0
                )
                or 0
            )


            if malicious >= 20:

                floor = _max_risk(
                    floor,
                    "High"
                )

                reasons.append(
                    f"VirusTotal reported {malicious} "
                    "malicious engine detections, imposing "
                    "a provisional minimum High risk level."
                )


            elif malicious >= 10:

                floor = _max_risk(
                    floor,
                    "Medium"
                )

                reasons.append(
                    f"VirusTotal reported {malicious} "
                    "malicious engine detections, imposing "
                    "a provisional minimum Medium risk level."
                )


            elif malicious >= 3:

                floor = _max_risk(
                    floor,
                    "Low"
                )

                reasons.append(
                    f"VirusTotal reported {malicious} "
                    "malicious engine detections, imposing "
                    "a provisional minimum Low risk level."
                )


            elif suspicious >= 3:

                floor = _max_risk(
                    floor,
                    "Low"
                )

                reasons.append(
                    f"VirusTotal reported {suspicious} "
                    "suspicious engine detections, imposing "
                    "a provisional minimum Low risk level."
                )


        # -------------------------------------------------
        # AbuseIPDB confidence floors
        # -------------------------------------------------

        elif provider == "AbuseIPDB":

            abuse_score = float(
                evidence.get(
                    "abuse_confidence_score",
                    0
                )
                or 0
            )


            if abuse_score >= 80:

                floor = _max_risk(
                    floor,
                    "High"
                )

                reasons.append(
                    "AbuseIPDB abuse confidence is at least "
                    "80%, imposing a provisional minimum "
                    "High risk level."
                )


            elif abuse_score >= 50:

                floor = _max_risk(
                    floor,
                    "Medium"
                )

                reasons.append(
                    "AbuseIPDB abuse confidence is at least "
                    "50%, imposing a provisional minimum "
                    "Medium risk level."
                )


            elif abuse_score >= 20:

                floor = _max_risk(
                    floor,
                    "Low"
                )

                reasons.append(
                    "AbuseIPDB abuse confidence is at least "
                    "20%, imposing a provisional minimum "
                    "Low risk level."
                )


    return {

        "risk_level":
            floor,

        "reasons":
            reasons
    }


# =========================================================
# DECISION FROM FINAL RISK
# =========================================================

def _decision_from_risk(
    risk_level: str
) -> str:

    if risk_level == "Critical":
        return "very_high_risk_reputation"

    if risk_level == "High":
        return "high_risk_reputation"

    if risk_level == "Medium":
        return "suspicious_reputation"

    if risk_level == "Low":
        return "weak_reputation_signal"

    return "no_significant_reputation_signal"


# =========================================================
# RECOMMENDED ACTION FROM FINAL RISK
# =========================================================

def _recommended_action(
    risk_level: str
) -> str:

    if risk_level == "Critical":

        return (
            "Escalate for immediate analyst review and "
            "correlate with SIEM, network, asset, and local "
            "ML evidence before automated response."
        )


    if risk_level == "High":

        return (
            "Prioritize this IP for analyst investigation. "
            "Correlate external reputation with local SIEM "
            "events, ML evidence, affected assets, and "
            "network behavior."
        )


    if risk_level == "Medium":

        return (
            "Investigate the supporting provider evidence "
            "and correlate with local MedShield ML, SIEM, "
            "asset, and network context."
        )


    if risk_level == "Low":

        return (
            "Monitor the address and correlate with other "
            "MedShield evidence before escalation."
        )


    return (
        "No significant external reputation signal. "
        "Continue normal monitoring and local correlation."
    )


# =========================================================
# MAIN ENGINE
# =========================================================

def evaluate_reputation(
    threat_intelligence: Dict[str, Any]
) -> Dict[str, Any]:

    providers = (
        threat_intelligence.get(
            "providers",
            {}
        )
        or {}
    )


    signals: List[
        Dict[str, Any]
    ] = []


    # -----------------------------------------------------
    # Extract normalized provider signals
    # -----------------------------------------------------

    abuse_signal = (
        _abuseipdb_signal(
            providers.get(
                "abuseipdb",
                {}
            )
        )
    )


    vt_signal = (
        _virustotal_signal(
            providers.get(
                "virustotal",
                {}
            )
        )
    )


    if abuse_signal:
        signals.append(
            abuse_signal
        )


    if vt_signal:
        signals.append(
            vt_signal
        )


    # -----------------------------------------------------
    # No usable provider evidence
    # -----------------------------------------------------

    if not signals:

        return {

            "score":
                None,

            "score_based_risk_level":
                "Unknown",

            "evidence_floor_level":
                "Unknown",

            "risk_level":
                "Unknown",

            "decision":
                "insufficient_evidence",

            "confidence":
                "none",

            "provider_agreement":
                "not_applicable",

            "provider_signal_count":
                0,

            "signals":
                [],

            "explanation": [

                (
                    "No usable external threat-intelligence "
                    "provider evidence was available."
                )
            ],

            "recommended_action":

                (
                    "Use local SIEM and ML evidence and retry "
                    "external enrichment when available."
                )
        }


    # -----------------------------------------------------
    # Continuous normalized score
    # -----------------------------------------------------

    values = [

        float(
            item[
                "signal"
            ]
        )

        for item in signals
    ]


    score = (

        sum(values)
        / len(values)
    )


    score = round(
        _clamp(
            score
        ),
        2
    )


    score_based_risk = (
        _risk_level_from_score(
            score
        )
    )


    # -----------------------------------------------------
    # Raw-evidence safety floor
    # -----------------------------------------------------

    evidence_floor = (
        _evidence_risk_floor(
            signals
        )
    )


    evidence_floor_level = (
        evidence_floor[
            "risk_level"
        ]
    )


    final_risk = _max_risk(
        score_based_risk,
        evidence_floor_level
    )


    # -----------------------------------------------------
    # Provider signal alignment / confidence
    # -----------------------------------------------------

    if len(values) == 1:

        provider_agreement = (
            "single_provider"
        )

        confidence = "low"


    else:

        difference = abs(
            values[0]
            - values[1]
        )


        if difference <= 15:

            provider_agreement = (
                "strong_signal_alignment"
            )

            confidence = "high"


        elif difference <= 35:

            provider_agreement = (
                "moderate_signal_alignment"
            )

            confidence = "medium"


        else:

            provider_agreement = (
                "weak_signal_alignment"
            )

            confidence = "low"


    # -----------------------------------------------------
    # Explanation
    # -----------------------------------------------------

    explanation: List[str] = []


    for signal in signals:

        provider = signal[
            "provider"
        ]

        provider_score = signal[
            "signal"
        ]


        explanation.append(

            (
                f"{provider} contributed a normalized "
                f"reputation signal of "
                f"{provider_score:.2f}/100."
            )
        )


    explanation.append(
        (
            f"The continuous reputation score is "
            f"{score:.2f}/100, corresponding to a "
            f"score-based risk level of "
            f"{score_based_risk}."
        )
    )


    for reason in evidence_floor[
        "reasons"
    ]:

        explanation.append(
            reason
        )


    if (
        RISK_ORDER.get(
            evidence_floor_level,
            0
        )
        >
        RISK_ORDER.get(
            score_based_risk,
            0
        )
    ):

        explanation.append(
            (
                f"The final external risk was raised from "
                f"{score_based_risk} to {final_risk} by "
                "the raw-evidence risk floor. The numeric "
                "reputation score itself was not inflated."
            )
        )


    if len(signals) == 2:

        explanation.append(
            (
                "Provider signal alignment was classified "
                f"as {provider_agreement}. This describes "
                "similarity between normalized provider "
                "signals; it does not by itself mean the "
                "address is safe or malicious."
            )
        )


    explanation.append(
        (
            "The MedShield external reputation assessment "
            "must be correlated with local SIEM, network, "
            "asset, machine-learning, and contextual "
            "evidence before treating an address as "
            "malicious."
        )
    )


    return {

        "score":
            score,

        "score_based_risk_level":
            score_based_risk,

        "evidence_floor_level":
            evidence_floor_level,

        "risk_level":
            final_risk,

        "decision":
            _decision_from_risk(
                final_risk
            ),

        "confidence":
            confidence,

        "provider_agreement":
            provider_agreement,

        "provider_signal_count":
            len(signals),

        "signals":
            signals,

        "explanation":
            explanation,

        "recommended_action":
            _recommended_action(
                final_risk
            )
    }
