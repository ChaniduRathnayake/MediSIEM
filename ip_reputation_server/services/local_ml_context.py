from typing import Any, Dict, List, Optional

from database import events_collection
from services.ip_classifier import classify_ip


# =========================================================
# HELPERS
# =========================================================


def _optional_number(value: Any) -> Optional[float]:
    """Return a float when evidence exists; otherwise preserve absence."""

    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _round_or_none(value: Optional[float], digits: int = 2):
    if value is None:
        return None
    return round(value, digits)


def _max_or_none(values: List[float], digits: int = 2):
    if not values:
        return None
    return round(max(values), digits)


def _average_or_none(values: List[float], digits: int = 2):
    if not values:
        return None
    return round(sum(values) / len(values), digits)


def _mirs_band(score: Optional[float]) -> str:
    if score is None:
        return "Unknown"
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def _mirs_value(item: Dict[str, Any]) -> Optional[float]:
    return _optional_number(
        item.get("MIRS", item.get("mirs"))
    )


def _aps_value(item: Dict[str, Any]) -> Optional[float]:
    return _optional_number(
        item.get("aps", item.get("APS"))
    )


def _nested_context(item: Dict[str, Any]) -> Dict[str, Any]:
    value = item.get("healthcare_context")
    return value if isinstance(value, dict) else {}


def _nested_reputation(item: Dict[str, Any]) -> Dict[str, Any]:
    value = item.get("ip_reputation")
    return value if isinstance(value, dict) else {}


def _nested_breakdown(item: Dict[str, Any]) -> Dict[str, Any]:
    value = item.get("mirs_breakdown")
    return value if isinstance(value, dict) else {}


# =========================================================
# FETCH LOCAL ML / CONTEXT RECORDS
# =========================================================


async def fetch_local_ml_records(
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Read the latest flow assessments ingested by the Ubuntu collector."""

    try:
        records: List[Dict[str, Any]] = []

        cursor = (
            events_collection
            .find()
            .sort("_id", -1)
            .limit(limit)
        )

        for item in cursor:
            item["_id"] = str(item["_id"])
            records.append(item)

        return records

    except Exception as exc:
        print("[MedShield] Mongo event fetch error:", exc)
        return []


# =========================================================
# CORRELATE IP WITH LOCAL ML / CONTEXT / MIRS
# =========================================================


async def correlate_ip_with_local_ml(
    ip: str,
    limit: int = 100,
) -> Dict[str, Any]:
    normalized_ip = classify_ip(ip)["ip"]

    try:
        records = await fetch_local_ml_records(limit=limit)
    except Exception as exc:
        return {
            "available": False,
            "status": "local_ml_backend_unavailable",
            "ip": normalized_ip,
            "error": exc.__class__.__name__,
            "matched_event_count": 0,
            "mirs_evidence": {
                "available": False,
                "status": "backend_unavailable",
            },
            "events": [],
        }

    # -----------------------------------------------------
    # Find source OR destination matches
    # -----------------------------------------------------

    matches = [
        record
        for record in records
        if (
            record.get("src_ip") == normalized_ip
            or record.get("dest_ip") == normalized_ip
        )
    ]

    if not matches:
        return {
            "available": True,
            "status": "no_local_evidence",
            "ip": normalized_ip,
            "records_scanned": len(records),
            "matched_event_count": 0,
            "source_matches": 0,
            "destination_matches": 0,
            "ml_fusion_observed": False,
            "mirs_evidence": {
                "available": False,
                "status": "no_matching_flow_mirs",
            },
            "summary": None,
            "events": [],
        }

    # -----------------------------------------------------
    # Direction counts
    # -----------------------------------------------------

    source_matches = sum(
        1 for item in matches
        if item.get("src_ip") == normalized_ip
    )
    destination_matches = sum(
        1 for item in matches
        if item.get("dest_ip") == normalized_ip
    )

    # -----------------------------------------------------
    # Numeric evidence. Missing values are excluded rather
    # than silently converted to zero.
    # -----------------------------------------------------

    rf_scores = [
        value
        for item in matches
        if (
            value := _optional_number(
                (item.get("random_forest") or {}).get("attack_probability")
            )
        ) is not None
    ]

    if_scores = [
        value
        for item in matches
        if (
            value := _optional_number(
                (item.get("isolation_forest") or {}).get("anomaly_score")
            )
        ) is not None
    ]

    coverage_scores = [
        value
        for item in matches
        if (value := _optional_number(item.get("ml_feature_coverage"))) is not None
    ]

    real_coverage_scores = [
        value
        for item in matches
        if (
            value := _optional_number(item.get("ml_real_feature_coverage"))
        ) is not None
    ]

    context_scores = [
        value
        for item in matches
        if (
            value := _optional_number(item.get("context_aware_risk_score"))
        ) is not None
    ]

    healthcare_scores = [
        value
        for item in matches
        if (
            value := _optional_number(item.get("healthcare_context_score"))
        ) is not None
    ]

    mirs_scores = [
        value
        for item in matches
        if (value := _mirs_value(item)) is not None
    ]

    aps_scores = [
        value
        for item in matches
        if (value := _aps_value(item)) is not None
    ]

    latest = matches[0]
    latest_mirs_event = next(
        (item for item in matches if _mirs_value(item) is not None),
        None,
    )

    # -----------------------------------------------------
    # MIRS evidence projection
    # -----------------------------------------------------

    if latest_mirs_event:
        latest_mirs = _mirs_value(latest_mirs_event)
        latest_aps = _aps_value(latest_mirs_event)
        latest_breakdown = _nested_breakdown(latest_mirs_event)
        latest_rep = _nested_reputation(latest_mirs_event)
        latest_context = _nested_context(latest_mirs_event)

        mirs_evidence = {
            "available": True,
            "status": "mirs_evidence_found",
            "latest_score": _round_or_none(latest_mirs),
            "max_score": _max_or_none(mirs_scores),
            "average_score": _average_or_none(mirs_scores),
            "risk_band": (
                latest_mirs_event.get("risk_level")
                or _mirs_band(latest_mirs)
            ),
            "latest_aps": _round_or_none(latest_aps),
            "max_aps": _max_or_none(aps_scores),
            "ml_fusion_enabled": bool(
                latest_mirs_event.get("ml_fusion_enabled", False)
            ),
            "feature_coverage": _optional_number(
                latest_mirs_event.get("ml_feature_coverage")
            ),
            "real_feature_coverage": _optional_number(
                latest_mirs_event.get("ml_real_feature_coverage")
            ),
            "timestamp": latest_mirs_event.get("timestamp"),
            "flow_id": latest_mirs_event.get("flow_id"),
            "src_ip": latest_mirs_event.get("src_ip"),
            "dest_ip": latest_mirs_event.get("dest_ip"),
            "breakdown": latest_breakdown,
            "flow_reputation": latest_rep,
            "healthcare_context": latest_context,
            "explanations": latest_mirs_event.get("explanations") or [],
        }
    else:
        mirs_evidence = {
            "available": False,
            "status": "mirs_not_present_in_stored_events",
            "message": (
                "Matching historical flow records were found, but they do not "
                "contain MIRS. New events ingested after the MIRS ingestion "
                "upgrade will populate this panel."
            ),
        }

    # -----------------------------------------------------
    # Simplified event projection for the Windows UI
    # -----------------------------------------------------

    projected_events = []

    for item in matches[:25]:
        healthcare_context = _nested_context(item)
        item_mirs = _mirs_value(item)

        projected_events.append({
            "id": item.get("_id"),
            "timestamp": item.get("timestamp"),
            "flow_id": item.get("flow_id"),
            "src_ip": item.get("src_ip"),
            "src_port": item.get("src_port"),
            "dest_ip": item.get("dest_ip"),
            "dest_port": item.get("dest_port"),
            "protocol": item.get("proto"),
            "application": item.get("app_proto"),
            "event_type": item.get("event_type"),
            "prediction": item.get("prediction"),
            "risk_level": item.get("risk_level"),
            "assessment_mode": item.get("assessment_mode"),
            "operational_priority": item.get("operational_priority"),
            "ml_feature_coverage": item.get("ml_feature_coverage"),
            "ml_real_feature_coverage": item.get("ml_real_feature_coverage"),
            "ml_fusion_enabled": bool(item.get("ml_fusion_enabled", False)),
            "aps": _aps_value(item),
            "mirs": item_mirs,
            "mirs_breakdown": _nested_breakdown(item),
            "ip_reputation": _nested_reputation(item),
            "healthcare_context": healthcare_context,
            "explanations": item.get("explanations") or [],
            "random_forest": {
                "prediction": (item.get("random_forest") or {}).get(
                    "prediction_label"
                ),
                "attack_probability": (item.get("random_forest") or {}).get(
                    "attack_probability"
                ),
                "confidence": (item.get("random_forest") or {}).get("confidence"),
            },
            "isolation_forest": {
                "prediction": (item.get("isolation_forest") or {}).get(
                    "prediction"
                ),
                "anomaly_score": (item.get("isolation_forest") or {}).get(
                    "anomaly_score"
                ),
                "anomaly_score_normalised": (
                    item.get("isolation_forest") or {}
                ).get("anomaly_score_normalised"),
            },
            "context_risk_score": item.get("context_aware_risk_score"),
            "context_risk_level": item.get("context_aware_risk_level"),
            "healthcare_context_score": item.get("healthcare_context_score"),
            "asset": {
                "asset_id": healthcare_context.get("asset_id") or item.get("asset_id"),
                "hostname": healthcare_context.get("hostname") or item.get("asset_hostname"),
                "asset_type": healthcare_context.get("asset_type") or item.get("asset_type"),
                "clinical_zone": healthcare_context.get("clinical_zone") or item.get("clinical_zone"),
                "criticality": healthcare_context.get("criticality") or item.get("asset_criticality"),
                "patient_safety_impact": healthcare_context.get(
                    "patient_safety_impact"
                ) or item.get("patient_safety_impact"),
            },
            "suricata_alert": item.get("suricata_alert") or {},
        })

    return {
        "available": True,
        "status": "local_evidence_found",
        "ip": normalized_ip,
        "records_scanned": len(records),
        "matched_event_count": len(matches),
        "source_matches": source_matches,
        "destination_matches": destination_matches,
        "ml_fusion_observed": any(
            bool(item.get("ml_fusion_enabled"))
            for item in matches
        ),
        "mirs_evidence": mirs_evidence,
        "summary": {
            # RF remains a probability in the API (0-1). The React UI is
            # responsible for rendering it as a percentage.
            "max_rf_attack_probability": _max_or_none(rf_scores, 4),
            "max_if_anomaly_score": _max_or_none(if_scores, 4),
            "average_feature_coverage": _average_or_none(coverage_scores),
            "average_real_feature_coverage": _average_or_none(
                real_coverage_scores
            ),
            "max_context_risk_score": _max_or_none(context_scores),
            "max_healthcare_context_score": _max_or_none(healthcare_scores),
            "latest_mirs": mirs_evidence.get("latest_score"),
            "max_mirs": mirs_evidence.get("max_score"),
            "latest_aps": mirs_evidence.get("latest_aps"),
            "latest_context_risk_level": latest.get("context_aware_risk_level"),
            "latest_operational_priority": latest.get("operational_priority"),
            "latest_assessment_mode": latest.get("assessment_mode"),
            "latest_timestamp": latest.get("timestamp"),
        },
        "events": projected_events,
    }

# Backward compatibility for existing Log Sources integration
LEGACY_MEDSHIELD_URL = "http://192.168.154.130:8080/ml/reputation"
