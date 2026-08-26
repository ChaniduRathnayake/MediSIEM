from datetime import datetime, timezone

from fastapi import APIRouter

from database import events_collection


router = APIRouter(
    prefix="/api/v1/correlation",
    tags=["ML Ingestion"],
)


@router.post("/ingest")
async def ingest_ml_event(data: dict):
    """
    Persist the complete Ubuntu MedShield flow assessment used by the
    Windows IP Investigation / correlation UI.

    Important: do not replace missing evidence with zero. A missing MIRS,
    context score, or reputation score means "not available", not "safe".
    """

    timestamp = data.get("timestamp") or datetime.now(timezone.utc).isoformat()
    mirs = data.get("MIRS", data.get("mirs"))

    event = {
        "timestamp": timestamp,
        "flow_id": data.get("flow_id"),
        "src_ip": data.get("src_ip"),
        "dest_ip": data.get("dest_ip"),
        "src_port": data.get("src_port"),
        "dest_port": data.get("dest_port"),
        "proto": data.get("proto"),
        "app_proto": data.get("app_proto"),
        "event_type": data.get("event_type"),

        "prediction": data.get("prediction"),
        "risk_level": data.get("risk_level"),
        "assessment_mode": data.get("assessment_mode"),
        "operational_priority": data.get("operational_priority"),

        # Data-quality / fusion gating
        "ml_feature_coverage": data.get("ml_feature_coverage"),
        "ml_real_feature_coverage": data.get("ml_real_feature_coverage"),
        "ml_fusion_enabled": bool(data.get("ml_fusion_enabled", False)),
        "ml_data_quality": data.get("ml_data_quality") or {},

        # Local model evidence
        "random_forest": data.get("random_forest") or {},
        "isolation_forest": data.get("isolation_forest") or {},
        "aps": data.get("aps", data.get("APS")),

        # MedShield Integrated Risk Score. Keep both spellings for
        # compatibility with existing Ubuntu and Windows code.
        "MIRS": mirs,
        "mirs": mirs,
        "mirs_breakdown": data.get("mirs_breakdown") or {},

        # Context remains a separate evidence dimension even though it may
        # contribute to MIRS.
        "context_aware_risk_score": data.get("context_aware_risk_score"),
        "context_aware_risk_level": data.get("context_aware_risk_level"),
        "healthcare_context_score": data.get("healthcare_context_score"),
        "healthcare_context": data.get("healthcare_context") or {},

        # Ubuntu flow enrichment. This is retained as evidence explaining
        # the flow-level MIRS; it does not overwrite the Windows external
        # reputation lookup shown in IP Investigation.
        "ip_reputation": data.get("ip_reputation") or {},

        "suricata_alert": data.get("suricata_alert") or {},
        "explanations": data.get("explanations") or [],
    }

    # Preserve legacy flat asset fields if an older/newer collector sends
    # them. The correlation service understands both the nested and flat
    # shapes.
    for field in (
        "asset_id",
        "asset_hostname",
        "asset_type",
        "clinical_zone",
        "asset_criticality",
        "patient_safety_impact",
    ):
        if field in data:
            event[field] = data.get(field)

    result = events_collection.insert_one(event)

    return {
        "status": "stored",
        "event_id": str(result.inserted_id),
        "mirs_stored": mirs is not None,
        "ml_fusion_enabled": event["ml_fusion_enabled"],
    }
