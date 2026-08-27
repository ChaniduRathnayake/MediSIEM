from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from services.ip_classifier import (
    classify_ip,
)

from services.intelligence_store import (
    get_ip_profile,
)

from services.internal_intelligence import (
    get_internal_disposition,
)

from services.analyst_intelligence import (
    get_analyst_intelligence,
)

from services.local_ml_context import (
    correlate_ip_with_local_ml,
)

from services.wazuh_indexer import (
    search_wazuh_alerts_for_ip,
)

from services.operational_risk import (
    evaluate_operational_risk,
)


router = APIRouter(
    prefix="/api/v1/operational",
    tags=["Operational Risk"],
)


@router.get(
    "/{ip_address}",
    summary=(
        "Build complete MedShield operational "
        "risk assessment for an IP"
    ),
)
async def operational_assessment(
    ip_address: str,

    # Same high-volume recency issue as correlation.py's correlate_ip: 100
    # most-recent events isn't enough headroom once flow ingestion is fast,
    # so this was silently reporting "no_local_evidence"/MIRS Unavailable
    # for IPs the live feed (scan_limit up to 5000) had just observed.
    local_limit: int = Query(
        default=1000,
        ge=1,
        le=5000,
    ),

    wazuh_limit: int = Query(
        default=50,
        ge=1,
        le=200,
    ),
):


    # -----------------------------------------------------
    # 1. Validate / normalize IP
    # -----------------------------------------------------

    try:

        classification = classify_ip(
            ip_address
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=422,
            detail=str(exc),
        )


    normalized_ip = (
        classification["ip"]
    )


    # -----------------------------------------------------
    # 2. Latest external reputation
    # -----------------------------------------------------

    try:

        profile = get_ip_profile(
            normalized_ip
        )

    except Exception as exc:

        print(
            "[MedShield] Reputation profile error:",
            exc.__class__.__name__,
        )

        profile = None


    external_risk = None
    external_score = None
    external_confidence = None

    if profile:

        external_risk = profile.get(
            "current_risk_level"
        )

        external_score = profile.get(
            "current_score"
        )

        external_confidence = profile.get(
            "confidence"
        )


    # -----------------------------------------------------
    # 3. Internal intelligence
    # -----------------------------------------------------

    try:

        internal_intelligence = (
            get_internal_disposition(
                normalized_ip
            )
        )

    except Exception as exc:

        print(
            "[MedShield] Internal intelligence error:",
            exc.__class__.__name__,
        )

        internal_intelligence = None


    # -----------------------------------------------------
    # 4. Analyst intelligence
    # -----------------------------------------------------

    try:

        analyst_intelligence = (
            get_analyst_intelligence(
                normalized_ip
            )
        )

    except Exception as exc:

        print(
            "[MedShield] Analyst intelligence error:",
            exc.__class__.__name__,
        )

        analyst_intelligence = None


    # -----------------------------------------------------
    # 5. Local ML / context
    # -----------------------------------------------------

    local_correlation = (
        await correlate_ip_with_local_ml(
            ip=normalized_ip,
            limit=local_limit,
        )
    )


    # -----------------------------------------------------
    # 6. Wazuh / Suricata correlation
    # -----------------------------------------------------

    wazuh_evidence = (
        await search_wazuh_alerts_for_ip(
            normalized_ip,
            wazuh_limit,
        )
    )


    # -----------------------------------------------------
    # 7. Operational risk engine
    # -----------------------------------------------------

    assessment = (
        evaluate_operational_risk(

            external_risk=
                external_risk,

            local_correlation=
                local_correlation,

            wazuh_evidence=
                wazuh_evidence,

            internal_intelligence=
                internal_intelligence,

            analyst_intelligence=
                analyst_intelligence,
        )
    )


    # -----------------------------------------------------
    # 8. Response
    # -----------------------------------------------------

    return {

        "ip":
            normalized_ip,

        "classification":
            classification,

        "external_reputation": {

            "available":
                bool(profile),

            "score":
                external_score,

            "risk_level":
                external_risk
                or "Unknown",

            "confidence":
                external_confidence
                or "none",
        },

        "local_ml_context": {

            "available":
                local_correlation.get(
                    "available",
                    False,
                ),

            "status":
                local_correlation.get(
                    "status"
                ),

            "matched_event_count":
                local_correlation.get(
                    "matched_event_count",
                    0,
                ),

            "summary":
                local_correlation.get(
                    "summary"
                ),
        },

        "wazuh_suricata": {

            "available":
                wazuh_evidence.get(
                    "available",
                    False,
                ),

            "status":
                wazuh_evidence.get(
                    "status"
                ),

            "matched_alert_count":
                wazuh_evidence.get(
                    "matched_alert_count",
                    0,
                ),

            "suricata_alert_count":
                wazuh_evidence.get(
                    "suricata_alert_count",
                    0,
                ),

            "highest_rule_level":
                wazuh_evidence.get(
                    "highest_rule_level"
                ),

            "latest_alert_timestamp":
                wazuh_evidence.get(
                    "latest_alert_timestamp"
                ),

            "top_rules":
                wazuh_evidence.get(
                    "top_rules",
                    [],
                ),
        },

        "internal_intelligence":
            internal_intelligence,

        "analyst_intelligence":
            analyst_intelligence,

        "operational_assessment":
            assessment,
    }

