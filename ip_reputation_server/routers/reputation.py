from fastapi import APIRouter, HTTPException

from models.schemas import (
    IPLookupRequest,
    ReputationLookupResponse
)

from services.ip_classifier import classify_ip
from services.threat_intelligence import enrich_ip
from services.reputation_engine import evaluate_reputation

from services.intelligence_store import (
    record_reputation_lookup
)

from services.internal_intelligence import (
    get_internal_disposition
)


router = APIRouter(
    prefix="/api/v1/reputation",
    tags=["IP Reputation"]
)


# =========================================================
# IP REPUTATION LOOKUP
# =========================================================

@router.post(
    "/lookup",
    response_model=ReputationLookupResponse,
    summary="Perform MedShield IP reputation analysis"
)
async def lookup_ip(
    payload: IPLookupRequest
):

    # -----------------------------------------------------
    # 1. CLASSIFY IP
    # -----------------------------------------------------

    try:

        classification = classify_ip(
            payload.ip
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=422,
            detail=str(exc)
        )


    explanation = [
        classification["reason"]
    ]


    # -----------------------------------------------------
    # 2. INTERNAL ANALYST INTELLIGENCE
    # -----------------------------------------------------

    try:

        internal_intelligence = (
            get_internal_disposition(
                classification["ip"]
            )
        )

        explanation.append(
            internal_intelligence[
                "message"
            ]
        )

    except Exception as exc:

        print(
            "[MedShield] Internal intelligence error:",
            exc.__class__.__name__
        )

        internal_intelligence = None

        explanation.append(
            "Internal analyst intelligence could not "
            "be retrieved."
        )


    # -----------------------------------------------------
    # 3. PUBLIC / EXTERNAL IP
    # -----------------------------------------------------

    if classification[
        "external_reputation_applicable"
    ]:

        threat_intelligence = await enrich_ip(
            classification["ip"]
        )


        configured = (
            threat_intelligence[
                "provider_summary"
            ]["configured"]
        )


        successful = (
            threat_intelligence[
                "provider_summary"
            ]["successful"]
        )


        # -----------------------------------------------
        # MedShield Reputation Engine
        # -----------------------------------------------

        reputation_analysis = (
            evaluate_reputation(
                threat_intelligence
            )
        )


        reputation_score = (
            reputation_analysis[
                "score"
            ]
        )


        risk_level = (
            reputation_analysis[
                "risk_level"
            ]
        )


        confidence = (
            reputation_analysis[
                "confidence"
            ]
        )


        # -----------------------------------------------
        # Threat intelligence state
        # -----------------------------------------------

        if configured == 0:

            reputation_status = (
                "threat_intelligence_not_configured"
            )

            explanation.append(
                "The IP is eligible for Internet "
                "reputation analysis, but no external "
                "provider API keys are configured."
            )


        elif successful == 0:

            reputation_status = (
                "threat_intelligence_unavailable"
            )

            explanation.append(
                "Threat-intelligence providers are "
                "configured, but none returned usable "
                "evidence."
            )


        elif successful < configured:

            reputation_status = (
                "partial_threat_intelligence"
            )

            explanation.append(
                "At least one configured provider "
                "returned evidence, but enrichment "
                "was incomplete."
            )


        else:

            reputation_status = (
                "reputation_analysis_complete"
            )

            explanation.append(
                "External threat intelligence was "
                "successfully analyzed by MedShield."
            )


        explanation.extend(
            reputation_analysis.get(
                "explanation",
                []
            )
        )


    # -----------------------------------------------------
    # 4. PRIVATE / LOCAL / SPECIAL IP
    # -----------------------------------------------------

    else:

        threat_intelligence = None

        reputation_analysis = None

        reputation_status = (
            "context_only"
        )

        reputation_score = None

        risk_level = None

        confidence = None


        explanation.append(
            "External Internet reputation providers "
            "were intentionally not queried."
        )

        explanation.append(
            "This address should instead be evaluated "
            "using local SIEM events, asset identity, "
            "analyst intelligence, and network behavior."
        )


    # -----------------------------------------------------
    # 5. ANALYST LIST EFFECT
    # -----------------------------------------------------

    if internal_intelligence:

        effective_status = (
            internal_intelligence.get(
                "effective_status"
            )
        )


        if effective_status == "watch":

            explanation.append(
                "MedShield operational guidance: "
                "enhanced monitoring is recommended "
                "because this IP is on the internal "
                "watchlist."
            )


        elif effective_status == "block":

            explanation.append(
                "MedShield operational guidance: "
                "this IP is on the internal blocklist. "
                "Containment or blocking should follow "
                "organizational policy."
            )


        elif effective_status == "allow":

            explanation.append(
                "MedShield operational guidance: "
                "this IP is internally allowlisted. "
                "External evidence remains visible and "
                "should not be discarded."
            )


        elif effective_status == "conflict":

            explanation.append(
                "MedShield detected conflicting internal "
                "analyst intelligence. Manual analyst "
                "review is required before automated action."
            )


    # -----------------------------------------------------
    # 6. SAVE EXTERNAL REPUTATION OBSERVATION
    # -----------------------------------------------------

    try:

        record_reputation_lookup(

            ip=
                classification["ip"],

            classification=
                classification,

            reputation_status=
                reputation_status,

            reputation_score=
                reputation_score,

            risk_level=
                risk_level,

            confidence=
                confidence,

            threat_intelligence=
                threat_intelligence,

            reputation_analysis=
                reputation_analysis
        )


        explanation.append(
            "This reputation observation was stored "
            "in the MedShield intelligence database."
        )


    except Exception as exc:

        print(
            "[MedShield] MongoDB persistence error:",
            exc.__class__.__name__
        )

        explanation.append(
            "Reputation analysis completed, but the "
            "observation could not be persisted."
        )


    # -----------------------------------------------------
    # 7. RESPONSE
    # -----------------------------------------------------

    return {

        "ip":
            classification["ip"],

        "classification":
            classification,

        "reputation_status":
            reputation_status,

        "reputation_score":
            reputation_score,

        "risk_level":
            risk_level,

        "confidence":
            confidence,

        "threat_intelligence":
            threat_intelligence,

        "reputation_analysis":
            reputation_analysis,

        "internal_intelligence":
            internal_intelligence,

        "explanation":
            explanation
    }
