from datetime import datetime, timezone
from typing import Any, Dict, Optional

from bson import ObjectId

from database import (
    reputation_collection,
    reputation_history_collection
)


# =========================================================
# SERIALIZATION HELPER
# =========================================================

def _serialize(value: Any):
    """
    Convert MongoDB-specific values into JSON/API-friendly values.
    """

    if isinstance(value, ObjectId):
        return str(value)

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, dict):
        return {
            key: _serialize(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            _serialize(item)
            for item in value
        ]

    return value


# =========================================================
# SAVE REPUTATION LOOKUP
# =========================================================

def record_reputation_lookup(
    ip: str,
    classification: Dict[str, Any],
    reputation_status: str,
    reputation_score: Optional[float],
    risk_level: Optional[str],
    confidence: Optional[str],
    threat_intelligence: Optional[Dict[str, Any]],
    reputation_analysis: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Save the current IP intelligence profile and also
    create an immutable historical observation.
    """

    observed_at = datetime.now(timezone.utc)


    # -----------------------------------------------------
    # Find existing IP profile
    # -----------------------------------------------------

    existing = reputation_collection.find_one({
        "ip": ip
    })


    previous_score = None
    previous_risk_level = None


    if existing:

        previous_score = existing.get(
            "current_score"
        )

        previous_risk_level = existing.get(
            "current_risk_level"
        )


    # -----------------------------------------------------
    # Create history record
    # -----------------------------------------------------

    history_document = {

        "ip":
            ip,

        "observed_at":
            observed_at,

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

        "previous_score":
            previous_score,

        "previous_risk_level":
            previous_risk_level,

        "threat_intelligence":
            threat_intelligence,

        "reputation_analysis":
            reputation_analysis
    }


    history_result = (
        reputation_history_collection.insert_one(
            history_document
        )
    )


    # -----------------------------------------------------
    # Calculate first seen and observation count
    # -----------------------------------------------------

    if existing:

        first_seen = existing.get(
            "first_seen",
            observed_at
        )

        observation_count = int(
            existing.get(
                "observation_count",
                0
            )
        ) + 1

    else:

        first_seen = observed_at

        observation_count = 1


    # -----------------------------------------------------
    # Build current profile
    # -----------------------------------------------------

    profile_update = {

        "ip":
            ip,

        "first_seen":
            first_seen,

        "last_seen":
            observed_at,

        "observation_count":
            observation_count,

        "previous_score":
            previous_score,

        "current_score":
            reputation_score,

        "previous_risk_level":
            previous_risk_level,

        "current_risk_level":
            risk_level,

        "confidence":
            confidence,

        "reputation_status":
            reputation_status,

        "classification":
            classification,

        "latest_threat_intelligence":
            threat_intelligence,

        "latest_reputation_analysis":
            reputation_analysis,

        "last_history_id":
            history_result.inserted_id
    }


    # -----------------------------------------------------
    # Highest / lowest score
    # -----------------------------------------------------

    if reputation_score is not None:

        old_high = (
            existing.get("highest_score")
            if existing
            else None
        )

        old_low = (
            existing.get("lowest_score")
            if existing
            else None
        )


        if old_high is None:

            profile_update["highest_score"] = (
                reputation_score
            )

        else:

            profile_update["highest_score"] = max(
                float(old_high),
                float(reputation_score)
            )


        if old_low is None:

            profile_update["lowest_score"] = (
                reputation_score
            )

        else:

            profile_update["lowest_score"] = min(
                float(old_low),
                float(reputation_score)
            )


    # -----------------------------------------------------
    # Score change
    # -----------------------------------------------------

    if (
        reputation_score is not None
        and previous_score is not None
    ):

        profile_update["score_change"] = round(
            float(reputation_score)
            - float(previous_score),
            2
        )

    else:

        profile_update["score_change"] = None


    # -----------------------------------------------------
    # Save / update current IP profile
    # -----------------------------------------------------

    reputation_collection.update_one(

        {
            "ip": ip
        },

        {
            "$set":
                profile_update
        },

        upsert=True
    )


    saved_profile = (
        reputation_collection.find_one({
            "ip": ip
        })
    )


    return {

        "profile":
            _serialize(
                saved_profile
            ),

        "history_id":
            str(
                history_result.inserted_id
            )
    }


# =========================================================
# GET CURRENT IP PROFILE
# =========================================================

def get_ip_profile(
    ip: str
) -> Optional[Dict[str, Any]]:

    document = (
        reputation_collection.find_one({
            "ip": ip
        })
    )


    if not document:
        return None


    return _serialize(
        document
    )


# =========================================================
# GET IP HISTORY
# =========================================================

def get_ip_history(
    ip: str,
    limit: int = 50
):

    cursor = (

        reputation_history_collection
        .find({
            "ip": ip
        })
        .sort(
            "observed_at",
            -1
        )
        .limit(
            limit
        )
    )


    return [

        _serialize(document)

        for document
        in cursor
    ]
