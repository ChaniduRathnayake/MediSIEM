from datetime import datetime

from bson import ObjectId

from fastapi import (
    APIRouter,
    HTTPException,
    Query
)

from database import (
    reputation_collection
)

from services.ip_classifier import (
    classify_ip
)

from services.intelligence_store import (
    get_ip_profile,
    get_ip_history
)


router = APIRouter(
    prefix="/api/v1/intelligence",
    tags=["IP Intelligence"]
)


# =========================================================
# SERIALIZATION
# =========================================================

def serialize_value(value):

    if isinstance(value, ObjectId):
        return str(value)

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, dict):
        return {
            key: serialize_value(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            serialize_value(item)
            for item in value
        ]

    return value


# =========================================================
# OBSERVED / INVESTIGATED IP PROFILES
# =========================================================

@router.get(
    "",
    summary="List observed MedShield IP intelligence profiles"
)
def list_intelligence_profiles(

    limit: int = Query(
        default=100,
        ge=1,
        le=500
    )
):

    cursor = (
        reputation_collection
        .find({})
        .sort(
            "last_seen",
            -1
        )
        .limit(limit)
    )

    profiles = [
        serialize_value(document)
        for document in cursor
    ]

    return {

        "count":
            len(profiles),

        "limit":
            limit,

        "profiles":
            profiles
    }


# =========================================================
# CURRENT IP INTELLIGENCE PROFILE
# =========================================================

@router.get(
    "/{ip_address}",
    summary="Get current intelligence profile for an IP"
)
def get_intelligence_profile(
    ip_address: str
):

    try:

        classification = classify_ip(
            ip_address
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=422,
            detail=str(exc)
        )


    normalized_ip = (
        classification["ip"]
    )


    profile = get_ip_profile(
        normalized_ip
    )


    if not profile:

        raise HTTPException(
            status_code=404,
            detail=(
                "No MedShield intelligence profile "
                "exists for this IP yet."
            )
        )


    return {

        "ip":
            normalized_ip,

        "status":
            "found",

        "profile":
            profile
    }


# =========================================================
# IP REPUTATION HISTORY
# =========================================================

@router.get(
    "/{ip_address}/history",
    summary="Get historical reputation observations"
)
def get_intelligence_history(
    ip_address: str,

    limit: int = Query(
        default=50,
        ge=1,
        le=500
    )
):

    try:

        classification = classify_ip(
            ip_address
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=422,
            detail=str(exc)
        )


    normalized_ip = (
        classification["ip"]
    )


    history = get_ip_history(
        normalized_ip,
        limit=limit
    )


    return {

        "ip":
            normalized_ip,

        "count":
            len(history),

        "limit":
            limit,

        "history":
            history
    }
