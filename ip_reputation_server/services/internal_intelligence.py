from datetime import datetime, timezone
from typing import Any, Dict, Optional

from database import (
    reputation_lists_collection,
    audit_collection
)

from services.ip_classifier import (
    classify_ip
)


VALID_LIST_TYPES = {
    "allow",
    "watch",
    "block"
}


def _now():
    return datetime.now(
        timezone.utc
    )


def _serialize(document):
    if not document:
        return None

    result = dict(document)

    if "_id" in result:
        result["_id"] = str(
            result["_id"]
        )

    for key in (
        "created_at",
        "updated_at"
    ):

        value = result.get(key)

        if isinstance(
            value,
            datetime
        ):

            result[key] = (
                value.isoformat()
            )

    return result


# =========================================================
# ADD / UPDATE INTERNAL INTELLIGENCE
# =========================================================

def upsert_reputation_list(
    ip: str,
    list_type: str,
    reason: str,
    actor: str
) -> Dict[str, Any]:

    classification = classify_ip(
        ip
    )

    normalized_ip = (
        classification["ip"]
    )

    normalized_type = (
        list_type.strip().lower()
    )


    if normalized_type not in VALID_LIST_TYPES:

        raise ValueError(
            "list_type must be one of: "
            "allow, watch, block"
        )


    existing = (
        reputation_lists_collection.find_one(
            {
                "ip":
                    normalized_ip,

                "list_type":
                    normalized_type
            }
        )
    )


    timestamp = _now()


    if existing:

        created_at = existing.get(
            "created_at",
            timestamp
        )

    else:

        created_at = timestamp


    document = {

        "ip":
            normalized_ip,

        "list_type":
            normalized_type,

        "reason":
            reason.strip(),

        "actor":
            actor.strip()
            or "analyst",

        "created_at":
            created_at,

        "updated_at":
            timestamp
    }


    reputation_lists_collection.update_one(

        {
            "ip":
                normalized_ip,

            "list_type":
                normalized_type
        },

        {
            "$set":
                document
        },

        upsert=True
    )


    # -----------------------------------------------------
    # AUDIT EVENT
    # -----------------------------------------------------

    audit_collection.insert_one(
        {
            "created_at":
                timestamp,

            "actor":
                document["actor"],

            "action":
                (
                    "reputation_list_updated"
                    if existing
                    else
                    "reputation_list_added"
                ),

            "subject":
                normalized_ip,

            "details": {

                "list_type":
                    normalized_type,

                "reason":
                    document["reason"]
            }
        }
    )


    saved = (
        reputation_lists_collection.find_one(
            {
                "ip":
                    normalized_ip,

                "list_type":
                    normalized_type
            }
        )
    )


    return _serialize(
        saved
    )


# =========================================================
# GET INTELLIGENCE FOR ONE IP
# =========================================================

def get_ip_lists(
    ip: str
):

    normalized_ip = (
        classify_ip(ip)["ip"]
    )


    cursor = (
        reputation_lists_collection.find(
            {
                "ip":
                    normalized_ip
            }
        )
    )


    return [

        _serialize(document)

        for document
        in cursor
    ]


# =========================================================
# GET ALL LIST RECORDS
# =========================================================

def get_all_lists(
    list_type: Optional[str] = None
):

    query = {}


    if list_type:

        normalized_type = (
            list_type.strip().lower()
        )


        if normalized_type not in VALID_LIST_TYPES:

            raise ValueError(
                "Invalid list type."
            )


        query[
            "list_type"
        ] = normalized_type


    cursor = (
        reputation_lists_collection
        .find(query)
        .sort(
            "updated_at",
            -1
        )
    )


    return [

        _serialize(document)

        for document
        in cursor
    ]


# =========================================================
# REMOVE FROM LIST
# =========================================================

def remove_from_list(
    ip: str,
    list_type: str,
    actor: str = "analyst"
):

    normalized_ip = (
        classify_ip(ip)["ip"]
    )


    normalized_type = (
        list_type.strip().lower()
    )


    if normalized_type not in VALID_LIST_TYPES:

        raise ValueError(
            "Invalid list type."
        )


    result = (
        reputation_lists_collection.delete_one(
            {
                "ip":
                    normalized_ip,

                "list_type":
                    normalized_type
            }
        )
    )


    if result.deleted_count:

        audit_collection.insert_one(
            {
                "created_at":
                    _now(),

                "actor":
                    actor,

                "action":
                    "reputation_list_removed",

                "subject":
                    normalized_ip,

                "details": {
                    "list_type":
                        normalized_type
                }
            }
        )


    return {
        "deleted":
            bool(
                result.deleted_count
            ),

        "ip":
            normalized_ip,

        "list_type":
            normalized_type
    }


# =========================================================
# INTERNAL INTELLIGENCE DISPOSITION
# =========================================================

def get_internal_disposition(
    ip: str
) -> Dict[str, Any]:

    items = get_ip_lists(
        ip
    )


    memberships = sorted(
        list({
            item["list_type"]
            for item in items
        })
    )


    # -----------------------------------------------------
    # Detect contradictory analyst intelligence
    # -----------------------------------------------------

    conflicting = (
        "allow" in memberships
        and "block" in memberships
    )


    if conflicting:

        effective_status = (
            "conflict"
        )

        operational_disposition = (
            "analyst_review_required"
        )

        message = (
            "The IP exists in both the allowlist and "
            "blocklist. Automatic action should not be "
            "taken until an analyst resolves the conflict."
        )


    elif "block" in memberships:

        effective_status = (
            "block"
        )

        operational_disposition = (
            "block_or_contain"
        )

        message = (
            "The IP is present in the MedShield blocklist."
        )


    elif "watch" in memberships:

        effective_status = (
            "watch"
        )

        operational_disposition = (
            "enhanced_monitoring"
        )

        message = (
            "The IP is present in the MedShield watchlist."
        )


    elif "allow" in memberships:

        effective_status = (
            "allow"
        )

        operational_disposition = (
            "trusted_with_monitoring"
        )

        message = (
            "The IP is present in the MedShield allowlist."
        )


    else:

        effective_status = (
            "none"
        )

        operational_disposition = (
            "no_internal_override"
        )

        message = (
            "No internal analyst intelligence exists "
            "for this IP."
        )


    return {

        "matched":
            bool(items),

        "memberships":
            memberships,

        "effective_status":
            effective_status,

        "operational_disposition":
            operational_disposition,

        "conflict":
            conflicting,

        "message":
            message,

        "entries":
            items
    }
