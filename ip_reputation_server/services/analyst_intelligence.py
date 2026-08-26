from datetime import datetime, timezone
from typing import Any, Dict, Optional

from bson import ObjectId

from database import (
    reputation_collection,
    analyst_notes_collection,
    analyst_verdicts_collection,
    audit_collection
)

from services.ip_classifier import classify_ip


VALID_VERDICTS = {
    "benign",
    "suspicious",
    "malicious",
    "undetermined"
}


# =========================================================
# HELPERS
# =========================================================

def _now():
    return datetime.now(timezone.utc)


def _serialize(value: Any):

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


def _normalize_ip(ip: str) -> str:

    classification = classify_ip(ip)

    return classification["ip"]


# =========================================================
# SET ANALYST VERDICT
# =========================================================

def set_analyst_verdict(
    ip: str,
    verdict: str,
    reason: str,
    actor: str
) -> Dict[str, Any]:

    normalized_ip = _normalize_ip(ip)

    normalized_verdict = (
        verdict.strip().lower()
    )

    if normalized_verdict not in VALID_VERDICTS:

        raise ValueError(
            "verdict must be one of: "
            "benign, suspicious, malicious, undetermined"
        )


    actor = actor.strip() or "analyst"

    reason = reason.strip()

    timestamp = _now()


    # -----------------------------------------------------
    # Determine previous verdict
    # -----------------------------------------------------

    previous = (
        analyst_verdicts_collection
        .find_one(
            {
                "ip": normalized_ip
            },
            sort=[
                ("created_at", -1)
            ]
        )
    )


    previous_verdict = (
        previous.get("verdict")
        if previous
        else None
    )


    # -----------------------------------------------------
    # Store immutable verdict history
    # -----------------------------------------------------

    verdict_document = {

        "ip":
            normalized_ip,

        "verdict":
            normalized_verdict,

        "previous_verdict":
            previous_verdict,

        "reason":
            reason,

        "actor":
            actor,

        "created_at":
            timestamp
    }


    result = (
        analyst_verdicts_collection
        .insert_one(
            verdict_document
        )
    )


    # -----------------------------------------------------
    # Update current IP profile
    # -----------------------------------------------------

    reputation_collection.update_one(

        {
            "ip": normalized_ip
        },

        {
            "$set": {

                "analyst_verdict":
                    normalized_verdict,

                "analyst_verdict_reason":
                    reason,

                "analyst_verdict_actor":
                    actor,

                "analyst_verdict_updated_at":
                    timestamp
            },

            "$setOnInsert": {

                "ip":
                    normalized_ip,

                "first_seen":
                    timestamp,

                "observation_count":
                    0
            }
        },

        upsert=True
    )


    # -----------------------------------------------------
    # Audit event
    # -----------------------------------------------------

    audit_collection.insert_one(
        {

            "created_at":
                timestamp,

            "actor":
                actor,

            "action":
                "analyst_verdict_set",

            "subject":
                normalized_ip,

            "details": {

                "verdict":
                    normalized_verdict,

                "previous_verdict":
                    previous_verdict,

                "reason":
                    reason,

                "verdict_id":
                    str(
                        result.inserted_id
                    )
            }
        }
    )


    saved = (
        analyst_verdicts_collection
        .find_one(
            {
                "_id":
                    result.inserted_id
            }
        )
    )


    return _serialize(saved)


# =========================================================
# ADD ANALYST NOTE
# =========================================================

def add_analyst_note(
    ip: str,
    note: str,
    actor: str
) -> Dict[str, Any]:

    normalized_ip = _normalize_ip(ip)

    clean_note = note.strip()

    actor = actor.strip() or "analyst"


    if not clean_note:

        raise ValueError(
            "Analyst note cannot be empty."
        )


    timestamp = _now()


    note_document = {

        "ip":
            normalized_ip,

        "note":
            clean_note,

        "actor":
            actor,

        "created_at":
            timestamp
    }


    result = (
        analyst_notes_collection
        .insert_one(
            note_document
        )
    )


    # -----------------------------------------------------
    # Update profile note metadata
    # -----------------------------------------------------

    reputation_collection.update_one(

        {
            "ip":
                normalized_ip
        },

        {
            "$set": {

                "last_analyst_note":
                    clean_note,

                "last_analyst_note_actor":
                    actor,

                "last_analyst_note_at":
                    timestamp
            },

            "$inc": {

                "analyst_note_count":
                    1
            },

            "$setOnInsert": {

                "ip":
                    normalized_ip,

                "first_seen":
                    timestamp,

                "observation_count":
                    0
            }
        },

        upsert=True
    )


    # -----------------------------------------------------
    # Audit event
    # -----------------------------------------------------

    audit_collection.insert_one(
        {

            "created_at":
                timestamp,

            "actor":
                actor,

            "action":
                "analyst_note_added",

            "subject":
                normalized_ip,

            "details": {

                "note_id":
                    str(
                        result.inserted_id
                    )
            }
        }
    )


    saved = (
        analyst_notes_collection
        .find_one(
            {
                "_id":
                    result.inserted_id
            }
        )
    )


    return _serialize(saved)


# =========================================================
# GET CURRENT VERDICT
# =========================================================

def get_current_verdict(
    ip: str
) -> Optional[Dict[str, Any]]:

    normalized_ip = _normalize_ip(ip)


    document = (
        analyst_verdicts_collection
        .find_one(
            {
                "ip":
                    normalized_ip
            },
            sort=[
                ("created_at", -1)
            ]
        )
    )


    return _serialize(document)


# =========================================================
# GET VERDICT HISTORY
# =========================================================

def get_verdict_history(
    ip: str,
    limit: int = 100
):

    normalized_ip = _normalize_ip(ip)


    cursor = (
        analyst_verdicts_collection
        .find(
            {
                "ip":
                    normalized_ip
            }
        )
        .sort(
            "created_at",
            -1
        )
        .limit(
            limit
        )
    )


    return [
        _serialize(document)
        for document in cursor
    ]


# =========================================================
# GET ANALYST NOTES
# =========================================================

def get_analyst_notes(
    ip: str,
    limit: int = 100
):

    normalized_ip = _normalize_ip(ip)


    cursor = (
        analyst_notes_collection
        .find(
            {
                "ip":
                    normalized_ip
            }
        )
        .sort(
            "created_at",
            -1
        )
        .limit(
            limit
        )
    )


    return [
        _serialize(document)
        for document in cursor
    ]


# =========================================================
# GET COMPLETE ANALYST INTELLIGENCE
# =========================================================

def get_analyst_intelligence(
    ip: str
):

    normalized_ip = _normalize_ip(ip)


    current_verdict = (
        get_current_verdict(
            normalized_ip
        )
    )


    notes = (
        get_analyst_notes(
            normalized_ip
        )
    )


    verdict_history = (
        get_verdict_history(
            normalized_ip
        )
    )


    return {

        "ip":
            normalized_ip,

        "current_verdict":
            current_verdict,

        "note_count":
            len(notes),

        "verdict_count":
            len(verdict_history),

        "notes":
            notes,

        "verdict_history":
            verdict_history
    }
