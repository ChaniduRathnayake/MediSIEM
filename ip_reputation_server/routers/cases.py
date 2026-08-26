from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from database import (
    cases_collection,
    audit_collection,
    reputation_collection
)


router = APIRouter(
    prefix="/api/v1/cases",
    tags=["Cases"]
)


# =========================================================
# REQUEST MODELS
# =========================================================

class CaseCreateRequest(BaseModel):

    ip: str

    title: str = Field(
        ...,
        min_length=1,
        max_length=300
    )

    description: str = Field(
        default="",
        max_length=5000
    )

    severity: str = Field(
        default="Medium"
    )

    actor: str = Field(
        default="analyst01",
        max_length=200
    )


class CaseStatusRequest(BaseModel):

    status: str

    reason: str = Field(
        default="",
        max_length=2000
    )

    actor: str = Field(
        default="analyst01",
        max_length=200
    )


# =========================================================
# HELPERS
# =========================================================

def now_utc():

    return datetime.now(
        timezone.utc
    )


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


def parse_case_id(case_id: str):

    if not ObjectId.is_valid(case_id):

        raise HTTPException(
            status_code=422,
            detail="Invalid case ID."
        )

    return ObjectId(case_id)


# =========================================================
# CREATE CASE
# =========================================================

@router.post(
    "",
    summary="Create a MedShield investigation case"
)
def create_case(
    request: CaseCreateRequest
):

    allowed_severity = {
        "Low",
        "Medium",
        "High",
        "Critical"
    }

    if request.severity not in allowed_severity:

        raise HTTPException(
            status_code=422,
            detail=(
                "Severity must be Low, Medium, "
                "High or Critical."
            )
        )


    timestamp = now_utc()


    profile = reputation_collection.find_one(
        {
            "ip": request.ip
        }
    )


    reputation_snapshot = None

    if profile:

        reputation_snapshot = {

            "score":
                profile.get(
                    "current_score"
                ),

            "risk_level":
                profile.get(
                    "current_risk_level"
                ),

            "confidence":
                profile.get(
                    "confidence"
                ),

            "last_seen":
                profile.get(
                    "last_seen"
                )
        }


    document = {

        "ip":
            request.ip,

        "title":
            request.title,

        "description":
            request.description,

        "severity":
            request.severity,

        "status":
            "open",

        "created_by":
            request.actor,

        "assigned_to":
            request.actor,

        "created_at":
            timestamp,

        "updated_at":
            timestamp,

        "closed_at":
            None,

        "reputation_snapshot":
            reputation_snapshot
    }


    result = cases_collection.insert_one(
        document
    )


    case_id = str(
        result.inserted_id
    )


    audit_collection.insert_one({

        "action":
            "case_created",

        "subject":
            request.ip,

        "actor":
            request.actor,

        "details": {

            "case_id":
                case_id,

            "title":
                request.title,

            "severity":
                request.severity
        },

        "created_at":
            timestamp
    })


    document["_id"] = result.inserted_id


    return {

        "status":
            "created",

        "case":
            serialize_value(
                document
            )
    }


# =========================================================
# LIST CASES
# =========================================================

@router.get(
    "",
    summary="List MedShield cases"
)
def list_cases(

    limit: int = Query(
        default=100,
        ge=1,
        le=500
    ),

    status: Optional[str] = None
):

    query = {}

    if status:

        query["status"] = status


    cursor = (
        cases_collection
        .find(query)
        .sort(
            "updated_at",
            -1
        )
        .limit(limit)
    )


    cases = [
        serialize_value(document)
        for document in cursor
    ]


    return {

        "count":
            len(cases),

        "cases":
            cases
    }


# =========================================================
# GET ONE CASE
# =========================================================

@router.get(
    "/{case_id}",
    summary="Get a MedShield case"
)
def get_case(
    case_id: str
):

    object_id = parse_case_id(
        case_id
    )


    document = cases_collection.find_one(
        {
            "_id": object_id
        }
    )


    if not document:

        raise HTTPException(
            status_code=404,
            detail="Case not found."
        )


    return {

        "case":
            serialize_value(
                document
            )
    }


# =========================================================
# UPDATE CASE STATUS
# =========================================================

@router.patch(
    "/{case_id}/status",
    summary="Update MedShield case status"
)
def update_case_status(
    case_id: str,
    request: CaseStatusRequest
):

    allowed_statuses = {
        "open",
        "in_progress",
        "resolved",
        "closed"
    }


    if request.status not in allowed_statuses:

        raise HTTPException(
            status_code=422,
            detail=(
                "Status must be open, in_progress, "
                "resolved or closed."
            )
        )


    object_id = parse_case_id(
        case_id
    )


    existing = cases_collection.find_one(
        {
            "_id": object_id
        }
    )


    if not existing:

        raise HTTPException(
            status_code=404,
            detail="Case not found."
        )


    timestamp = now_utc()


    update = {

        "status":
            request.status,

        "updated_at":
            timestamp
    }


    if request.status == "closed":

        update["closed_at"] = timestamp

    else:

        update["closed_at"] = None


    cases_collection.update_one(

        {
            "_id": object_id
        },

        {
            "$set": update
        }
    )


    audit_collection.insert_one({

        "action":
            "case_status_updated",

        "subject":
            existing.get("ip"),

        "actor":
            request.actor,

        "details": {

            "case_id":
                case_id,

            "previous_status":
                existing.get("status"),

            "new_status":
                request.status,

            "reason":
                request.reason
        },

        "created_at":
            timestamp
    })


    updated = cases_collection.find_one(
        {
            "_id": object_id
        }
    )


    return {

        "status":
            "updated",

        "case":
            serialize_value(
                updated
            )
    }
