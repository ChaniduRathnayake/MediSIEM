from fastapi import APIRouter, Query

from database import audit_collection


router = APIRouter(
    prefix="/api/v1/audit",
    tags=["Audit"]
)


def serialize_document(document):

    result = dict(document)

    if "_id" in result:
        result["_id"] = str(result["_id"])

    if result.get("created_at"):
        result["created_at"] = (
            result["created_at"].isoformat()
        )

    return result


# =========================================================
# GET AUDIT EVENTS
# =========================================================

@router.get(
    "",
    summary="Get MedShield analyst and intelligence audit events"
)
def get_audit_events(

    limit: int = Query(
        default=100,
        ge=1,
        le=500
    )
):

    cursor = (
        audit_collection
        .find({})
        .sort(
            "created_at",
            -1
        )
        .limit(limit)
    )

    events = [
        serialize_document(document)
        for document in cursor
    ]

    return {

        "count":
            len(events),

        "events":
            events
    }
