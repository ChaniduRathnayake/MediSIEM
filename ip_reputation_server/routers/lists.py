from typing import Optional

from fastapi import (
    APIRouter,
    HTTPException,
    Query
)

from models.schemas import (
    ReputationListRequest
)

from services.internal_intelligence import (
    upsert_reputation_list,
    get_ip_lists,
    get_all_lists,
    remove_from_list
)


router = APIRouter(
    prefix="/api/v1/lists",
    tags=["Internal Intelligence"]
)


# =========================================================
# ADD / UPDATE LIST RECORD
# =========================================================

@router.post(
    "",
    summary="Add an IP to allow/watch/block intelligence"
)
def add_list_entry(
    payload: ReputationListRequest
):

    try:

        result = (
            upsert_reputation_list(
                ip=payload.ip,
                list_type=payload.list_type,
                reason=payload.reason,
                actor=payload.actor
            )
        )


        return {
            "status":
                "saved",

            "entry":
                result
        }


    except ValueError as exc:

        raise HTTPException(
            status_code=422,
            detail=str(exc)
        )


# =========================================================
# GET ALL LIST RECORDS
# =========================================================

@router.get(
    "",
    summary="Get allow/watch/block records"
)
def list_entries(

    list_type: Optional[str] = Query(
        default=None
    )
):

    try:

        items = get_all_lists(
            list_type
        )


        return {
            "count":
                len(items),

            "items":
                items
        }


    except ValueError as exc:

        raise HTTPException(
            status_code=422,
            detail=str(exc)
        )


# =========================================================
# GET INTERNAL INTELLIGENCE FOR ONE IP
# =========================================================

@router.get(
    "/ip/{ip_address}",
    summary="Get internal intelligence for an IP"
)
def ip_list_entries(
    ip_address: str
):

    try:

        items = get_ip_lists(
            ip_address
        )


        return {
            "ip":
                ip_address,

            "count":
                len(items),

            "items":
                items
        }


    except ValueError as exc:

        raise HTTPException(
            status_code=422,
            detail=str(exc)
        )


# =========================================================
# REMOVE LIST RECORD
# =========================================================

@router.delete(
    "/{list_type}/{ip_address}",
    summary="Remove an IP from an internal intelligence list"
)
def delete_list_entry(

    list_type: str,

    ip_address: str,

    actor: str = "analyst"
):

    try:

        return remove_from_list(
            ip=ip_address,
            list_type=list_type,
            actor=actor
        )


    except ValueError as exc:

        raise HTTPException(
            status_code=422,
            detail=str(exc)
        )
