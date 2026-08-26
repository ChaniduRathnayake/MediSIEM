from fastapi import (
    APIRouter,
    HTTPException
)

from models.schemas import (
    AnalystVerdictRequest,
    AnalystNoteRequest
)

from services.analyst_intelligence import (
    set_analyst_verdict,
    add_analyst_note,
    get_analyst_intelligence
)


router = APIRouter(
    prefix="/api/v1/analyst",
    tags=["Analyst Intelligence"]
)


# =========================================================
# SET ANALYST VERDICT
# =========================================================

@router.post(
    "/verdict",
    summary="Set analyst verdict for an IP"
)
def create_verdict(
    payload: AnalystVerdictRequest
):

    try:

        verdict = set_analyst_verdict(

            ip=
                payload.ip,

            verdict=
                payload.verdict,

            reason=
                payload.reason,

            actor=
                payload.actor
        )


        return {

            "status":
                "saved",

            "verdict":
                verdict
        }


    except ValueError as exc:

        raise HTTPException(
            status_code=422,
            detail=str(exc)
        )


    except Exception as exc:

        print(
            "[MedShield] Analyst verdict error:",
            exc.__class__.__name__
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to store analyst verdict."
        )


# =========================================================
# ADD ANALYST NOTE
# =========================================================

@router.post(
    "/note",
    summary="Add analyst investigation note"
)
def create_note(
    payload: AnalystNoteRequest
):

    try:

        note = add_analyst_note(

            ip=
                payload.ip,

            note=
                payload.note,

            actor=
                payload.actor
        )


        return {

            "status":
                "saved",

            "note":
                note
        }


    except ValueError as exc:

        raise HTTPException(
            status_code=422,
            detail=str(exc)
        )


    except Exception as exc:

        print(
            "[MedShield] Analyst note error:",
            exc.__class__.__name__
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to store analyst note."
        )


# =========================================================
# GET COMPLETE ANALYST INTELLIGENCE
# =========================================================

@router.get(
    "/{ip_address}",
    summary="Get analyst intelligence for an IP"
)
def analyst_intelligence(
    ip_address: str
):

    try:

        result = get_analyst_intelligence(
            ip_address
        )


        return {

            "status":
                "found",

            "analyst_intelligence":
                result
        }


    except ValueError as exc:

        raise HTTPException(
            status_code=422,
            detail=str(exc)
        )


    except Exception as exc:

        print(
            "[MedShield] Analyst intelligence error:",
            exc.__class__.__name__
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve analyst intelligence."
        )
