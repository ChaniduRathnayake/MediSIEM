from fastapi import (
    APIRouter,
    HTTPException,
    Query
)

from services.ip_classifier import (
    classify_ip
)

from services.wazuh_indexer import (
    search_wazuh_alerts_for_ip
)


router = APIRouter(
    prefix="/api/v1/wazuh",
    tags=["Wazuh Intelligence"]
)


@router.get(
    "/{ip_address}",
    summary="Correlate an IP with Wazuh alert evidence"
)
async def correlate_wazuh_ip(

    ip_address: str,

    limit: int = Query(
        default=50,
        ge=1,
        le=200
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


    result = await search_wazuh_alerts_for_ip(
        normalized_ip,
        limit=limit
    )


    return {

        "ip":
            normalized_ip,

        **result
    }
