from fastapi import (
    APIRouter,
    Query,
)

from services.wazuh_indexer import (
    hunt_wazuh_alerts,
)


router = APIRouter(
    prefix="/api/v1/threat-hunt",
    tags=["Threat Hunt"],
)


@router.get(
    "",
    summary=(
        "Hunt Wazuh and Suricata security evidence"
    ),
)
async def threat_hunt(

    hours: int = Query(
        default=24,
        ge=1,
        le=720,
    ),

    ip: str | None = Query(
        default=None,
    ),

    src_ip: str | None = Query(
        default=None,
    ),

    dest_ip: str | None = Query(
        default=None,
    ),

    min_level: int | None = Query(
        default=None,
        ge=0,
        le=15,
    ),

    rule_id: str | None = Query(
        default=None,
    ),

    signature: str | None = Query(
        default=None,
    ),

    signature_id: str | None = Query(
        default=None,
    ),

    protocol: str | None = Query(
        default=None,
    ),

    app_proto: str | None = Query(
        default=None,
    ),

    direction: str | None = Query(
        default=None,
    ),

    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
):

    return await hunt_wazuh_alerts(

        hours=hours,

        ip_address=ip,

        src_ip=src_ip,

        dest_ip=dest_ip,

        min_level=min_level,

        rule_id=rule_id,

        signature=signature,

        signature_id=signature_id,

        protocol=protocol,

        app_proto=app_proto,

        direction=direction,

        limit=limit,
    )
