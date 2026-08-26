from datetime import datetime, timezone

import httpx
from fastapi import APIRouter

from services.local_ml_context import (
    LEGACY_MEDSHIELD_URL
)


router = APIRouter(
    prefix="/api/v1/log-sources",
    tags=["Log Sources"]
)


def now_iso():
    return datetime.now(
        timezone.utc
    ).isoformat()


@router.get(
    "",
    summary="Get real MedShield log/source health"
)
async def get_log_sources():

    checked_at = now_iso()

    source = {

        "id":
            "legacy-medshield-ml-context",

        "name":
            "MedShield Local ML / Suricata Context Feed",

        "type":
            "network_ml_context",

        "endpoint":
            LEGACY_MEDSHIELD_URL,

        "status":
            "unknown",

        "reachable":
            False,

        "checked_at":
            checked_at,

        "records_available":
            0,

        "latest_event_timestamp":
            None,

        "ml_fusion_observed":
            False,

        "average_feature_coverage":
            None,

        "message":
            None
    }


    try:

        async with httpx.AsyncClient(
            timeout=8.0
        ) as client:

            response = await client.get(
                LEGACY_MEDSHIELD_URL,
                params={
                    "limit": 100
                }
            )


        source["http_status"] = (
            response.status_code
        )


        if response.status_code != 200:

            source["status"] = "degraded"

            source["message"] = (
                f"Source returned HTTP "
                f"{response.status_code}."
            )

            return {

                "count": 1,

                "healthy": 0,

                "degraded": 1,

                "unavailable": 0,

                "sources": [
                    source
                ]
            }


        payload = response.json()


        if isinstance(payload, list):

            records = payload

        elif isinstance(payload, dict):

            records = (
                payload.get("reputation")
                or payload.get("records")
                or payload.get("items")
                or payload.get("data")
                or []
            )

        else:

            records = []


        source["reachable"] = True

        source["records_available"] = (
            len(records)
        )


        timestamps = [

            item.get("timestamp")

            for item in records

            if isinstance(item, dict)
            and item.get("timestamp")
        ]


        if timestamps:

            source["latest_event_timestamp"] = (
                max(timestamps)
            )


        source["ml_fusion_observed"] = any(

            bool(
                item.get(
                    "ml_fusion_enabled"
                )
            )

            for item in records

            if isinstance(item, dict)
        )


        coverage_values = [

            float(
                item.get(
                    "ml_feature_coverage"
                )
            )

            for item in records

            if isinstance(item, dict)
            and item.get(
                "ml_feature_coverage"
            ) is not None
        ]


        if coverage_values:

            source[
                "average_feature_coverage"
            ] = round(

                sum(
                    coverage_values
                )
                / len(
                    coverage_values
                ),

                2
            )


        if records:

            source["status"] = "healthy"

            source["message"] = (
                "Source is reachable and "
                "returned MedShield telemetry."
            )

        else:

            source["status"] = "degraded"

            source["message"] = (
                "Source is reachable but "
                "returned no telemetry records."
            )


    except Exception as exc:

        source["status"] = "unavailable"

        source["message"] = (
            f"Unable to reach source: {exc}"
        )


    healthy = (
        1
        if source["status"] == "healthy"
        else 0
    )

    degraded = (
        1
        if source["status"] == "degraded"
        else 0
    )

    unavailable = (
        1
        if source["status"] == "unavailable"
        else 0
    )


    return {

        "count": 1,

        "healthy":
            healthy,

        "degraded":
            degraded,

        "unavailable":
            unavailable,

        "sources": [
            source
        ]
    }
