import json
from typing import Any, Dict, Optional

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from database import events_collection

from services.ip_classifier import classify_ip

from services.local_ml_context import (
    correlate_ip_with_local_ml,
)


router = APIRouter(
    prefix="/api/v1/correlation",
    tags=["ML & Context Correlation"],
)


# =========================================================
# HELPERS
# =========================================================

def _optional_number(value: Any) -> Optional[float]:

    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _percentage_value(value: Any) -> Optional[float]:

    number = _optional_number(value)

    if number is None:
        return None

    # Compatibility with older records that stored
    # probabilities as 0.0-1.0 rather than 0-100.
    if 0 <= number <= 1:
        number *= 100

    return round(number, 2)


def _mirs_band(score: Optional[float]) -> str:

    if score is None:
        return "Unknown"

    if score >= 80:
        return "Critical"

    if score >= 60:
        return "High"

    if score >= 30:
        return "Medium"

    return "Low"


def _public_candidate(ip: Any) -> bool:

    if not isinstance(ip, str) or not ip.strip():
        return False

    try:
        classification = classify_ip(ip)

        return bool(
            classification.get(
                "external_reputation_applicable",
                False,
            )
        )

    except Exception:
        return False


# =========================================================
# LIVE ML / IP FEED
# IMPORTANT:
# This route MUST remain above /{ip_address}.
# =========================================================

@router.get(
    "/live-feed",
    summary="List recently observed public IPs with local ML evidence",
)
async def live_ip_feed(

    scan_limit: int = Query(
        default=1000,
        ge=1,
        le=5000,
    ),

    max_items: int = Query(
        default=50,
        ge=1,
        le=200,
    ),
):

    try:

        cursor = (
            events_collection
            .find({})
            .sort("_id", -1)
            .limit(scan_limit)
        )

        feed: Dict[str, Dict[str, Any]] = {}

        scanned = 0

        for event in cursor:

            scanned += 1

            src_ip = event.get("src_ip")
            dest_ip = event.get("dest_ip")

            candidates = []

            if _public_candidate(src_ip):
                candidates.append(
                    (src_ip, "source")
                )

            if (
                _public_candidate(dest_ip)
                and dest_ip != src_ip
            ):
                candidates.append(
                    (dest_ip, "destination")
                )

            if not candidates:
                continue

            mirs = _optional_number(
                event.get(
                    "MIRS",
                    event.get("mirs"),
                )
            )

            aps = _percentage_value(
                event.get(
                    "aps",
                    event.get("APS"),
                )
            )

            rf = (
                event.get("random_forest")
                if isinstance(
                    event.get("random_forest"),
                    dict,
                )
                else {}
            )

            isolation = (
                event.get("isolation_forest")
                if isinstance(
                    event.get("isolation_forest"),
                    dict,
                )
                else {}
            )

            rf_probability = _percentage_value(
                rf.get("attack_probability")
            )

            if_score = _percentage_value(
                isolation.get("anomaly_score")
            )

            real_coverage = _percentage_value(
                event.get(
                    "ml_real_feature_coverage"
                )
            )

            supplied_coverage = _percentage_value(
                event.get(
                    "ml_feature_coverage"
                )
            )

            fusion = bool(
                event.get(
                    "ml_fusion_enabled",
                    False,
                )
            )

            for ip, direction in candidates:

                if ip not in feed:

                    feed[ip] = {
                        "ip": ip,
                        "flow_count": 0,
                        "source_matches": 0,
                        "destination_matches": 0,

                        "latest_timestamp": event.get(
                            "timestamp"
                        ),

                        "latest_risk_level": event.get(
                            "risk_level"
                        ),

                        "latest_mirs": mirs,
                        "max_mirs": mirs,

                        "latest_aps": aps,
                        "max_aps": aps,

                        "latest_rf_prediction": rf.get(
                            "prediction"
                        ),

                        "latest_rf_attack_probability":
                            rf_probability,

                        "max_rf_attack_probability":
                            rf_probability,

                        "latest_if_prediction":
                            isolation.get("prediction"),

                        "latest_if_anomaly_score":
                            if_score,

                        "max_if_anomaly_score":
                            if_score,

                        "ml_fusion_observed": fusion,

                        "latest_real_feature_coverage":
                            real_coverage,

                        "latest_supplied_feature_coverage":
                            supplied_coverage,

                        "latest_flow": {
                            "src_ip": src_ip,
                            "src_port": event.get(
                                "src_port"
                            ),
                            "dest_ip": dest_ip,
                            "dest_port": event.get(
                                "dest_port"
                            ),
                            "protocol": event.get(
                                "protocol"
                            ),
                            "application": event.get(
                                "application"
                            ),
                            "flow_id": event.get(
                                "flow_id"
                            ),
                        },
                    }

                row = feed[ip]

                row["flow_count"] += 1

                if direction == "source":
                    row["source_matches"] += 1
                else:
                    row["destination_matches"] += 1

                row["ml_fusion_observed"] = bool(
                    row["ml_fusion_observed"]
                    or fusion
                )

                if mirs is not None:

                    current = row.get(
                        "max_mirs"
                    )

                    if (
                        current is None
                        or mirs > current
                    ):
                        row["max_mirs"] = round(
                            mirs,
                            2,
                        )

                if aps is not None:

                    current = row.get(
                        "max_aps"
                    )

                    if (
                        current is None
                        or aps > current
                    ):
                        row["max_aps"] = aps

                if rf_probability is not None:

                    current = row.get(
                        "max_rf_attack_probability"
                    )

                    if (
                        current is None
                        or rf_probability > current
                    ):
                        row[
                            "max_rf_attack_probability"
                        ] = rf_probability

                if if_score is not None:

                    current = row.get(
                        "max_if_anomaly_score"
                    )

                    if (
                        current is None
                        or if_score > current
                    ):
                        row[
                            "max_if_anomaly_score"
                        ] = if_score

        items = []

        for row in feed.values():

            risk_score = row.get(
                "max_mirs"
            )

            risk_band = _mirs_band(
                risk_score
            )

            row["risk_band"] = risk_band

            # "suspicious" here means the integrated
            # risk score reached Medium or above.
            # It does NOT assert that the IP is malicious.
            row["suspicious"] = (
                risk_score is not None
                and risk_score >= 30
            )

            items.append(row)

        risk_rank = {
            "Critical": 4,
            "High": 3,
            "Medium": 2,
            "Low": 1,
            "Unknown": 0,
        }

        items.sort(
            key=lambda item: (
                risk_rank.get(
                    item.get("risk_band"),
                    0,
                ),
                item.get("max_mirs") or -1,
                item.get(
                    "max_rf_attack_probability"
                )
                or -1,
                item.get("flow_count") or 0,
            ),
            reverse=True,
        )

        items = items[:max_items]

        return {
            "available": True,
            "status": "live_ml_ip_feed",
            "records_scanned": scanned,
            "unique_public_ips": len(feed),
            "returned_count": len(items),
            "suspicious_count": sum(
                1
                for item in items
                if item.get("suspicious")
            ),
            "items": items,
        }

    except Exception as exc:

        print(
            "[MedShield] Live IP feed error:",
            exc.__class__.__name__,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load live local ML IP feed."
            ),
        )


# =========================================================
# CORRELATE IP WITH LOCAL MEDSHIELD ML / CONTEXT DATA
# =========================================================

@router.get(
    "/{ip_address}",
    summary="Correlate an IP with local ML and contextual SIEM evidence",
)
async def correlate_ip(
    ip_address: str,

    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
):

    try:

        result = await correlate_ip_with_local_ml(
            ip=ip_address,
            limit=limit,
        )

        # Compatibility: older service versions may return
        # a JSON-encoded string.
        if isinstance(result, str):

            try:
                result = json.loads(result)

            except json.JSONDecodeError:
                pass

        return result

    except ValueError as exc:

        raise HTTPException(
            status_code=422,
            detail=str(exc),
        )

    except Exception as exc:

        print(
            "[MedShield] Correlation error:",
            exc.__class__.__name__,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to perform local "
                "ML/context correlation."
            ),
        )