import os
from collections import Counter
from typing import Any

import httpx
from dotenv import load_dotenv


load_dotenv()


WAZUH_INDEXER_URL = os.getenv(
    "WAZUH_INDEXER_URL",
    "https://192.168.154.130:9200"
).rstrip("/")

WAZUH_INDEXER_USERNAME = os.getenv(
    "WAZUH_INDEXER_USERNAME",
    ""
)

WAZUH_INDEXER_PASSWORD = os.getenv(
    "WAZUH_INDEXER_PASSWORD",
    ""
)

WAZUH_INDEX_PATTERN = os.getenv(
    "WAZUH_INDEX_PATTERN",
    "wazuh-alerts-*"
)

WAZUH_VERIFY_TLS = (
    os.getenv(
        "WAZUH_VERIFY_TLS",
        "false"
    ).lower() == "true"
)


def _project_alert(
    hit: dict[str, Any]
) -> dict[str, Any]:

    source = hit.get("_source") or {}
    rule = source.get("rule") or {}
    data = source.get("data") or {}
    alert = data.get("alert") or {}
    agent = source.get("agent") or {}

    return {

        "document_id":
            hit.get("_id"),

        "index":
            hit.get("_index"),

        "timestamp":
            source.get("timestamp"),

        "wazuh_rule": {

            "id":
                rule.get("id"),

            "level":
                rule.get("level"),

            "description":
                rule.get("description"),

            "groups":
                rule.get("groups") or []
        },

        "agent": {

            "id":
                agent.get("id"),

            "name":
                agent.get("name")
        },

        "location":
            source.get("location"),

        # srcip/dstip is Wazuh's own decoder convention (sshd, firewall);
        # src_ip/dest_ip shows up from some non-network decoders. Whichever
        # one the matched document actually used, this reads it correctly.
        "src_ip":
            data.get("srcip", data.get("src_ip")),

        "src_port":
            data.get("srcport", data.get("src_port")),

        "dest_ip":
            data.get("dstip", data.get("dest_ip")),

        "dest_port":
            data.get("dstport", data.get("dest_port")),

        "protocol":
            data.get("proto"),

        "app_proto":
            data.get("app_proto"),

        "direction":
            data.get("direction"),

        "suricata_alert": {

            "action":
                alert.get("action"),

            "signature_id":
                alert.get("signature_id"),

            "signature":
                alert.get("signature"),

            "category":
                alert.get("category"),

            "severity":
                alert.get("severity")
        },

        "medshield_log_source":
            data.get("medshield_log_source")
    }


async def search_wazuh_alerts_for_ip(
    ip_address: str,
    limit: int = 50
):

    if (
        not WAZUH_INDEXER_USERNAME
        or not WAZUH_INDEXER_PASSWORD
    ):

        return {

            "available":
                False,

            "status":
                "not_configured",

            "matched_alert_count":
                0,

            "alerts":
                [],

            "error":
                "Wazuh Indexer credentials are not configured."
        }


    query = {

        "size":
            min(
                max(limit, 1),
                200
            ),

        "sort": [
            {
                "timestamp": {
                    "order": "desc"
                }
            }
        ],

        "query": {

            "bool": {

                "minimum_should_match":
                    1,

                # Wazuh's own decoders (sshd, firewall, etc.) write
                # data.srcip/data.dstip — no underscore. Only some
                # non-network decoders (e.g. cloud/AWS integrations) use
                # src_ip/dest_ip. This instance's real alerts were
                # confirmed to use srcip/dstip (127 real sshd hits) while
                # src_ip/dest_ip matched zero documents — querying only the
                # underscored form meant this silently never found evidence
                # for any IP, regardless of whether Wazuh actually had it.
                "should": [

                    {
                        "match_phrase": {
                            "data.srcip":
                                ip_address
                        }
                    },

                    {
                        "match_phrase": {
                            "data.dstip":
                                ip_address
                        }
                    },

                    {
                        "match_phrase": {
                            "data.src_ip":
                                ip_address
                        }
                    },

                    {
                        "match_phrase": {
                            "data.dest_ip":
                                ip_address
                        }
                    }
                ]
            }
        }
    }


    url = (
        f"{WAZUH_INDEXER_URL}/"
        f"{WAZUH_INDEX_PATTERN}/_search"
    )


    try:

        async with httpx.AsyncClient(
            verify=WAZUH_VERIFY_TLS,
            timeout=10.0,
            auth=(
                WAZUH_INDEXER_USERNAME,
                WAZUH_INDEXER_PASSWORD
            )
        ) as client:

            response = await client.post(
                url,
                json=query
            )


        if response.status_code != 200:

            return {

                "available":
                    False,

                "status":
                    "indexer_error",

                "http_status":
                    response.status_code,

                "matched_alert_count":
                    0,

                "alerts":
                    [],

                "error":
                    response.text[:500]
            }


        payload = response.json()

        hits = (
            payload
            .get("hits", {})
            .get("hits", [])
        )


        alerts = [
            _project_alert(hit)
            for hit in hits
        ]


        levels = [

            item
            .get("wazuh_rule", {})
            .get("level")

            for item in alerts

            if item
            .get("wazuh_rule", {})
            .get("level") is not None
        ]


        descriptions = [

            item
            .get("wazuh_rule", {})
            .get("description")

            for item in alerts

            if item
            .get("wazuh_rule", {})
            .get("description")
        ]


        suricata_count = sum(

            1

            for item in alerts

            if (
                item.get(
                    "medshield_log_source"
                ) == "suricata"

                or "suricata" in [

                    str(group).lower()

                    for group in (
                        item
                        .get("wazuh_rule", {})
                        .get("groups", [])
                    )
                ]
            )
        )


        top_rules = [

            {
                "description":
                    description,

                "count":
                    count
            }

            for description, count
            in Counter(
                descriptions
            ).most_common(5)
        ]


        return {

            "available":
                True,

            "status":
                (
                    "wazuh_evidence_found"
                    if alerts
                    else "no_wazuh_evidence"
                ),

            "matched_alert_count":
                len(alerts),

            "suricata_alert_count":
                suricata_count,

            "highest_rule_level":
                max(levels)
                if levels
                else None,

            "latest_alert_timestamp":
                (
                    alerts[0].get("timestamp")
                    if alerts
                    else None
                ),

            "top_rules":
                top_rules,

            "alerts":
                alerts
        }


    except Exception as exc:

        return {

            "available":
                False,

            "status":
                "wazuh_unavailable",

            "matched_alert_count":
                0,

            "alerts":
                [],

            "error":
                str(exc)
        }


# =========================================================
# GENERAL WAZUH / SURICATA THREAT HUNT
# =========================================================

async def hunt_wazuh_alerts(
    *,
    hours: int = 24,
    ip_address: str | None = None,
    src_ip: str | None = None,
    dest_ip: str | None = None,
    min_level: int | None = None,
    rule_id: str | None = None,
    signature: str | None = None,
    signature_id: str | None = None,
    protocol: str | None = None,
    app_proto: str | None = None,
    direction: str | None = None,
    limit: int = 100
):

    if (
        not WAZUH_INDEXER_USERNAME
        or not WAZUH_INDEXER_PASSWORD
    ):

        return {
            "available": False,
            "status": "not_configured",
            "total_matches": 0,
            "returned_count": 0,
            "alerts": [],
            "error":
                "Wazuh Indexer credentials are not configured."
        }


    filters = []

    # -----------------------------------------------------
    # Time window
    # -----------------------------------------------------

    filters.append({
        "range": {
            "timestamp": {
                "gte": f"now-{max(hours, 1)}h",
                "lte": "now"
            }
        }
    })


    # -----------------------------------------------------
    # IP filters
    # -----------------------------------------------------

    # See search_wazuh_alerts_for_ip's comment: this Wazuh instance's real
    # decoders (sshd, firewall) write srcip/dstip, not src_ip/dest_ip —
    # match both conventions so hunts don't silently miss real alerts.
    if ip_address:

        filters.append({
            "bool": {
                "minimum_should_match": 1,
                "should": [
                    {
                        "match_phrase": {
                            "data.srcip":
                                ip_address
                        }
                    },
                    {
                        "match_phrase": {
                            "data.dstip":
                                ip_address
                        }
                    },
                    {
                        "match_phrase": {
                            "data.src_ip":
                                ip_address
                        }
                    },
                    {
                        "match_phrase": {
                            "data.dest_ip":
                                ip_address
                        }
                    }
                ]
            }
        })


    if src_ip:

        filters.append({
            "bool": {
                "minimum_should_match": 1,
                "should": [
                    {"match_phrase": {"data.srcip": src_ip}},
                    {"match_phrase": {"data.src_ip": src_ip}},
                ]
            }
        })


    if dest_ip:

        filters.append({
            "bool": {
                "minimum_should_match": 1,
                "should": [
                    {"match_phrase": {"data.dstip": dest_ip}},
                    {"match_phrase": {"data.dest_ip": dest_ip}},
                ]
            }
        })


    # -----------------------------------------------------
    # Wazuh rule filters
    # -----------------------------------------------------

    if min_level is not None:

        filters.append({
            "range": {
                "rule.level": {
                    "gte": min_level
                }
            }
        })


    if rule_id:

        filters.append({
            "match_phrase": {
                "rule.id":
                    rule_id
            }
        })


    # -----------------------------------------------------
    # Suricata filters
    # -----------------------------------------------------

    if signature:

        filters.append({
            "match_phrase": {
                "data.alert.signature":
                    signature
            }
        })


    if signature_id:

        filters.append({
            "match_phrase": {
                "data.alert.signature_id":
                    signature_id
            }
        })


    if protocol:

        filters.append({
            "match_phrase": {
                "data.proto":
                    protocol
            }
        })


    if app_proto:

        filters.append({
            "match_phrase": {
                "data.app_proto":
                    app_proto
            }
        })


    if direction:

        filters.append({
            "match_phrase": {
                "data.direction":
                    direction
            }
        })


    # -----------------------------------------------------
    # OpenSearch request
    # -----------------------------------------------------

    query = {

        "size":
            min(
                max(limit, 1),
                500
            ),

        "track_total_hits":
            True,

        "sort": [
            {
                "timestamp": {
                    "order": "desc"
                }
            }
        ],

        "query": {
            "bool": {
                "filter":
                    filters
            }
        }
    }


    url = (
        f"{WAZUH_INDEXER_URL}/"
        f"{WAZUH_INDEX_PATTERN}/_search"
    )


    try:

        async with httpx.AsyncClient(
            verify=WAZUH_VERIFY_TLS,
            timeout=15.0,
            auth=(
                WAZUH_INDEXER_USERNAME,
                WAZUH_INDEXER_PASSWORD
            )
        ) as client:

            response = await client.post(
                url,
                json=query
            )


        if response.status_code != 200:

            return {
                "available": False,
                "status": "indexer_error",
                "http_status":
                    response.status_code,
                "total_matches": 0,
                "returned_count": 0,
                "alerts": [],
                "error":
                    response.text[:1000]
            }


        payload = response.json()

        hit_container = (
            payload.get("hits")
            or {}
        )

        raw_hits = (
            hit_container.get("hits")
            or []
        )


        total_block = (
            hit_container.get("total")
        )

        if isinstance(
            total_block,
            dict
        ):
            total_matches = (
                total_block.get(
                    "value",
                    len(raw_hits)
                )
            )
        else:
            total_matches = (
                total_block
                if isinstance(
                    total_block,
                    int
                )
                else len(raw_hits)
            )


        alerts = [
            _project_alert(hit)
            for hit in raw_hits
        ]


        # -------------------------------------------------
        # Summary
        # -------------------------------------------------

        levels = [
            item.get(
                "wazuh_rule",
                {}
            ).get(
                "level"
            )
            for item in alerts
            if item.get(
                "wazuh_rule",
                {}
            ).get(
                "level"
            ) is not None
        ]


        src_ips = [
            item.get("src_ip")
            for item in alerts
            if item.get("src_ip")
        ]


        dest_ips = [
            item.get("dest_ip")
            for item in alerts
            if item.get("dest_ip")
        ]


        descriptions = [
            item.get(
                "wazuh_rule",
                {}
            ).get(
                "description"
            )
            for item in alerts
            if item.get(
                "wazuh_rule",
                {}
            ).get(
                "description"
            )
        ]


        signatures = [
            item.get(
                "suricata_alert",
                {}
            ).get(
                "signature"
            )
            for item in alerts
            if item.get(
                "suricata_alert",
                {}
            ).get(
                "signature"
            )
        ]


        suricata_count = sum(

            1

            for item in alerts

            if (
                item.get(
                    "medshield_log_source"
                ) == "suricata"

                or "suricata" in [
                    str(group).lower()

                    for group in (
                        item.get(
                            "wazuh_rule",
                            {}
                        ).get(
                            "groups",
                            []
                        )
                    )
                ]
            )
        )


        top_rules = [
            {
                "description":
                    description,
                "count":
                    count
            }

            for description, count
            in Counter(
                descriptions
            ).most_common(10)
        ]


        top_signatures = [
            {
                "signature":
                    value,
                "count":
                    count
            }

            for value, count
            in Counter(
                signatures
            ).most_common(10)
        ]


        return {

            "available":
                True,

            "status":
                (
                    "hunt_results_found"
                    if alerts
                    else "no_hunt_results"
                ),

            "filters": {
                "hours":
                    hours,
                "ip":
                    ip_address,
                "src_ip":
                    src_ip,
                "dest_ip":
                    dest_ip,
                "min_level":
                    min_level,
                "rule_id":
                    rule_id,
                "signature":
                    signature,
                "signature_id":
                    signature_id,
                "protocol":
                    protocol,
                "app_proto":
                    app_proto,
                "direction":
                    direction
            },

            "total_matches":
                total_matches,

            "returned_count":
                len(alerts),

            "suricata_alert_count":
                suricata_count,

            "highest_rule_level":
                (
                    max(levels)
                    if levels
                    else None
                ),

            "unique_source_ips":
                len(set(src_ips)),

            "unique_destination_ips":
                len(set(dest_ips)),

            "latest_alert_timestamp":
                (
                    alerts[0].get(
                        "timestamp"
                    )
                    if alerts
                    else None
                ),

            "top_rules":
                top_rules,

            "top_signatures":
                top_signatures,

            "alerts":
                alerts
        }


    except Exception as exc:

        return {
            "available": False,
            "status": "wazuh_unavailable",
            "total_matches": 0,
            "returned_count": 0,
            "alerts": [],
            "error":
                str(exc)
        }
