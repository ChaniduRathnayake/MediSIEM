import httpx

from config import settings


async def lookup_abuseipdb(
    ip_address: str
):
    """
    Query AbuseIPDB for reputation information.

    Returns normalized evidence so the rest of MedShield
    does not depend directly on the provider's raw format.
    """

    # -----------------------------------------------------
    # API key not configured
    # -----------------------------------------------------

    if not settings.ABUSEIPDB_API_KEY:

        return {
            "provider": "AbuseIPDB",

            "configured": False,

            "available": False,

            "status": "not_configured",

            "error": None,

            "evidence": None
        }


    headers = {

        "Accept":
            "application/json",

        "Key":
            settings.ABUSEIPDB_API_KEY
    }


    params = {

        "ipAddress":
            ip_address,

        "maxAgeInDays":
            settings.ABUSEIPDB_MAX_AGE_DAYS
    }


    try:

        async with httpx.AsyncClient(
            timeout=settings.TI_TIMEOUT_SECONDS
        ) as client:

            response = await client.get(

                settings.ABUSEIPDB_URL,

                headers=headers,

                params=params
            )


        # -------------------------------------------------
        # Provider returned HTTP error
        # -------------------------------------------------

        if response.status_code != 200:

            return {
                "provider": "AbuseIPDB",

                "configured": True,

                "available": False,

                "status": "provider_error",

                "http_status":
                    response.status_code,

                "error":
                    response.text[:500],

                "evidence":
                    None
            }


        payload = response.json()

        data = payload.get(
            "data",
            {}
        )


        # -------------------------------------------------
        # Normalize provider evidence
        # -------------------------------------------------

        evidence = {

            "ip_address":
                data.get(
                    "ipAddress",
                    ip_address
                ),

            "ip_version":
                data.get(
                    "ipVersion"
                ),

            "is_public":
                data.get(
                    "isPublic"
                ),

            "abuse_confidence_score":
                data.get(
                    "abuseConfidenceScore",
                    0
                ),

            "country_code":
                data.get(
                    "countryCode"
                ),

            "usage_type":
                data.get(
                    "usageType"
                ),

            "isp":
                data.get(
                    "isp"
                ),

            "domain":
                data.get(
                    "domain"
                ),

            "is_tor":
                data.get(
                    "isTor"
                ),

            "total_reports":
                data.get(
                    "totalReports",
                    0
                ),

            "distinct_reporters":
                data.get(
                    "numDistinctUsers",
                    0
                ),

            "last_reported_at":
                data.get(
                    "lastReportedAt"
                )
        }


        return {

            "provider":
                "AbuseIPDB",

            "configured":
                True,

            "available":
                True,

            "status":
                "success",

            "error":
                None,

            "evidence":
                evidence
        }


    except httpx.TimeoutException:

        return {

            "provider":
                "AbuseIPDB",

            "configured":
                True,

            "available":
                False,

            "status":
                "timeout",

            "error":
                "AbuseIPDB request timed out.",

            "evidence":
                None
        }


    except Exception as exc:

        return {

            "provider":
                "AbuseIPDB",

            "configured":
                True,

            "available":
                False,

            "status":
                "error",

            "error":
                exc.__class__.__name__,

            "evidence":
                None
        }
