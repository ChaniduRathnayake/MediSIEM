import httpx

from config import settings


async def lookup_virustotal(
    ip_address: str
):
    """
    Query VirusTotal for IP intelligence and normalize
    the response into MedShield's provider evidence format.
    """


    # -----------------------------------------------------
    # API key not configured
    # -----------------------------------------------------

    if not settings.VIRUSTOTAL_API_KEY:

        return {

            "provider":
                "VirusTotal",

            "configured":
                False,

            "available":
                False,

            "status":
                "not_configured",

            "error":
                None,

            "evidence":
                None
        }


    headers = {

        "x-apikey":
            settings.VIRUSTOTAL_API_KEY
    }


    url = (

        f"{settings.VIRUSTOTAL_URL}/"
        f"{ip_address}"
    )


    try:

        async with httpx.AsyncClient(
            timeout=settings.TI_TIMEOUT_SECONDS
        ) as client:

            response = await client.get(

                url,

                headers=headers
            )


        # -------------------------------------------------
        # Provider returned HTTP error
        # -------------------------------------------------

        if response.status_code != 200:

            return {

                "provider":
                    "VirusTotal",

                "configured":
                    True,

                "available":
                    False,

                "status":
                    "provider_error",

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

        attributes = data.get(
            "attributes",
            {}
        )


        analysis_stats = attributes.get(

            "last_analysis_stats",

            {}
        )


        malicious = int(
            analysis_stats.get(
                "malicious",
                0
            ) or 0
        )

        suspicious = int(
            analysis_stats.get(
                "suspicious",
                0
            ) or 0
        )

        harmless = int(
            analysis_stats.get(
                "harmless",
                0
            ) or 0
        )

        undetected = int(
            analysis_stats.get(
                "undetected",
                0
            ) or 0
        )

        timeout = int(
            analysis_stats.get(
                "timeout",
                0
            ) or 0
        )


        total_engines = (

            malicious
            + suspicious
            + harmless
            + undetected
            + timeout
        )


        # -------------------------------------------------
        # Normalize evidence
        # -------------------------------------------------

        evidence = {

            "ip_address":
                data.get(
                    "id",
                    ip_address
                ),

            "reputation":
                attributes.get(
                    "reputation",
                    0
                ),

            "country":
                attributes.get(
                    "country"
                ),

            "continent":
                attributes.get(
                    "continent"
                ),

            "asn":
                attributes.get(
                    "asn"
                ),

            "as_owner":
                attributes.get(
                    "as_owner"
                ),

            "network":
                attributes.get(
                    "network"
                ),

            "last_analysis_date":
                attributes.get(
                    "last_analysis_date"
                ),

            "last_analysis_stats": {

                "malicious":
                    malicious,

                "suspicious":
                    suspicious,

                "harmless":
                    harmless,

                "undetected":
                    undetected,

                "timeout":
                    timeout,

                "total":
                    total_engines
            }
        }


        return {

            "provider":
                "VirusTotal",

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
                "VirusTotal",

            "configured":
                True,

            "available":
                False,

            "status":
                "timeout",

            "error":
                "VirusTotal request timed out.",

            "evidence":
                None
        }


    except Exception as exc:

        return {

            "provider":
                "VirusTotal",

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
