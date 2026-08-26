import asyncio

from services.abuseipdb import (
    lookup_abuseipdb
)

from services.virustotal import (
    lookup_virustotal
)


async def enrich_ip(
    ip_address: str
):
    """
    Run independent threat-intelligence provider lookups
    concurrently.

    Failure of one provider does not stop the other provider.
    """

    abuseipdb_result, virustotal_result = (

        await asyncio.gather(

            lookup_abuseipdb(
                ip_address
            ),

            lookup_virustotal(
                ip_address
            )
        )
    )


    successful_providers = sum([

        bool(
            abuseipdb_result.get(
                "available"
            )
        ),

        bool(
            virustotal_result.get(
                "available"
            )
        )
    ])


    configured_providers = sum([

        bool(
            abuseipdb_result.get(
                "configured"
            )
        ),

        bool(
            virustotal_result.get(
                "configured"
            )
        )
    ])


    return {

        "providers": {

            "abuseipdb":
                abuseipdb_result,

            "virustotal":
                virustotal_result
        },


        "provider_summary": {

            "configured":
                configured_providers,

            "successful":
                successful_providers,

            "total":
                2
        }
    }
