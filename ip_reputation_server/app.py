from fastapi import FastAPI

from config import settings

from database import (
    database_health
)

from routers.reputation import (
    router as reputation_router
)

from routers.intelligence import (
    router as intelligence_router
)

from routers.lists import (
    router as lists_router
)

from routers.analyst import (
    router as analyst_router
)

from routers.correlation import (
    router as correlation_router
)

from routers.operational import (
    router as operational_router
)

from routers.audit import (
    router as audit_router
)


# =========================================================
# MEDSHIELD APPLICATION
# =========================================================

app = FastAPI(

    title=settings.APP_NAME,

    version=settings.APP_VERSION,

    description="""
# MedShield IP Reputation Intelligence

IP Reputation and Threat Intelligence subsystem
for the MedShield SIEM platform.

Current capabilities:

- IPv4 / IPv6 classification
- Public/private IP awareness
- AbuseIPDB enrichment
- VirusTotal enrichment
- Explainable MedShield reputation scoring
- Provider agreement analysis
- Confidence assessment
- Persistent MongoDB intelligence profiles
- Historical reputation observations
- First-seen / last-seen tracking
- Reputation trend tracking
- Internal allowlist
- Internal watchlist
- Internal blocklist
- Audit recording for analyst list actions
"""
)


# =========================================================
# REGISTER ROUTERS
# =========================================================

app.include_router(
    reputation_router
)

app.include_router(
    intelligence_router
)

app.include_router(
    lists_router
)

app.include_router(
    analyst_router
)

app.include_router(
    correlation_router
)

app.include_router(
    operational_router
)

app.include_router(
    audit_router
)


# =========================================================
# ROOT
# =========================================================

@app.get(
    "/",
    tags=["Platform"],
    summary="MedShield service information"
)
def root():

    return {

        "service":
            settings.APP_NAME,

        "version":
            settings.APP_VERSION,

        "status":
            "running",

        "component":
            "ip_reputation_intelligence",

        "documentation":
            "/docs"
    }


# =========================================================
# HEALTH
# =========================================================

@app.get(
    "/api/health",
    tags=["Platform"],
    summary="Check MedShield service health"
)
def health():

    mongo = database_health()


    abuse_configured = bool(
        settings.ABUSEIPDB_API_KEY
    )

    vt_configured = bool(
        settings.VIRUSTOTAL_API_KEY
    )


    configured_count = sum([
        abuse_configured,
        vt_configured
    ])


    if configured_count == 2:

        ti_status = "configured"

    elif configured_count == 1:

        ti_status = "partially_configured"

    else:

        ti_status = "not_configured"


    overall_status = (

        "healthy"

        if mongo["connected"]

        else "degraded"
    )


    return {

        "status":
            overall_status,

        "service":
            settings.APP_NAME,

        "version":
            settings.APP_VERSION,

        "components": {

            "api": {
                "status":
                    "healthy"
            },

            "mongodb":
                mongo,

            "ip_classifier": {
                "status":
                    "healthy"
            },

            "reputation_engine": {
                "status":
                    "healthy"
            },

            "intelligence_store": {
                "status":
                    (
                        "healthy"
                        if mongo["connected"]
                        else "unavailable"
                    )
            },

            "internal_intelligence": {
                "status":
                    (
                        "healthy"
                        if mongo["connected"]
                        else "unavailable"
                    )
            },

            "threat_intelligence": {

                "status":
                    ti_status,

                "providers": {

                    "abuseipdb": {
                        "configured":
                            abuse_configured
                    },

                    "virustotal": {
                        "configured":
                            vt_configured
                    }
                }
            }
        }
    }





# =========================================================
# CASE MANAGEMENT
# =========================================================

from routers.cases import router as cases_router

app.include_router(cases_router)



# =========================================================
# LOG SOURCE HEALTH
# =========================================================

from routers.log_sources import router as log_sources_router

app.include_router(log_sources_router)


# =========================================================
# WAZUH INTELLIGENCE
# =========================================================

from routers.wazuh import router as wazuh_router

app.include_router(wazuh_router)


from routers.threat_hunt import router as threat_hunt_router
app.include_router(threat_hunt_router)

from routers.ml_ingest import router as ml_ingest_router

app.include_router(
    ml_ingest_router
)
