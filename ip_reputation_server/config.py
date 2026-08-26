import os
from dotenv import load_dotenv


# =========================================================
# LOAD ENVIRONMENT
# =========================================================

load_dotenv()


class Settings:
    """
    Central configuration for the MedShield
    IP Reputation Intelligence service.
    """

    # -----------------------------------------------------
    # Application
    # -----------------------------------------------------

    APP_NAME = "MedShield IP Reputation Intelligence"

    APP_VERSION = "1.1.0"

    HOST = os.getenv(
        "MEDSHIELD_HOST",
        "0.0.0.0"
    )

    PORT = int(
        os.getenv(
            "MEDSHIELD_PORT",
            "8088"
        )
    )


    # -----------------------------------------------------
    # MongoDB
    # -----------------------------------------------------

    MONGO_URI = os.getenv(
        "MONGO_URI",
        "mongodb://127.0.0.1:27017"
    )

    MONGO_DB = os.getenv(
        "MONGO_DB",
        "medshield_ip_reputation"
    )


    # -----------------------------------------------------
    # AbuseIPDB
    # -----------------------------------------------------

    ABUSEIPDB_API_KEY = os.getenv(
        "ABUSEIPDB_API_KEY",
        ""
    ).strip()

    ABUSEIPDB_URL = (
        "https://api.abuseipdb.com/api/v2/check"
    )

    ABUSEIPDB_MAX_AGE_DAYS = int(
        os.getenv(
            "ABUSEIPDB_MAX_AGE_DAYS",
            "90"
        )
    )


    # -----------------------------------------------------
    # VirusTotal
    # -----------------------------------------------------

    VIRUSTOTAL_API_KEY = os.getenv(
        "VIRUSTOTAL_API_KEY",
        ""
    ).strip()

    VIRUSTOTAL_URL = (
        "https://www.virustotal.com/api/v3/ip_addresses"
    )


    # -----------------------------------------------------
    # HTTP / TI Settings
    # -----------------------------------------------------

    TI_TIMEOUT_SECONDS = float(
        os.getenv(
            "TI_TIMEOUT_SECONDS",
            "10"
        )
    )


settings = Settings()
