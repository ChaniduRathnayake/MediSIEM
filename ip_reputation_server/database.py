from pymongo import MongoClient
from pymongo.errors import PyMongoError

from config import settings


# ---------------------------------------------------------
# MongoDB Client
# ---------------------------------------------------------

client = MongoClient(
    settings.MONGO_URI,
    serverSelectionTimeoutMS=2500
)


# ---------------------------------------------------------
# MedShield IP Reputation Database
# ---------------------------------------------------------

db = client[settings.MONGO_DB]


# Collections that we will use later
reputation_collection = db["reputation"]

reputation_history_collection = db["reputation_history"]

analyst_notes_collection = db["analyst_notes"]

reputation_lists_collection = db["reputation_lists"]

cases_collection = db["cases"]

events_collection = db["events"]

log_sources_collection = db["log_sources"]

audit_collection = db["audit"]


# ---------------------------------------------------------
# Database Health Check
# ---------------------------------------------------------

def database_health():
    """
    Check whether MongoDB is reachable.

    This function does not crash the whole API when MongoDB
    is temporarily unavailable. Instead, MedShield reports
    the database component as unavailable/degraded.
    """

    try:

        client.admin.command("ping")

        return {
            "connected": True,
            "status": "healthy",
            "database": settings.MONGO_DB
        }

    except PyMongoError as exc:

        return {
            "connected": False,
            "status": "unavailable",
            "database": settings.MONGO_DB,
            "detail": exc.__class__.__name__
        }

    except Exception as exc:

        return {
            "connected": False,
            "status": "unavailable",
            "database": settings.MONGO_DB,
            "detail": exc.__class__.__name__
        }


# =========================================================
# ANALYST INVESTIGATION COLLECTIONS
# =========================================================

analyst_verdicts_collection = db["analyst_verdicts"]

