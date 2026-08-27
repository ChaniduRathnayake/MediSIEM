from pymongo import MongoClient
from pymongo.errors import PyMongoError

from config import settings


# ---------------------------------------------------------
# MongoDB Client
# ---------------------------------------------------------

client = MongoClient(
    settings.MONGO_URI,
    serverSelectionTimeoutMS=2500,
    # serverSelectionTimeoutMS only bounds picking a server; once a socket to
    # Mongo is open, a connection that goes quietly unresponsive has no
    # timeout by default and can hang a request — including
    # database_health()'s own ping — indefinitely instead of degrading.
    connectTimeoutMS=5000,
    # Generous on purpose: /live-feed scans up to 5000 documents from a
    # remote Atlas cluster, which legitimately takes longer than a
    # single-document health ping under real network latency — 8000ms here
    # turned "slow but correct" into "reliably 500s" the first time Atlas
    # round-trips were elevated.
    socketTimeoutMS=20000
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
# Log retention: auto-expire raw flow telemetry
# ---------------------------------------------------------
# events_collection is the live Suricata collector's per-flow firehose —
# unlike cases/analyst_notes/audit/verdicts (analyst work product, must
# persist), it's disposable telemetry that exists to feed the live feed and
# recent-flow correlation. Left unbounded it will eventually fill a
# capacity-limited cluster (e.g. Atlas free tier's 512MB) until writes start
# failing. A TTL index deletes documents past their retention window
# automatically, without a separate cleanup job.
#
# TTL requires a genuine BSON Date field — the "timestamp" field is the
# collector's own string, kept as-is for display/back-compat, so ingestion
# also stamps "ingested_at" as a real datetime specifically for this index.
#
# create_index() is idempotent when the spec is unchanged; if
# EVENTS_RETENTION_DAYS was changed since the index was created, Mongo
# rejects the mismatched expireAfterSeconds (IndexOptionsConflict) rather
# than silently ignoring it, so that case is repaired via collMod.
try:
    _retention_seconds = int(settings.EVENTS_RETENTION_DAYS * 86400)
    try:
        events_collection.create_index(
            "ingested_at",
            name="ingested_at_ttl",
            expireAfterSeconds=_retention_seconds,
        )
    except PyMongoError as exc:
        if getattr(exc, "code", None) == 85:  # IndexOptionsConflict
            db.command(
                "collMod",
                events_collection.name,
                index={
                    "keyPattern": {"ingested_at": 1},
                    "expireAfterSeconds": _retention_seconds,
                },
            )
        else:
            raise
except Exception as exc:
    # Never let a slow/unreachable Mongo at import time take the whole app
    # down — worst case, retention just isn't enforced until the next
    # successful startup.
    print("[MedShield] Could not ensure events TTL index:", exc.__class__.__name__)


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

