"""
CAAP Wazuh Consumer — Phase 7 (Day 3-6)
=========================================
Polls Elasticsearch / wazuh-indexer for new Wazuh alerts, runs each one
through the CAAP Flask pipeline (POST /predict), and writes the enriched
alert (original fields + CAAP fields) back into a dedicated `caap-alerts`
index.

Pipeline:
    wazuh-alerts-*  --poll-->  wazuh_consumer.py  --POST /predict-->  Flask
                                       |
                                       v
                                 caap-alerts (Elasticsearch)

Run:
    python src/wazuh_consumer.py                 # continuous polling loop
    python src/wazuh_consumer.py --once           # single poll cycle (testing)
    python src/wazuh_consumer.py --once --dry-run # poll + predict, skip ES write

Config is via environment variables (see CONFIG section below) or a .env
file in the project root (loaded automatically if python-dotenv is present).

Requires:
    pip install elasticsearch requests python-dotenv
"""

import os
import sys
import json
import time
import signal
import logging
import argparse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from elasticsearch import Elasticsearch, ConnectionError as ESConnectionError

# --------------------------------------------------------------------------
# Config (env vars — override in .env or the shell)
# --------------------------------------------------------------------------

ES_HOST = os.getenv("ES_HOST", "https://localhost:9200")
ES_USER = os.getenv("ES_USER", "admin")
ES_PASS = os.getenv("ES_PASS", "admin")
ES_VERIFY_CERTS = os.getenv("ES_VERIFY_CERTS", "false").lower() == "true"  # wazuh-indexer uses self-signed certs

# Wazuh writes alerts into a rolling daily index, e.g. wazuh-alerts-4.x-2026.07.31
WAZUH_ALERTS_INDEX_PATTERN = os.getenv("WAZUH_ALERTS_INDEX_PATTERN", "wazuh-alerts-*")
CAAP_ALERTS_INDEX = os.getenv("CAAP_ALERTS_INDEX", "caap-alerts")

FLASK_PREDICT_URL = os.getenv("FLASK_PREDICT_URL", "http://localhost:5001/predict")
FLASK_TIMEOUT_SECONDS = int(os.getenv("FLASK_TIMEOUT_SECONDS", "10"))

POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "10"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "100"))

# Persisted cursor so restarts don't reprocess the whole index
STATE_FILE = os.getenv("STATE_FILE", os.path.join(os.path.dirname(__file__), "..", ".wazuh_consumer_state.json"))

# Only alerts at/above this Wazuh rule level are sent through the pipeline.
# (Levels 0-2 are mostly noise / login success events.)
MIN_RULE_LEVEL = int(os.getenv("MIN_RULE_LEVEL", "3"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("wazuh_consumer")

_shutdown = False


def _handle_sigint(signum, frame):
    global _shutdown
    log.info("Shutdown signal received — finishing current cycle then exiting.")
    _shutdown = True


signal.signal(signal.SIGINT, _handle_sigint)
signal.signal(signal.SIGTERM, _handle_sigint)


# --------------------------------------------------------------------------
# State (cursor) handling
# --------------------------------------------------------------------------

def load_state() -> Dict[str, Any]:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            log.warning(f"Could not read state file ({e}); starting fresh.")
    # First run: start from "now" so we don't replay the entire historical index
    return {"last_timestamp": datetime.now(timezone.utc).isoformat()}


def save_state(state: Dict[str, Any]) -> None:
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except OSError as e:
        log.error(f"Could not persist state file: {e}")


# --------------------------------------------------------------------------
# Elasticsearch client
# --------------------------------------------------------------------------

def get_es_client() -> Elasticsearch:
    return Elasticsearch(
        ES_HOST,
        basic_auth=(ES_USER, ES_PASS),
        verify_certs=ES_VERIFY_CERTS,
        ssl_show_warn=False,
        request_timeout=30,
    )


def fetch_new_alerts(es: Elasticsearch, since_iso: str, size: int = BATCH_SIZE) -> List[Dict[str, Any]]:
    """
    Query wazuh-alerts-* for documents newer than `since_iso`, ascending
    by @timestamp so alerts are processed in order.
    """
    query = {
        "size": size,
        "sort": [{"@timestamp": "asc"}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gt": since_iso}}},
                    {"range": {"rule.level": {"gte": MIN_RULE_LEVEL}}},
                ]
            }
        },
    }
    resp = es.search(index=WAZUH_ALERTS_INDEX_PATTERN, body=query)
    return resp.get("hits", {}).get("hits", [])


def index_enriched_alert(es: Elasticsearch, doc_id: str, body: Dict[str, Any]) -> None:
    """
    Write to caap-alerts using the original alert's _id as the doc id.
    This makes the write idempotent — reprocessing the same alert (e.g.
    after a crash/restart before the state file was saved) just overwrites
    the same document instead of creating a duplicate.
    """
    es.index(index=CAAP_ALERTS_INDEX, id=doc_id, document=body)


# --------------------------------------------------------------------------
# Wazuh alert -> CAAP feature payload adapter
# --------------------------------------------------------------------------
# NOTE: This is the piece you'll want to refine as part of your thesis
# methodology. app.py's /predict endpoint was trained on network-flow
# features (CIC IoMT / CICIDS: flow_bytes_s, flow_packets_s, IAT, packet
# length stats, active/idle means, ...). Wazuh log-based alerts
# (auth.log/syslog/audit.log, Windows Event IDs 4624/4625/4688/7045) don't
# carry those flow statistics directly — they're host/event alerts, not
# packet captures.
#
# The mapping below is a reasonable placeholder: it zero-fills the flow
# features the model doesn't have real values for, and derives what it can
# (device/department context, rough severity signal) from the Wazuh alert
# itself. Swap in your real feature-engineering logic here.

# Feature order must match what scaler.pkl / random_forest.pkl expect.
# Update this list to match your actual trained feature_cols.pkl.
FLOW_FEATURE_DEFAULTS = {
    "flow_bytes_s": 0.0,
    "flow_packets_s": 0.0,
    "flow_iat_mean": 0.0,
    "fwd_pkt_len_mean": 0.0,
    "active_mean": 0.0,
    "idle_mean": 0.0,
    # ... add the remaining trained feature columns here with 0.0 defaults
}

# Simple agent-name -> (device_type, department) lookup. Extend this with
# your real hospital asset inventory, or replace with a DB/CC-table lookup
# similar to the port-based table in src/cas_engine.py.
AGENT_DEVICE_MAP = {
    # "hospital-ubuntu-agent-01": {"device_type": "Clinical Workstation", "department": "Administration"},
}

DEFAULT_DEVICE = {"device_type": "Unclassified Host", "department": "IT Infrastructure"}


def wazuh_alert_to_caap_payload(hit: Dict[str, Any]) -> Dict[str, Any]:
    src = hit.get("_source", {})
    agent = src.get("agent", {}) or {}
    agent_name = agent.get("name", "unknown")

    device_ctx = AGENT_DEVICE_MAP.get(agent_name, DEFAULT_DEVICE)

    payload = dict(FLOW_FEATURE_DEFAULTS)  # start with zero-filled flow features
    payload["device_type"] = device_ctx["device_type"]
    payload["department"] = device_ctx["department"]

    return payload


# --------------------------------------------------------------------------
# Flask /predict call
# --------------------------------------------------------------------------

def call_predict(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        resp = requests.post(FLASK_PREDICT_URL, json=payload, timeout=FLASK_TIMEOUT_SECONDS)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        log.error(f"/predict call failed: {e}")
        return None


# --------------------------------------------------------------------------
# Enrichment
# --------------------------------------------------------------------------

def build_enriched_doc(hit: Dict[str, Any], caap_result: Dict[str, Any]) -> Dict[str, Any]:
    src = hit.get("_source", {})
    return {
        # Original Wazuh alert fields, preserved for traceability
        "wazuh": {
            "alert_id": hit.get("_id"),
            "timestamp": src.get("@timestamp"),
            "agent": src.get("agent"),
            "rule": src.get("rule"),
            "data": src.get("data"),
            "location": src.get("location"),
            "full_log": src.get("full_log"),
        },
        # CAAP enrichment fields (from Flask /predict)
        "caap": {
            "label": caap_result.get("label"),
            "confidence": caap_result.get("confidence"),
            "TR_score": caap_result.get("TR_score"),
            "TS_score": caap_result.get("TS_score"),
            "cluster": caap_result.get("cluster"),
            "CAS": caap_result.get("CAS"),
            "action": caap_result.get("action"),
            "explanation": caap_result.get("explanation"),
        },
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }


# --------------------------------------------------------------------------
# Main poll cycle
# --------------------------------------------------------------------------

def run_cycle(es: Elasticsearch, state: Dict[str, Any], dry_run: bool = False) -> int:
    since = state["last_timestamp"]
    hits = fetch_new_alerts(es, since)

    if not hits:
        log.info(f"No new alerts since {since}.")
        return 0

    log.info(f"Fetched {len(hits)} new alert(s) since {since}.")
    processed = 0

    for hit in hits:
        alert_id = hit.get("_id")
        src = hit.get("_source", {})
        ts = src.get("@timestamp")

        payload = wazuh_alert_to_caap_payload(hit)
        caap_result = call_predict(payload)

        if caap_result is None:
            log.warning(f"Skipping alert {alert_id} — /predict failed.")
            continue

        enriched = build_enriched_doc(hit, caap_result)

        if dry_run:
            log.info(f"[dry-run] Would index alert {alert_id} -> CAS={caap_result.get('CAS')} "
                      f"action={caap_result.get('action')}")
        else:
            try:
                index_enriched_alert(es, alert_id, enriched)
                log.info(f"Indexed enriched alert {alert_id} -> CAS={caap_result.get('CAS')} "
                         f"action={caap_result.get('action')}")
            except Exception as e:
                log.error(f"Failed to index alert {alert_id} into {CAAP_ALERTS_INDEX}: {e}")
                continue

        processed += 1
        if ts:
            state["last_timestamp"] = ts

    if not dry_run:
        save_state(state)

    return processed


def main():
    parser = argparse.ArgumentParser(description="CAAP Wazuh Consumer")
    parser.add_argument("--once", action="store_true", help="Run a single poll cycle and exit.")
    parser.add_argument("--dry-run", action="store_true", help="Predict but skip writing to Elasticsearch.")
    args = parser.parse_args()

    log.info(f"Connecting to Elasticsearch/wazuh-indexer at {ES_HOST} ...")
    es = get_es_client()

    try:
        if not es.ping():
            log.error("Could not reach Elasticsearch (ping failed). Check ES_HOST / ES_USER / ES_PASS / certs.")
            sys.exit(1)
    except ESConnectionError as e:
        log.error(f"Elasticsearch connection error: {e}")
        sys.exit(1)

    log.info("Connected. Starting consumer.")
    log.info(f"  Source index pattern : {WAZUH_ALERTS_INDEX_PATTERN}")
    log.info(f"  Target index          : {CAAP_ALERTS_INDEX}")
    log.info(f"  Flask /predict URL    : {FLASK_PREDICT_URL}")
    log.info(f"  Min rule level        : {MIN_RULE_LEVEL}")
    log.info(f"  Poll interval         : {POLL_INTERVAL_SECONDS}s")

    state = load_state()

    if args.once:
        run_cycle(es, state, dry_run=args.dry_run)
        return

    while not _shutdown:
        try:
            run_cycle(es, state, dry_run=args.dry_run)
        except Exception as e:
            log.error(f"Unexpected error in poll cycle: {e}", exc_info=True)
        for _ in range(POLL_INTERVAL_SECONDS):
            if _shutdown:
                break
            time.sleep(1)

    log.info("Consumer stopped.")


if __name__ == "__main__":
    main()
