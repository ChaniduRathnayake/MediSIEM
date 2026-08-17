# The live CAAP enrichment loop: watches CICFlowMeter's flow-output CSVs for
# new rows, sends each to the CAAP Flask AI server (real RF + IF + K-Means),
# and indexes the result into OpenSearch's "caap-alerts" index — the Node
# backend polls that index and pushes to the dashboard over Socket.IO.
# Requires: pip install pandas requests watchdog
# Usage: python flow_consumer.py --flow-dir ./cicflowmeter_output --caap-url http://localhost:5001 \
#     --indexer-url https://localhost:9200 --indexer-user admin --indexer-pass changeme

import argparse
import json
import os
import time
from datetime import datetime, timezone

import pandas as pd
import requests
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

requests.packages.urllib3.disable_warnings()  # Wazuh Indexer's self-signed cert in dev

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEVICE_MAP_PATH = os.path.join(SCRIPT_DIR, "device_map.json")

with open(DEVICE_MAP_PATH) as f:
    DEVICE_MAP = json.load(f)

# Column names CICFlowMeter typically uses for source IP — check yours matches one of these.
SRC_IP_CANDIDATES = ["Src IP", "Source IP", "src_ip"]
DST_PORT_CANDIDATES = ["Dst Port", "Destination Port", "dst_port"]


def lookup_device(src_ip: str) -> dict:
    return DEVICE_MAP.get(src_ip, DEVICE_MAP.get("_default", {"device_type": "Unknown Device", "department": "General"}))


def find_column(row: dict, candidates):
    for c in candidates:
        if c in row:
            return c
    return None


class FlowFileHandler(FileSystemEventHandler):
    """Tracks read offsets per file and processes only newly appended rows."""

    def __init__(self, caap_url: str, indexer_url: str, indexer_auth, index_name: str):
        self.caap_url = caap_url
        self.indexer_url = indexer_url
        self.indexer_auth = indexer_auth
        self.index_name = index_name
        self._row_counts = {}

    def on_modified(self, event):
        if event.is_directory or not event.src_path.endswith(".csv"):
            return
        self._process_new_rows(event.src_path)

    def _process_new_rows(self, path: str):
        try:
            df = pd.read_csv(path, low_memory=False)
        except Exception as exc:
            print(f"[flow_consumer] Could not read {path} yet: {exc}")
            return

        df.columns = df.columns.str.strip()
        already_seen = self._row_counts.get(path, 0)
        new_rows = df.iloc[already_seen:]
        if new_rows.empty:
            return

        print(f"[flow_consumer] {len(new_rows)} new flow row(s) in {os.path.basename(path)}")
        for _, row in new_rows.iterrows():
            self._handle_row(row.to_dict())
        self._row_counts[path] = len(df)

    def _handle_row(self, row: dict):
        src_ip_col = find_column(row, SRC_IP_CANDIDATES)
        src_ip = str(row.get(src_ip_col, "")) if src_ip_col else ""
        device = lookup_device(src_ip)

        # Build the /predict payload: every numeric flow column, as-is, plus clinical metadata.
        payload = {k: v for k, v in row.items() if isinstance(v, (int, float)) and not pd.isna(v)}
        payload["device_type"] = device["device_type"]
        payload["department"] = device["department"]
        payload["hour_of_day"] = datetime.now().hour
        payload["cve_known_exploited"] = False  # wire up a real CVE feed here if/when available

        try:
            # SHAP explanation over the full Random Forest genuinely takes
            # ~20s per call on typical dev hardware — 5s silently dropped
            # every live prediction on timeout with no visible error (Python
            # stdout is block-buffered under systemd, so even the printed
            # failure went unseen). Give it real headroom.
            res = requests.post(f"{self.caap_url}/predict", json=payload, timeout=30)
            res.raise_for_status()
            enrichment = res.json()
        except Exception as exc:
            print(f"[flow_consumer] CAAP /predict call failed: {exc}")
            return

        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": src_ip,
            "agent": {"name": device["device_type"], "ip": src_ip, "department": device["department"]},
            "flow": row,
            **enrichment,
        }

        self._index_doc(doc)

    def _index_doc(self, doc: dict):
        try:
            res = requests.post(
                f"{self.indexer_url}/{self.index_name}/_doc",
                json=doc,
                auth=self.indexer_auth,
                verify=False,
                timeout=5,
            )
            res.raise_for_status()
            print(f"[flow_consumer] Indexed alert — label={doc.get('label')} CAS={doc.get('CAS')} action={doc.get('action')}")
        except Exception as exc:
            print(f"[flow_consumer] Failed to index into {self.index_name}: {exc}")


def main():
    parser = argparse.ArgumentParser(description="CAAP live flow consumer")
    parser.add_argument("--flow-dir", required=True, help="Directory CICFlowMeter writes live CSV output to")
    parser.add_argument("--caap-url", default="http://localhost:5001")
    parser.add_argument("--indexer-url", default="https://localhost:9200")
    parser.add_argument("--indexer-user", default="admin")
    parser.add_argument("--indexer-pass", default="changeme")
    parser.add_argument("--index-name", default="caap-alerts")
    args = parser.parse_args()

    os.makedirs(args.flow_dir, exist_ok=True)
    handler = FlowFileHandler(
        caap_url=args.caap_url,
        indexer_url=args.indexer_url,
        indexer_auth=(args.indexer_user, args.indexer_pass),
        index_name=args.index_name,
    )

    # Process any files already present before we start watching.
    for fname in os.listdir(args.flow_dir):
        if fname.endswith(".csv"):
            handler._process_new_rows(os.path.join(args.flow_dir, fname))

    observer = Observer()
    observer.schedule(handler, args.flow_dir, recursive=False)
    observer.start()
    print(f"[flow_consumer] Watching {args.flow_dir} for new CICFlowMeter output...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
