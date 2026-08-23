# Gets real alerts into the dashboard without a live capture: reads real rows
# from ai_server/data/test/*.csv (held-out CICIoT2023-schema test split),
# feeds them through Flask /predict, and indexes results into the same
# `caap-alerts` index flow_consumer.py writes to — genuine model output,
# just replayed rather than captured off the wire. Defaults to the
# WAZUH_INDEXER_*/CAAP_AI_URL values in backend/.env; override with flags.
# Usage: python ml-pipeline/replay_test_flows.py [--count 300 --min-delay 0.5 --max-delay 2.0]

import argparse
import csv
import itertools
import json
import os
import random
import time
from datetime import datetime, timezone

import requests

requests.packages.urllib3.disable_warnings()

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)  # .../ml-pipeline -> repo root
DATA_DIR = os.path.join(REPO_ROOT, "ai_server", "data", "test")
ENV_PATH = os.path.join(REPO_ROOT, "backend", ".env")
DEVICE_MAP_PATH = os.path.join(SCRIPT_DIR, "device_map.json")

# category -> (filename, relative weight in the replay mix). Benign weighted
# heaviest so attacks stand out against a realistic baseline instead of the
# dashboard being wall-to-wall CRITICAL.
CATEGORY_FILES = {
    "Benign": ("Benign_test.pcap.csv", 6),
    "ARP_Spoofing": ("ARP_Spoofing_test.pcap.csv", 1),
    "Recon-Port_Scan": ("Recon-Port_Scan_test.pcap.csv", 1),
    "Recon-OS_Scan": ("Recon-OS_Scan_test.pcap.csv", 1),
    "TCP_IP-DoS-SYN": ("TCP_IP-DoS-SYN_test.pcap.csv", 2),
    "TCP_IP-DDoS-UDP1": ("TCP_IP-DDoS-UDP1_test.pcap.csv", 1),
    "MQTT-DDoS-Connect_Flood": ("MQTT-DDoS-Connect_Flood_test.pcap.csv", 1),
}
ROWS_PER_FILE = 500  # cap how much of each (huge) CSV we load into memory


def read_env_defaults():
    values = {}
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                values[key.strip()] = val.strip()
    return values


def load_category_rows(category: str, filename: str) -> list:
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        print(f"[replay] WARNING: {path} not found, skipping category {category!r}")
        return []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(itertools.islice(reader, ROWS_PER_FILE))
    print(f"[replay] loaded {len(rows)} rows for {category!r} from {filename}")
    return rows


def to_numeric_payload(row: dict) -> dict:
    payload = {}
    for k, v in row.items():
        try:
            payload[k] = float(v)
        except (TypeError, ValueError):
            payload[k] = 0.0
    return payload


def load_devices():
    with open(DEVICE_MAP_PATH, encoding="utf-8") as f:
        raw = json.load(f)
    return [
        {"ip": ip, **meta}
        for ip, meta in raw.items()
        if not ip.startswith("_")
    ]


def main():
    env = read_env_defaults()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--caap-url", default=env.get("CAAP_AI_URL", "http://localhost:5001"))
    parser.add_argument("--indexer-url", default=env.get("WAZUH_INDEXER_URL", "https://localhost:9200"))
    parser.add_argument("--indexer-user", default=env.get("WAZUH_INDEXER_USER", "admin"))
    parser.add_argument("--indexer-pass", default=env.get("WAZUH_INDEXER_PASS", "changeme"))
    parser.add_argument("--index-name", default=env.get("WAZUH_INDEXER_INDEX", "caap-alerts"))
    parser.add_argument("--count", type=int, default=200, help="Total rows to replay (0 = run forever)")
    parser.add_argument("--min-delay", type=float, default=1.0, help="Min seconds between rows")
    parser.add_argument("--max-delay", type=float, default=3.0, help="Max seconds between rows")
    args = parser.parse_args()

    print(f"[replay] CAAP AI server: {args.caap_url}")
    print(f"[replay] Indexer: {args.indexer_url} -> index {args.index_name!r}")

    categories = {cat: load_category_rows(cat, fname) for cat, (fname, _) in CATEGORY_FILES.items()}
    categories = {cat: rows for cat, rows in categories.items() if rows}
    if not categories:
        raise SystemExit("[replay] No category data loaded — check ai_server/data/test/ exists.")

    weights = [CATEGORY_FILES[cat][1] for cat in categories]
    devices = load_devices()
    if not devices:
        raise SystemExit("[replay] device_map.json has no real devices (only _default/_comment).")

    session = requests.Session()
    indexer_auth = (args.indexer_user, args.indexer_pass)

    sent = 0
    attempts = 0
    consecutive_indexer_failures = 0
    device_cycle = itertools.cycle(devices)
    try:
        while args.count == 0 or attempts < args.count:
            attempts += 1
            category = random.choices(list(categories.keys()), weights=weights, k=1)[0]
            row = random.choice(categories[category])
            device = next(device_cycle)

            payload = to_numeric_payload(row)
            payload["device_type"] = device["device_type"]
            payload["department"] = device["department"]
            payload["hour_of_day"] = datetime.now().hour
            payload["cve_known_exploited"] = False

            try:
                res = session.post(f"{args.caap_url}/predict", json=payload, timeout=15)
                res.raise_for_status()
                enrichment = res.json()
            except Exception as exc:
                print(f"[replay] /predict call failed ({category}): {exc}", flush=True)
                time.sleep(random.uniform(args.min_delay, args.max_delay))
                continue

            doc = {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "src_ip": device["ip"],
                "agent": {"name": device["device_type"], "ip": device["ip"], "department": device["department"]},
                "replay_source_category": category,  # not fed to the model — just for eyeballing the replay mix
                **enrichment,
            }

            try:
                res = session.post(
                    f"{args.indexer_url}/{args.index_name}/_doc",
                    json=doc, auth=indexer_auth, verify=False, timeout=10,
                )
                res.raise_for_status()
                sent += 1
                consecutive_indexer_failures = 0
                print(
                    f"[replay] #{sent} {category:<24} device={device['device_type']:<16} "
                    f"label={doc.get('label')} CAS={doc.get('CAS')} action={doc.get('action')}",
                    flush=True,
                )
            except Exception as exc:
                body = getattr(exc, "response", None)
                body_text = body.text[:300] if body is not None else ""
                print(f"[replay] failed to index into {args.index_name}: {exc} {body_text}", flush=True)
                consecutive_indexer_failures += 1
                if consecutive_indexer_failures >= 5:
                    raise SystemExit(
                        f"[replay] {consecutive_indexer_failures} consecutive indexer failures — "
                        "stopping instead of looping silently. Check WAZUH_INDEXER_URL/USER/PASS and "
                        "that the indexer is reachable."
                    )

            time.sleep(random.uniform(args.min_delay, args.max_delay))
    except KeyboardInterrupt:
        print(f"\n[replay] stopped after {sent}/{attempts} alerts.", flush=True)

    print(f"[replay] done — {sent}/{attempts} alerts indexed.", flush=True)


if __name__ == "__main__":
    main()
