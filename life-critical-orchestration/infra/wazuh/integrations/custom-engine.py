#!/usr/bin/env python3
"""Wazuh custom integration: forward matching alerts to the enrichment shim.

Wazuh's integratord invokes this as:  custom-engine <alert_file> <api_key> <hook_url>
We read the single-alert JSON from <alert_file> and POST it to the shim's
/wazuh-alert (<hook_url>). Stdlib only (urllib) so it runs under the manager's
bundled Python with no extra packages. Errors are logged, never raised, so a
down shim never disturbs the SIEM.
"""
import json
import sys
import urllib.request
from datetime import datetime

LOG = "/var/ossec/logs/custom-engine.log"


def log(msg):
    try:
        with open(LOG, "a") as f:
            f.write(f"{datetime.now().isoformat()} {msg}\n")
    except Exception:
        pass


def main():
    if len(sys.argv) < 3:
        log(f"too few args: {sys.argv}")
        return
    alert_file = sys.argv[1]
    hook_url = sys.argv[3] if len(sys.argv) > 3 else sys.argv[2]
    try:
        with open(alert_file) as f:
            alert = json.load(f)
    except Exception as e:
        log(f"cannot read alert file {alert_file}: {e}")
        return
    req = urllib.request.Request(
        hook_url, data=json.dumps(alert).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            log(f"posted alert {alert.get('id', '?')} -> {hook_url} [{resp.status}]")
    except Exception as e:
        log(f"error posting to {hook_url}: {e}")


if __name__ == "__main__":
    main()
