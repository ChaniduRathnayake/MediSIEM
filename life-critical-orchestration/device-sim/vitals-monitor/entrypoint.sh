#!/bin/sh
# Start the Wazuh agent (auto-enrols to the manager on first start), then hand
# off to the vitals publisher in the foreground. The agent runs as a background
# service alongside the device's clinical service -- exactly like a real endpoint.
set -e

echo "[entrypoint] starting Wazuh agent (enrolling to manager)..."
/var/ossec/bin/wazuh-control start || echo "[entrypoint] agent start returned non-zero -- continuing so the device still runs"

echo "[entrypoint] starting vitals publisher..."
exec python -u publisher.py
