# Wazuh → Enrichment Shim Integration

This document describes how to wire a real Wazuh manager to the enrichment shim.
For PP1 we stub this path (see `scripts/post_wazuh_alert.sh`); the configuration
below is the production-shaped version we'll demonstrate live in PP2.

## Architecture

```
  Wazuh Manager  ──(integrator)──>  Enrichment Shim  ──(HTTP)──>  Decision Engine
  (rules fire)                       (asset registry)             (classify + audit)
```

Wazuh's built-in **integrator** module forwards alerts that match a filter to an
external HTTP endpoint. We point it at the enrichment shim's `/wazuh-alert`
endpoint. The shim does the rest.

## ossec.conf snippet

Add this block inside `<ossec_config>` on the Wazuh manager:

```xml
<integration>
  <name>custom-life-critical</name>
  <hook_url>http://shim:8001/wazuh-alert</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

Notes on each field:

- `name` — must start with `custom-` for a user-defined integration.
- `hook_url` — where to POST the alert. In Docker this should be the shim
  service name + port; outside Docker, `http://localhost:8001/wazuh-alert`.
- `level` — minimum Wazuh rule level to forward. Level 7 forwards everything
  in the medium-and-above range; tune per environment.
- `alert_format` — the shim expects native Wazuh JSON.

## Custom integration script (optional)

If you want logic before forwarding (e.g. drop noisy rule IDs), drop a script
at `/var/ossec/integrations/custom-life-critical` on the manager. Wazuh runs
it with the alert path as `$1` and the API key as `$2`. The script can
read the JSON, decide whether to POST, and exit.

For PP1 we don't need this — we forward directly from `<integration>` and let
the shim's registry handle "is this asset known" filtering.

## Restart Wazuh after config changes

```bash
docker compose -f infra/wazuh-docker/single-node/docker-compose.yml restart wazuh.manager
```

Watch the manager log to confirm the integrator loaded:

```bash
docker logs wazuh.manager 2>&1 | grep -i integrator
```

## Triggering a real alert (for PP2)

Once configured, any rule that fires at level ≥ 7 produces a Wazuh alert
that gets POSTed to the shim. Easiest way to test the live path:

- Stand up a Wazuh agent on a VM named `rad-linac-01.hospital.local` (or
  whatever hostname matches your `enrichment/data/asset_registry.json`).
- SSH-fail a few times to trigger rule 5712 (SSH brute force, level 10).
- Watch the dashboard's audit timeline — the alert should appear within
  a few seconds of the rule firing.
