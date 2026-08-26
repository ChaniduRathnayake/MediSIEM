# Scripts

Helper scripts for development, testing, and demos.

| Script | Purpose |
|--------|---------|
| `post_wazuh_alert.sh` | Fire a single hand-crafted Wazuh alert through the pipe (shim → engine → audit log → dashboard). Interactive picker if invoked with no argument. |
| `run_full_demo.sh` | One-shot demo runner: preflight-checks all three services, then fires every sample Wazuh alert in sequence with paced pauses, summarises the result. |

## Quick reference

Single alert:

```bash
./scripts/post_wazuh_alert.sh data/sample-wazuh-alerts/01-tier3-linac-ransomware.json
```

Full demo (all 5 samples in sequence):

```bash
./scripts/run_full_demo.sh
./scripts/run_full_demo.sh --pause 5    # custom inter-alert pause
./scripts/run_full_demo.sh --no-pause   # fire as fast as possible
```

Both scripts are designed to be run from the repo root.
