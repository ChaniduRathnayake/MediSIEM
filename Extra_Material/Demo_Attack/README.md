# Demo_Attack — lab attack simulation + demo runbooks

Everything needed to generate simulated attack traffic against the lab VMs
for a CAAP demo, plus the runbooks for staging one. The live capture/scoring
side of the pipeline (`flow_consumer.py`, `live_feature_extractor.py`,
`device_map.json`, `run_victim_capture.sh`) lives separately in
[../../ml-pipeline/](../../ml-pipeline) at the repo root — see its README for
how that side works. This folder is the *attacker*-side tooling only.

**RUN ONLY IN AN ISOLATED LAB/VM NETWORK YOU OWN.** Spoofed ARP / SYN-flood /
port-scan traffic on any other network is illegal without explicit
authorization.

## What's here

| File | What it is |
|---|---|
| `attack_simulator.py` / `run_attack.sh` | Single-target attack tool — `--target <ip>`, one scenario or `all` at a time. The original tool this folder started from. |
| `multi_target_attack_simulator.py` / `run_multi_attack.sh` | Multi-target version (below) — sweeps every VM device in one run instead of one `--target` at a time, and saves a log + JSON summary as demo/thesis evidence. |
| `DEMO_RUNBOOK.md` | Full step-by-step: bring up the pipeline, start victim capture, launch the attack, read the dashboard. |
| `PP2_DEMO_SCRIPT.md` | Presentation-facing script — what to say, in what order, with fallbacks if something doesn't fire live. |

## multi_target_attack_simulator.py

Sweeps *every* VM device on the lab network (not just one `--target`) through
the same ARP-spoof / port-scan / SYN-flood / benign scenarios as
`attack_simulator.py` (imported from, not duplicated — both files live here
together), pausing between targets, and saves a timestamped console log +
JSON summary into this folder — the "receipts" for a demo run or thesis
writeup, the same idea as `MediSIEM_Attack_Simulation_Report.docx`.

### Requires

Root/Administrator + scapy: `pip install -r ../../ml-pipeline/requirements.txt`
(or just `pip install scapy`).

### Target sources — pick one

| Flag | Behavior |
|---|---|
| *(none)* | Every real IP key in [../../ml-pipeline/device_map.json](../../ml-pipeline/device_map.json) — this repo's documented lab VM inventory (currently the Ubuntu-VM and RHEL_8 boxes from `PP2_DEMO_SCRIPT.md`). |
| `--device-map <path>` | Same, but reads a different device-map file. |
| `--range <CIDR>` | Live ARP sweep, e.g. `--range 192.168.16.0/24` — attacks whatever VMs actually answer, not just what's on file. A sweep that finds 20+ live hosts needs `--yes` to proceed, as a guard against accidentally targeting a shared/non-lab network. |
| `--targets ip1,ip2,...` | Explicit list. |

The Windows host IP (`192.168.16.1` — running the Wazuh stack/Flask/backend/
dashboard) is excluded by default in every mode, per `DEMO_RUNBOOK.md`:
*"don't run the attack against the Windows host itself, it's busy serving the
pipeline."* Add more exclusions with `--exclude ip1,ip2`.

### Usage

```bash
# every device in device_map.json, full scenario cycle per device
sudo python multi_target_attack_simulator.py --scenario all

# live sweep of the lab subnet, port scan only
sudo python multi_target_attack_simulator.py --range 192.168.16.0/24 --scenario port_scan

# just the two documented demo VMs
sudo python multi_target_attack_simulator.py --targets 192.168.16.132,192.168.16.134
```

Or via the bash wrapper on the attacker VM:

```bash
sudo ./run_multi_attack.sh [same flags]
```

On Windows (as Administrator), run the Python script directly — same as
`attack_simulator.py`, raw sockets need Npcap installed (see
`../../ml-pipeline/README.md`).

### Before the demo

Bring up the pipeline and start capture on whichever VM(s) you're pointing
this at first — see [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md). This script only
generates the attack side; `live_feature_extractor.py` + `flow_consumer.py`
on the victim VM(s) (in `ml-pipeline/`) is what turns that traffic into a CAS
score on the dashboard.

### Output

Each run writes, into this folder:

- `demo_run_<timestamp>.log` — full console output (every scenario's own
  print lines, teed to file) with a `[HH:MM:SS]` narrative stamp at each
  target/scenario transition.
- `demo_run_<timestamp>_summary.json` — machine-readable summary: scenario,
  full target list, per-target start/end time and status (`ok`/`error`).

Use `--out-dir <path>` to save elsewhere instead.

### Flags reference

- `--scenario {arp_spoof,port_scan,syn_flood,benign,all}` (default `all`)
- `--gateway <ip>` — gateway to spoof for `arp_spoof` (default `192.168.16.1`)
- `--duration <seconds>` — length of time-based scenarios (default 15)
- `--target-delay <seconds>` — pause between targets (default 5)
- `--exclude ip1,ip2` — extra IPs to skip
- `--out-dir <path>` — where to save the log/summary (default: this folder)
- `--yes` — skip the confirmation guard on a `--range` sweep finding 20+ hosts
