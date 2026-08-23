# Live demo runbook — real agents + simulated attack → CAS score on the dashboard

Tailored to a 3-machine setup: **Windows PC** (host — Docker Wazuh stack,
Flask AI server, Node backend, React dashboard) + **Ubuntu VM** and
**RedHat VM** (both already running a Wazuh agent). See
[../../ml-pipeline/README.md](../../ml-pipeline/README.md) for how the
capture/scoring pipeline works and why there's no CICFlowMeter step; this doc
is just "what to type, in what order" for that exact topology. The live
capture components (`flow_consumer.py`, `live_feature_extractor.py`,
`device_map.json`, `run_victim_capture.sh`) live in `ml-pipeline/` at the repo
root; the attack tooling used in step 3 (`attack_simulator.py`,
`run_attack.sh`) lives right here in `Extra_Material/Demo_Attack/` alongside
this doc — see [README.md](README.md) for the multi-target variant that
attacks every VM device in one run instead of a single `--target`.

Two dashboard surfaces will both be doing something during the demo:

- **SOC / CAAP live feed** — real ML-scored alerts (CAS 0–10), fed by this
  pipeline. This is the one you're setting up here.
- **Wazuh browser tab** (Agents/Alerts/SCA/FIM) — raw HIDS detections from
  the victim's own Wazuh agent (e.g. repeated SSH auth failures during the
  port scan). This needs no extra setup — it's already live once the agent
  is connected. Worth pointing out to panelists side-by-side: "here's the
  raw signature hit, here's the same activity clinically scored."

## Roles

- **Victim** — the VM standing in for a clinical device. Recommend the
  **Ubuntu VM** (simpler `ip`/`scapy` capture, no special config).
- **Attacker** — the other VM. Recommend the **RedHat VM**.
  (Either way works — just don't run the attack against the Windows host
  itself, it's busy serving the pipeline.)

## 0. Give the victim a clinical identity (for a CAS score worth showing)

Without this, flows from an unrecognized IP fall back to `Unknown
Device`/`General` in
[../../ml-pipeline/device_map.json](../../ml-pipeline/device_map.json) — CAS
still computes, just with a flat clinical-criticality term. On the **Windows
host**, open `ml-pipeline/device_map.json` and add the Ubuntu VM's real IP
(find it on the VM with `ip -4 addr show`):

```json
{
  "192.168.56.XX": { "device_type": "ICU Ventilator", "department": "ICU" },
  "_default": { "device_type": "Unknown Device", "department": "General" }
}
```

`flow_consumer.py` loads this file **once at startup** (`DEVICE_MAP` in
`flow_consumer.py`), not per-row — so edit it *before* step 2 below, or
restart `run_victim_capture.sh` afterward if you change it mid-demo.

## 1. Windows host — bring up the pipeline

```powershell
powershell -ExecutionPolicy Bypass -File .\start-caap-pipeline.ps1
```

Confirms the Wazuh Indexer is reachable, then starts the Flask AI server
(:5001), Node backend (:5000), and React dashboard (:5173) each in their own
window. Leave it printing your host-only/LAN IP — you'll need it in step 2.

**Firewall check** (do this once, ahead of the actual demo): Windows
Firewall must allow inbound TCP on **5001** (Flask) and **9200** (Wazuh
Indexer) from the VM subnet, since the VMs are calling in as separate
network hosts now, not `localhost`. Quickest check from the Ubuntu VM:

```bash
curl -sk -u admin:<WAZUH_INDEXER_PASS> https://<windows-host-ip>:9200
curl -s http://<windows-host-ip>:5001/health
```

Both should respond before you start the capture — if either hangs, it's
the firewall, not the script.

## 2. Ubuntu VM (victim) — start capture + scoring

Get `ml-pipeline/` onto the VM (git clone the repo, or
`scp -r "ml-pipeline" user@ubuntu-vm:~/`), then:

```bash
cd "ml-pipeline"    # or wherever you scp'd it
pip3 install -r requirements.txt
ip -brief link                                    # find your interface name, e.g. enp0s3
chmod +x run_victim_capture.sh
sudo ./run_victim_capture.sh enp0s3 <windows-host-ip> admin <WAZUH_INDEXER_PASS>
```

(`<WAZUH_INDEXER_PASS>` is whatever `WAZUH_INDEXER_PASS` is set to in
`backend/.env` on the host.) Leave this running — it's your capture +
scoring process for the whole demo. No Npcap needed here; that's a
Windows-only requirement, Linux `scapy` uses libpcap directly (root is still
required for raw sockets).

## 3. RedHat VM (attacker) — launch the simulated attack

```bash
cd "Extra_Material/Demo_Attack"    # or wherever you scp'd it
pip3 install -r ../../ml-pipeline/requirements.txt   # or just: pip3 install scapy
chmod +x run_attack.sh
sudo ./run_attack.sh <ubuntu-victim-ip> all
```

To hit every VM device on the lab network in one run instead of a single
target, use `multi_target_attack_simulator.py` (or its `run_multi_attack.sh`
wrapper) in this same folder instead — see [README.md](README.md).

`all` cycles through every scenario (ARP spoof, port scan, SYN flood,
benign) — good for a "watch the CAS score rise and fall with the traffic"
narrative. For a punchier single moment, use `port_scan` or `syn_flood`
instead of `all`.

## 4. During the demo

- Open **http://\<windows-host-ip\>:5173**, log in, go to the SOC/CAAP live
  feed. Alerts should appear within a few seconds of the attack starting,
  each with a CAS score and action recommendation
  (`Immediate`/`Investigate`/`Monitor`).
- Switch to the **Wazuh browser** tab and show the same window of activity
  as raw agent alerts (SSH/auth failures etc.) — this is what makes the
  "clinically aware" pitch land: same underlying activity, two views, one
  prioritizes by CVSS-style severity alone, the other factors in device type
  + time + exploitation context.
- If nothing shows up: check the Node backend's window for
  `[alertPipeline] ⚠ ALERT ... HAS NO CAS FIELD` (index misconfigured — see
  `WAZUH_INDEXER_INDEX` in `backend/.env`, should be `caap-alerts`) or
  `[wazuhIndexerService] Index "caap-alerts" doesn't exist yet` (nothing
  indexed yet — check `flow_consumer.py`'s own terminal for errors first).

## Cleanup after the demo

Ctrl+C `run_victim_capture.sh` (kills both the extractor and consumer) and
`run_attack.sh` on their respective VMs. The host-side windows started by
`start-caap-pipeline.ps1` can stay running for a follow-up Q&A walkthrough.
