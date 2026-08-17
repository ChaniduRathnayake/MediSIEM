# PP2 live demo script — real-time attack simulation on the hospital lab network

Presentation-facing companion to [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md), which has the
full technical setup. This doc is the *what to say, in what order, with a
fallback if it breaks* version, built around the topology you've already
validated (see `MediSIEM_Attack_Simulation_Report.docx` — the SSH brute-force
run from 2026-08-11):

| Role | Machine | IP | Clinical identity (`device_map.json`) |
|---|---|---|---|
| Host — Wazuh manager/indexer, Flask AI server, Node backend, React dashboard | Windows (ChaniduB) | `192.168.16.1` | — (SOC/ops side, not a "device") |
| Victim 1 | Ubuntu-VM | `192.168.16.132` | **Infusion Pump — ICU** |
| Victim 2 | RHEL_8 | `192.168.16.134` | **Cardiac Monitor — Cardiology** |
| Attacker | (your choice — a third VM, or the Windows host as you did in the docx test) | — | — |

Framing this as "an attacker pivoted into the ICU subnet and is now hitting an
infusion pump" instead of "a VM at .132" is what makes the demo land as a
*medical-sector* SIEM story instead of a generic network security demo — say
the device name, not the IP, every time you narrate.

## Before presentation day

- [ ] Rehearse the full sequence once, start to finish, on the actual VMs —
      not just read this doc. Wazuh agent connectivity and VirtualBox
      host-only networking are the two things most likely to have drifted
      since your last successful run.
- [ ] Confirm `ai_server/models/*.pkl` exist and are current (`python
      train.py` if not — do this *before* the day, it takes a while).
- [ ] Confirm Windows Firewall allows inbound `5001` (Flask) and `9200`
      (Indexer) from the VM subnet (see DEMO_RUNBOOK.md step 1).
- [ ] **Record a screen capture of one full successful run** (attack launch →
      Wazuh alert → CAS score appearing on the dashboard) as a fallback video.
      Live network demos in front of an audience fail more often than solo
      runs — projector Wi-Fi, VM network mode resetting, a forgotten `sudo`.
      Having 90 seconds of screen recording queued up means a hiccup costs
      you a sentence ("let me show you a capture from last night's run
      instead"), not the demo.
- [ ] Pre-open and log into the dashboard tab and a Wazuh browser tab so you
      aren't typing credentials live.
- [ ] Have `MediSIEM_Attack_Simulation_Report.docx` open in a second window —
      it's your receipts if someone asks "did that actually fire a rule."

## Run order (during the presentation)

**1. Host — bring up the pipeline** (do this *before* you're on stage, not
live — it takes ~30s and produces boring terminal spam):
```powershell
powershell -ExecutionPolicy Bypass -File .\start-caap-pipeline.ps1
```

**2. Victim (say which one you're using out loud) — start capture + scoring.**
Talking point while this starts: *"This VM is standing in for an ICU infusion
pump — I've tagged its IP in our device inventory the same way a hospital
would register a real pump against its asset management system."*
```bash
sudo ./run_victim_capture.sh <iface> 192.168.16.1 admin <WAZUH_INDEXER_PASS>
```

**3. Attacker — launch the scenario.** `all` gives you a narrative arc (benign
→ recon → DoS); a single scenario is punchier if your slot is short.
```bash
sudo ./run_attack.sh 192.168.16.132 port_scan
```
Talking point: *"This is a reconnaissance scan — the kind of first move an
attacker makes after landing on a hospital's flat clinical network, looking
for what's reachable before deciding what to hit."*

**4. Switch to the dashboard.** Point out, side by side:
- **Wazuh tab** — the raw signature hit (e.g. repeated auth failures / a scan
  pattern). *"This is what every SIEM already gives you — a severity number
  with no idea it just found a live ICU device."*
- **CAAP live feed** — the same event, now carrying a Clinical Alert Score.
  *"Same detection, but scored knowing this is an infusion pump, in the ICU,
  and it's currently [day/night] — that's what pushes it to `Immediate`
  instead of sitting in a queue behind a hundred lower-stakes alerts."*

## If something doesn't fire live

Most likely failure and the one-line fix, so you don't stall mid-sentence:

| Symptom | Likely cause | Say / do |
|---|---|---|
| Nothing appears on CAAP feed after ~15s | `flow_consumer.py` can't reach Flask/Indexer (firewall) | Fall back to the recorded clip; mention it's a network-permission issue, not a detection failure |
| Wazuh tab shows the alert but CAAP doesn't | Index misconfig / `flow_consumer.py` not running on this VM | Same as above — pivot to "here's the raw HIDS layer working, and here's a capture of the full clinically-scored path" |
| Dashboard login fails | Session expired mid-setup | Have the tab already logged in before you start talking (see checklist) |

Framing a fallback as "here's the raw layer live, here's the full pipeline
from last night" is a completely normal thing to say in a systems demo and
costs you nothing credibility-wise — it's much better than silently retrying
commands in front of the room.

## Anticipated questions

- **"Is this real attack traffic or canned data?"** — Real: `attack_simulator.py`
  sends genuine packets (SYN scans, spoofed ARP, floods) over an isolated
  VirtualBox/VMware host-only network; `live_feature_extractor.py` captures
  them live and reconstructs the actual 45-column feature vector the model
  was trained on — nothing is replayed from a static file in this path (that
  exists too, as `replay_test_flows.py`, for offline testing).
- **"Why not just use Wazuh's built-in severity?"** — Because a `level 10`
  brute-force alert means the same thing whether it's against an idle admin
  laptop or a ventilator's control interface. CAAP adds device criticality,
  exploitation context, and time-of-day on top of that base severity —
  see `CAAP_Weight_Justification.html` for the full weighting rationale.
- **"Has this been validated against real Wazuh rules, not just simulated?"**
  — Yes: point to `MediSIEM_Attack_Simulation_Report.docx` — an SSH
  brute-force run against these same two VMs fired Wazuh rules 5712 (level
  10) and 5551 (level 10) with a full supporting audit trail underneath.
- **"What happens outside the lab — how would this reach a real hospital
  network?"** — It wouldn't as-is; `ml-pipeline` is explicitly gated to an
  isolated lab network (see the warning at the top of `attack_simulator.py`).
  The point of the simulation is validating the detection→scoring pipeline
  end-to-end before it's ever pointed at production traffic.

## Cleanup

Ctrl+C on both VM scripts. Host windows from `start-caap-pipeline.ps1` can
stay up for follow-up questions.
