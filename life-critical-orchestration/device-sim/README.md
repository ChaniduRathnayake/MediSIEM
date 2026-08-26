# device-sim/ — Emulated IoMT Device (Workstream A)

The "actual IoMT device" the framework is validated against. For PP2 this is a
software emulator running as Docker containers: a **monitored ICU vitals monitor**
that streams telemetry, plus the measurement harness that records its availability.
This is what makes the ≤5% accidental-disruption claim *measurable* instead of
asserted on a slide.

## Why containers (not a full VM)

Fits the existing Docker stack (Wazuh + Shuffle already run this way), resets
cleanly (`docker compose down && up`), and the real Wazuh agent installs inside the
device container just as it would on a VM. The device/logger **code is unchanged**
if a VM is later preferred for the report — only the runtime wrapper differs.

## Architecture

```
  [ vitals-monitor ] --publish--> [ mosquitto broker ] <--subscribe-- [ heartbeat-logger ]
    ICU-VENT-003                       :1883                            availability log
    + Wazuh agent  --------- reports to ---------> your Wazuh manager (host :1514/1515)
    (the "device")                                                      (the instrument)
```

The broker is deliberately **separate** from the device: when enforcement later
isolates the device, its publishes stop reaching the broker and the logger records
the gap — that gap *is* the disruption measurement. The Wazuh agent rides **inside**
the device container (not separate) so that the agent's active-response firewall
DROP actually isolates the device that's being protected.

## Components

- **vitals-monitor** — simulated ICU patient monitor (`ICU-VENT-003`). Publishes
  realistic vitals to `hospital/icu/ICU-VENT-003/vitals` once a second, **and runs a
  Wazuh agent** that reports to your manager. Monitors `/medical-data` (FIM, realtime)
  and `/var/log/auth.log` — the targets for the ransomware and brute-force scenarios.
- **mosquitto** — MQTT broker (the hospital's telemetry bus).
- **heartbeat-logger** — subscribes to the stream, detects interruptions, writes a
  continuous availability log to `data/availability.jsonl`. Pure math in
  `heartbeat-logger/availability.py`, unit-tested.

## Run it

```bash
cd device-sim
docker compose up --build
```

First build is slower now — it pulls the Wazuh agent .deb. Once up you'll see the
agent enrol, then vitals + heartbeats once a second.

## Verify A1 — the disruption signal

```bash
tail -f device-sim/data/availability.jsonl
docker compose pause vitals-monitor      # heartbeat stops
sleep 10
docker compose unpause vitals-monitor    # heartbeat resumes
```

Expect an `interruption_start` then an `interruption_end` (with downtime).

## Verify A2 — the agent is live and producing real alerts

1. In the Wazuh dashboard → **Agents**, `iomt-vitals-monitor` should appear and go
   **Active** (green) within a minute.
2. Trigger a real File Integrity event (stand-in for the ransomware scenario):
   ```bash
   docker compose exec vitals-monitor sh -c 'echo tampered >> /medical-data/record-001.csv'
   ```
   Within seconds the agent's **Integrity monitoring** view shows the file change —
   a real Wazuh alert from a real rule, replacing the hand-crafted JSON fixtures.
3. The vitals stream + heartbeat logger keep running throughout — the device does its
   clinical job *while being monitored*.

> Re-build re-enrolment: if a rebuild leaves the agent stuck "Never connected",
> remove the stale `iomt-vitals-monitor` entry in the dashboard (Agents → select →
> Remove) and `docker compose restart vitals-monitor`.

## Run the unit tests

```bash
cd device-sim/heartbeat-logger && pip install pytest && pytest
```

## Config (env vars / build args)

| Var | Default | Meaning |
|---|---|---|
| `MQTT_HOST` | `broker` | Broker hostname |
| `DEVICE_ID` | `ICU-VENT-003` | Asset ID (matches the engine's registry) |
| `PUBLISH_INTERVAL` | `1.0` | Seconds between vitals |
| `INTERRUPTION_FACTOR` | `3.0` | Gap > factor × interval ⇒ interruption |
| `WAZUH_MANAGER` (build arg) | `host.docker.internal` | Manager address the agent enrols to |

## Clinical protocol — HL7 v2 over MLLP

The device also speaks **HL7 v2.5 `ORU^R01`** (the message a real patient monitor
uses to report observations) over **MLLP** on port **2575** (the IANA-registered
HL7 port), to the `clinical-receiver` (stands in for the EHR / central monitoring
station). This is the fidelity layer that answers the panel: standardised clinical
traffic, not toy JSON — and the layer a SIEM and the engine actually act on.

Each reading is sent **both** as MQTT JSON (lightweight telemetry; the heartbeat
instrument) and as HL7 ORU^R01 (clinical messaging). Multi-protocol mirrors real
IoMT deployments. The receiver validates each message, returns a proper `MSA|AA`
ACK, and logs it to `data/hl7_received.jsonl`.

A message on the wire looks like (OBX values carry real **LOINC** codes):

```
MSH|^~\&|VITALS_MON|ICU|EHR|HOSPITAL|<ts>||ORU^R01|<id>|P|2.5
PID|1||A001^^^HOSP^MR||DOE^JANE||19700101|F
PV1|1|I|ICU^BED03^ICU-VENT-003
OBR|1|||VITALS^Vital Signs^L|||<ts>
OBX|1|NM|8867-4^Heart rate^LN||78.6|bpm|||||F
OBX|2|NM|59408-5^Oxygen saturation^LN||96.8|%|||||F
```

**Scope (honest framing):** real IoMT devices run closed, proprietary firmware that
can't be replicated. The emulator is faithful at the **network boundary** — the
standardised HL7/DICOM traffic the device exposes — because that is the only layer
a SIEM sees and the orchestration layer acts on. See ROADMAP §A2.

### Verify the HL7 path

```bash
docker compose up --build
# device logs show:  ... | HL7 ICU-VENT-003-N -> ACK AA
# receiver logs show: [receiver] ORU^R01 ... -> ACK AA
tail -f device-sim/data/hl7_received.jsonl   # the clinical-traffic record
```

## Next (Workstream B)

Wire the real ingest path: drive real activity (SSH brute-force, mass file changes
in `/medical-data`) → real Wazuh rules fire → Wazuh integrator POSTs to the
enrichment shim → engine `/decide`. The hand-crafted `data/sample-wazuh-alerts/`
fixtures retire as the primary demo path.
