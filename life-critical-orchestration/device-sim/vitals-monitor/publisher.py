"""Simulated ICU patient monitor (the emulated IoMT device).

Each second it produces one vitals reading and emits it two ways:
  - MQTT JSON  -> the lightweight telemetry bus (heartbeat-logger measures this)
  - HL7 ORU^R01 over MLLP -> the clinical receiver (standards-compliant clinical
    traffic; the layer a SIEM and the orchestration engine act on)

Being multi-protocol mirrors real IoMT deployments. generate_vitals() is pure so
it can be unit-tested without a broker.
"""
import json
import os
import random
import time
from datetime import datetime, timezone

import paho.mqtt.client as mqtt

import hl7_sender

MQTT_HOST = os.getenv("MQTT_HOST", "broker")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
# Connection-liveness detection. When a life-critical device is moved between
# network segments (e.g. quarantined onto a clinical-only VLAN), its existing
# TCP socket to the broker's old address goes silent with no RST. paho only
# notices after ~1.5x the keepalive, so a short keepalive = fast reconnect to
# the (still-reachable) broker = minimal clinical-telemetry gap.
MQTT_KEEPALIVE = int(os.getenv("MQTT_KEEPALIVE", "3"))
DEVICE_ID = os.getenv("DEVICE_ID", "ICU-VENT-003")
PUBLISH_INTERVAL = float(os.getenv("PUBLISH_INTERVAL", "1.0"))
TOPIC = f"hospital/icu/{DEVICE_ID}/vitals"

HL7_ENABLED = os.getenv("HL7_ENABLED", "true").lower() == "true"
HL7_HOST = os.getenv("HL7_HOST", "clinical-receiver")
HL7_PORT = int(os.getenv("HL7_PORT", "2575"))


def _drift(value, step, lo, hi):
    value += random.uniform(-step, step)
    return max(lo, min(hi, value))


def generate_vitals(state):
    """One realistic reading, drifting gently from the mutable `state` dict."""
    state["heart_rate"] = _drift(state["heart_rate"], 0.8, 50, 130)
    state["spo2"] = _drift(state["spo2"], 0.2, 88, 100)
    state["resp_rate"] = _drift(state["resp_rate"], 0.4, 8, 30)
    state["systolic"] = _drift(state["systolic"], 1.0, 90, 160)
    state["diastolic"] = _drift(state["diastolic"], 0.7, 55, 100)
    return {
        "device_id": DEVICE_ID,
        "device_type": "patient_monitor",
        "department": "ICU",
        "ts": datetime.now(timezone.utc).isoformat(),
        "epoch": time.time(),
        "heart_rate_bpm": round(state["heart_rate"], 1),
        "spo2_pct": round(state["spo2"], 1),
        "resp_rate_bpm": round(state["resp_rate"], 1),
        "bp_mmhg": f"{round(state['systolic'])}/{round(state['diastolic'])}",
    }


def main():
    state = {"heart_rate": 78.0, "spo2": 97.0, "resp_rate": 16.0,
             "systolic": 118.0, "diastolic": 76.0}
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"device-{DEVICE_ID}")
    # Tight auto-reconnect: after a segment move, re-establish telemetry fast.
    client.reconnect_delay_set(min_delay=1, max_delay=2)
    client.on_connect = lambda c, u, f, rc, p: print(
        f"[monitor] MQTT connected rc={rc} -> publishing {TOPIC}", flush=True)
    while True:
        try:
            client.connect(MQTT_HOST, MQTT_PORT, keepalive=MQTT_KEEPALIVE)
            break
        except Exception as e:
            print(f"[monitor] broker not ready ({e}); retrying...", flush=True)
            time.sleep(2)
    client.loop_start()
    print(f"[monitor] {DEVICE_ID} streaming every {PUBLISH_INTERVAL}s "
          f"(MQTT + {'HL7' if HL7_ENABLED else 'no HL7'})", flush=True)
    try:
        while True:
            v = generate_vitals(state)
            client.publish(TOPIC, json.dumps(v), qos=0)
            if HL7_ENABLED:
                ack, mid = hl7_sender.send(v, HL7_HOST, HL7_PORT)
                hl7_status = "ACK AA" if ack and "MSA|AA" in ack else "no ACK (receiver down?)"
                print(f"[monitor] HR={v['heart_rate_bpm']} SpO2={v['spo2_pct']} "
                      f"BP={v['bp_mmhg']} | HL7 {mid} -> {hl7_status}", flush=True)
            else:
                print(f"[monitor] HR={v['heart_rate_bpm']} SpO2={v['spo2_pct']} "
                      f"BP={v['bp_mmhg']}", flush=True)
            time.sleep(PUBLISH_INTERVAL)
    except KeyboardInterrupt:
        pass
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
