"""Heartbeat logger -- the measurement instrument.

Subscribes to the device's vitals stream and records its availability. When the
stream goes silent longer than INTERRUPTION_FACTOR x the publish interval it logs
an interruption; when it resumes it logs the recovery and the downtime. The
resulting availability log is what we aggregate into the accidental-disruption
rate during Phase 4 validation.
"""
import json
import os
import threading
import time
from datetime import datetime, timezone

import paho.mqtt.client as mqtt

MQTT_HOST = os.getenv("MQTT_HOST", "broker")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
PUBLISH_INTERVAL = float(os.getenv("PUBLISH_INTERVAL", "1.0"))
INTERRUPTION_FACTOR = float(os.getenv("INTERRUPTION_FACTOR", "3.0"))
TOPIC = os.getenv("TOPIC", "hospital/+/+/vitals")
LOG_PATH = os.getenv("LOG_PATH", "/data/availability.jsonl")
THRESHOLD = PUBLISH_INTERVAL * INTERRUPTION_FACTOR


def _write(record):
    record["ts"] = datetime.now(timezone.utc).isoformat()
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(record) + "\n")


class Monitor:
    """Tracks live up/down state of the stream and logs transitions."""

    def __init__(self):
        self.last_seen = None
        self.state = "up"
        self.down_since = None
        self.beats = 0
        self.lock = threading.Lock()

    def on_beat(self, device_id):
        now = time.time()
        with self.lock:
            self.beats += 1
            self.last_seen = now
            if self.state == "down":
                downtime = now - self.down_since
                self.state = "up"
                _write({"event": "interruption_end", "device_id": device_id,
                        "downtime_s": round(downtime, 2)})
                print(f"[logger] RECOVERED after {downtime:.1f}s down", flush=True)
            elif self.beats % 10 == 0:
                print(f"[logger] {self.beats} heartbeats ok", flush=True)

    def watch(self):
        while True:
            time.sleep(PUBLISH_INTERVAL / 2)
            with self.lock:
                if self.last_seen is None:
                    continue
                silent = time.time() - self.last_seen
                if self.state == "up" and silent > THRESHOLD:
                    self.state = "down"
                    self.down_since = self.last_seen
                    _write({"event": "interruption_start", "silent_s": round(silent, 2)})
                    print(f"[logger] INTERRUPTION: stream silent {silent:.1f}s", flush=True)


def main():
    mon = Monitor()
    threading.Thread(target=mon.watch, daemon=True).start()

    def on_connect(c, u, f, rc, p):
        print(f"[logger] connected rc={rc} -> subscribing {TOPIC}", flush=True)
        c.subscribe(TOPIC, qos=0)

    def on_message(c, u, msg):
        try:
            data = json.loads(msg.payload.decode())
            mon.on_beat(data.get("device_id", "unknown"))
        except Exception as e:
            print(f"[logger] bad message: {e}", flush=True)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="heartbeat-logger")
    client.on_connect = on_connect
    client.on_message = on_message
    _write({"event": "logger_start", "threshold_s": THRESHOLD})
    while True:
        try:
            client.connect(MQTT_HOST, MQTT_PORT, keepalive=10)
            break
        except Exception as e:
            print(f"[logger] broker not ready ({e}); retrying...", flush=True)
            time.sleep(2)
    client.loop_forever()


if __name__ == "__main__":
    main()
