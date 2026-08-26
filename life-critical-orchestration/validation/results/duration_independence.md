# Duration-independence — ICU-VENT-003 (measured 2026-08-02)

| Response | Hold 10s | Hold 40s | Behaviour |
|---|---|---|---|
| isolate | 12.0s | 41.0s | scales with containment (device dark throughout) |
| quarantine | 6.0s | 6.0s | fixed one-time reconnect blip |

Measured on the live device-sim. isolate's clinical-telemetry loss tracks the containment duration; quarantine's is a single reconnect cost independent of how long the device stays contained — the core life-critical advantage of micro-segmentation over a full network cut.
