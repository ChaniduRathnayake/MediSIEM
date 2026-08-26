"""Pure availability math -- no broker, no MQTT, fully unit-testable.

This is the core of the validation harness: given the arrival times of the
device's heartbeats, work out how much of the time the device's service was
actually available. Interruptions (gaps larger than factor x the expected
interval) are what an isolate_host enforcement produces; monitored_mode should
produce none.
"""


def compute_availability(arrival_epochs, expected_interval, factor=3.0):
    """Return availability stats for a sorted list of heartbeat arrival times."""
    threshold = expected_interval * factor
    interruptions = []
    total_downtime = 0.0
    for prev, cur in zip(arrival_epochs, arrival_epochs[1:]):
        gap = cur - prev
        if gap > threshold:
            downtime = gap - expected_interval  # discount one expected beat
            interruptions.append(
                {"start": prev, "end": cur, "duration_s": round(downtime, 2)})
            total_downtime += downtime
    if len(arrival_epochs) >= 2:
        span = arrival_epochs[-1] - arrival_epochs[0]
        uptime_pct = 100.0 * (span - total_downtime) / span if span > 0 else 100.0
    else:
        uptime_pct = 100.0
    return {
        "uptime_pct": round(uptime_pct, 3),
        "interruption_count": len(interruptions),
        "total_downtime_s": round(total_downtime, 2),
        "interruptions": interruptions,
    }
