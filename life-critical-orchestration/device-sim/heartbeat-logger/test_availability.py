from availability import compute_availability


def test_perfect_stream_is_100pct():
    beats = [1000.0 + i for i in range(60)]  # 60 beats, 1s apart
    r = compute_availability(beats, expected_interval=1.0)
    assert r["uptime_pct"] == 100.0
    assert r["interruption_count"] == 0


def test_single_interruption_detected():
    beats = [1000.0 + i for i in range(10)]            # 1s apart
    beats.append(beats[-1] + 11)                        # 11s silent gap
    beats += [beats[-1] + 1 + i for i in range(10)]     # resume 1s apart
    r = compute_availability(beats, expected_interval=1.0, factor=3.0)
    assert r["interruption_count"] == 1
    assert r["total_downtime_s"] == 10.0                # 11s gap minus 1 expected beat
    assert r["uptime_pct"] < 100.0


def test_jitter_below_threshold_is_not_an_interruption():
    beats = [1000.0, 1001.2, 1002.1, 1003.4, 1004.2]    # all gaps < 3s
    r = compute_availability(beats, expected_interval=1.0, factor=3.0)
    assert r["interruption_count"] == 0
