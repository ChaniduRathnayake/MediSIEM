"""Tests for the shared ActionLog."""

from __future__ import annotations

import json
from pathlib import Path

from shuffle_sim.action_log import ActionLog


def _record(log: ActionLog, **overrides):
    base = dict(
        decision_id="dec-1",
        asset_id="ASSET-1",
        workflow="test_wf",
        step="some_step",
        status="triggered",
        detail="something happened",
        extra={},
    )
    base.update(overrides)
    return log.record(**base)


def test_record_appends_to_file_and_ring(tmp_log):
    entry = _record(tmp_log)
    assert entry["decision_id"] == "dec-1"
    assert entry["step"] == "some_step"
    # On disk
    lines = tmp_log.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["decision_id"] == "dec-1"
    # In ring
    assert len(tmp_log.all()) == 1


def test_by_decision_filters(tmp_log):
    _record(tmp_log, decision_id="dec-A", step="a")
    _record(tmp_log, decision_id="dec-B", step="b")
    _record(tmp_log, decision_id="dec-A", step="c")

    a = tmp_log.by_decision("dec-A")
    b = tmp_log.by_decision("dec-B")
    z = tmp_log.by_decision("dec-MISSING")

    assert [e["step"] for e in a] == ["a", "c"]
    assert [e["step"] for e in b] == ["b"]
    assert z == []


def test_recent_returns_newest_first(tmp_log):
    _record(tmp_log, step="first")
    _record(tmp_log, step="second")
    _record(tmp_log, step="third")

    recent = tmp_log.recent(limit=10)
    assert [e["step"] for e in recent] == ["third", "second", "first"]


def test_recent_respects_limit(tmp_log):
    for i in range(5):
        _record(tmp_log, step=f"step-{i}")
    assert len(tmp_log.recent(limit=2)) == 2
    assert len(tmp_log.recent(limit=0)) == 0


def test_rehydrate_loads_existing_log(tmp_path: Path):
    log_path = tmp_path / "actions.jsonl"
    log = ActionLog(log_path=log_path)
    _record(log, decision_id="dec-X", step="alpha")
    _record(log, decision_id="dec-Y", step="beta")
    # Open a fresh ActionLog over the same file — it should rehydrate
    fresh = ActionLog(log_path=log_path)
    steps = [e["step"] for e in fresh.all()]
    assert steps == ["alpha", "beta"]


def test_ring_bounded_by_size(tmp_path: Path):
    log = ActionLog(log_path=tmp_path / "actions.jsonl", ring_size=3)
    for i in range(5):
        _record(log, step=f"s{i}")
    # Ring keeps only the last 3 in-memory
    assert [e["step"] for e in log.all()] == ["s2", "s3", "s4"]
    # But all 5 are on disk (durability is the file, not the ring)
    on_disk = log.path.read_text(encoding="utf-8").splitlines()
    assert len(on_disk) == 5


def test_extra_field_round_trips(tmp_log):
    _record(tmp_log, extra={"verbosity_level": "verbose", "duration_minutes": 60})
    entry = tmp_log.all()[0]
    assert entry["extra"]["verbosity_level"] == "verbose"
    assert entry["extra"]["duration_minutes"] == 60


def test_malformed_lines_in_log_are_skipped_on_rehydrate(tmp_path: Path):
    log_path = tmp_path / "actions.jsonl"
    # Manually write a mix of valid and malformed lines
    log_path.write_text(
        '{"step": "good1"}\n'
        'this is not json\n'
        '{"step": "good2"}\n',
        encoding="utf-8",
    )
    fresh = ActionLog(log_path=log_path)
    steps = [e["step"] for e in fresh.all()]
    assert steps == ["good1", "good2"]
