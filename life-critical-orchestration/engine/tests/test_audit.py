"""
Audit log tests.

Confirms:
  - Empty log verifies as ok
  - Single entry verifies as ok
  - Multi-entry chain verifies as ok
  - Tampered entries are detected (this is the whole point)
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.audit import AuditLogger
from src.models.decision import Decision, Tier


def _make_decision(idx: int) -> Decision:
    return Decision(
        alert_id=f"alert-test-{idx:04d}",
        asset_id="TEST-ASSET",
        tier=Tier.TIER_2,
        action="monitored_mode",
        rationale="test",
        matched_rule="RULE_3_life_critical_standard",
        effective_criticality="life_critical",
    )


@pytest.fixture
def temp_log(tmp_path: Path) -> AuditLogger:
    return AuditLogger(tmp_path / "audit.jsonl")


def test_empty_log_verifies_ok(temp_log):
    ok, error = temp_log.verify_chain()
    assert ok is True
    assert error is None


def test_single_entry_verifies_ok(temp_log):
    temp_log.append(_make_decision(1))
    ok, error = temp_log.verify_chain()
    assert ok is True
    assert error is None


def test_multi_entry_chain_verifies_ok(temp_log):
    for i in range(5):
        temp_log.append(_make_decision(i))
    ok, error = temp_log.verify_chain()
    assert ok is True


def test_tampered_entry_is_detected(temp_log):
    """Modifying an existing entry's payload must break the hash chain."""
    for i in range(3):
        temp_log.append(_make_decision(i))

    # Tamper: rewrite the second line with a different alert_id but keep
    # the original previous_hash and entry_hash. This simulates an attacker
    # editing a stored log.
    lines = temp_log.path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["decision"]["alert_id"] = "MALICIOUSLY_CHANGED"
    lines[1] = json.dumps(entry)
    temp_log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, error = temp_log.verify_chain()
    assert ok is False
    assert error is not None and "Entry 1" in error


def test_chain_links_each_entry_to_predecessor(temp_log):
    """previous_hash of entry N must equal entry_hash of entry N-1."""
    for i in range(4):
        temp_log.append(_make_decision(i))

    entries = list(temp_log.read_all())
    for i in range(1, len(entries)):
        assert entries[i]["previous_hash"] == entries[i - 1]["entry_hash"]


# ---------- Follow-up entries (clinician responses, etc.) ----------

def test_followup_extends_chain(temp_log):
    """A follow-up entry must hash-link to the previous entry."""
    temp_log.append(_make_decision(1))
    temp_log.append_followup({
        "kind": "clinician_response",
        "referenced_decision_id": "dec-test",
        "approved": True,
    })
    ok, error = temp_log.verify_chain()
    assert ok is True
    assert error is None


def test_followup_contains_payload(temp_log):
    """Follow-ups must round-trip through the chain with their payload intact."""
    temp_log.append(_make_decision(1))
    temp_log.append_followup({
        "kind": "clinician_response",
        "referenced_decision_id": "dec-abc",
        "approved": False,
        "clinician_id": "dr-test",
    })
    entries = list(temp_log.read_all())
    assert len(entries) == 2
    followup = entries[1].get("followup")
    assert followup is not None
    assert followup["kind"] == "clinician_response"
    assert followup["referenced_decision_id"] == "dec-abc"
    assert followup["approved"] is False


def test_decision_then_followup_then_decision_chain_holds(temp_log):
    """Mixed entries (Decision → followup → Decision) must verify cleanly."""
    temp_log.append(_make_decision(1))
    temp_log.append_followup({
        "kind": "clinician_response",
        "referenced_decision_id": "dec-1",
        "approved": True,
    })
    temp_log.append(_make_decision(2))
    ok, _ = temp_log.verify_chain()
    assert ok is True


def test_tampered_followup_is_detected(temp_log):
    """Modifying a follow-up's payload must break the chain."""
    temp_log.append(_make_decision(1))
    temp_log.append_followup({
        "kind": "clinician_response",
        "referenced_decision_id": "dec-1",
        "approved": True,
    })
    temp_log.append(_make_decision(2))

    # Tamper with the follow-up
    lines = temp_log.path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["followup"]["approved"] = False  # flip the clinician's answer
    lines[1] = json.dumps(entry)
    temp_log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, error = temp_log.verify_chain()
    assert ok is False
    assert error is not None and "Entry 1" in error
