"""Shared fixtures for shuffle_sim tests.

Each test gets its own ActionLog backed by a temp file so they don't
trample each other or the dev's real action_log.jsonl.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shuffle_sim.action_log import ActionLog


@pytest.fixture
def tmp_log(tmp_path: Path) -> ActionLog:
    """Fresh ActionLog rooted in a per-test temp dir."""
    return ActionLog(log_path=tmp_path / "actions.jsonl", ring_size=200)


@pytest.fixture
def tier2_decision() -> dict:
    return {
        "decision_id": "dec-test-tier2-aaa",
        "asset_id": "ICU-VENT-003",
        "tier": 2,
        "action": "monitored_mode",
        "rationale": "Test Tier 2 rationale",
        "proposed_action_if_approved": None,
    }


@pytest.fixture
def tier3_decision() -> dict:
    return {
        "decision_id": "dec-test-tier3-bbb",
        "asset_id": "RAD-LINAC-001",
        "tier": 3,
        "action": "await_clinician_approval",
        "rationale": "Extreme threat on life-critical asset",
        "proposed_action_if_approved": "isolate_host",
    }


@pytest.fixture
def tier1_decision() -> dict:
    return {
        "decision_id": "dec-test-tier1-ccc",
        "asset_id": "ADM-LAPTOP-014",
        "tier": 1,
        "action": "block_port",
        "rationale": "Non-critical asset, medium CVSS",
        "proposed_action_if_approved": None,
    }
