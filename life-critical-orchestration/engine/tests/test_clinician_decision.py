"""
Tests for the /clinician-decision endpoint and the /clinician-decisions
read-side helper. Uses FastAPI's TestClient.

These tests use a per-test audit log via the AUDIT_LOG_PATH env var, so
they don't pollute the dev's persistent audit log.
"""

from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


# ---------- Fixtures ----------

@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    """A fresh engine instance with an isolated audit log."""
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    # Also isolate the /alerts/recent cache — without this, every test run
    # posting a stub alert (e.g. _make_tier3_alert()) appended straight into
    # the dev's real recent_alerts.jsonl, polluting the Playbooks/SOC Console
    # Alert Feed cache with fake alert-t3-001/ASSET-A/ASSET-B entries.
    monkeypatch.setenv("RECENT_ALERTS_LOG_PATH", str(tmp_path / "recent_alerts.jsonl"))
    # Reload the main module so the AUDIT_LOG_PATH env var is picked up.
    # Important: do this AFTER monkeypatch.setenv so the module-level
    # constants resolve to the temp path.
    from src import main as engine_main
    importlib.reload(engine_main)
    return TestClient(engine_main.app)


def _make_tier3_alert(*, alert_id="alert-t3-001", asset_id="RAD-LINAC-001"):
    """A minimal Tier 3 alert that will classify as await_clinician_approval."""
    return {
        "alert_id": alert_id,
        "timestamp": "2026-05-06T10:00:00Z",
        "source": {
            "siem": "wazuh",
            "rule_id": "100200",
            "rule_description": "Ransomware encryption behaviour",
        },
        "threat": {
            "category": "ransomware",
            "cvss_score": 9.8,
            "technical_severity": "critical",
        },
        "asset": {
            "asset_id": asset_id,
            "hostname": "rad-linac-001.hospital.local",
            "device_category": "linear_accelerator",
            "department": "Radiology",
        },
        "clinical_context": {
            "criticality_score": 10,
            "patient_dependency": "life_critical",
            "time_sensitivity": 5,
            "shift": "day",
        },
        "enrichment_meta": {
            "enricher_version": "stub-1.0.0",
            "confidence": 1.0,
        },
    }


# ---------- /clinician-decision happy path ----------

def test_clinician_decision_404_for_unknown_decision_id(client):
    resp = client.post(
        "/clinician-decision",
        json={
            "decision_id": "dec-does-not-exist",
            "approved": True,
            "clinician_id": "dr-test",
        },
    )
    assert resp.status_code == 404


def test_clinician_decision_records_approval(client):
    # First, create a Tier 3 decision in the audit log
    decide_resp = client.post("/decide", json=_make_tier3_alert())
    assert decide_resp.status_code == 200
    decision = decide_resp.json()
    assert decision["tier"] == 3
    assert decision["action"] == "await_clinician_approval"
    decision_id = decision["decision_id"]

    # Approve it
    resp = client.post(
        "/clinician-decision",
        json={
            "decision_id": decision_id,
            "approved": True,
            "clinician_id": "dr-approve",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["final_action"] == "isolate_host"

    # Audit chain should still verify
    verify = client.get("/audit/verify").json()
    assert verify["ok"] is True


def test_clinician_decision_records_denial_with_fr06(client):
    decide_resp = client.post("/decide", json=_make_tier3_alert())
    decision_id = decide_resp.json()["decision_id"]

    resp = client.post(
        "/clinician-decision",
        json={
            "decision_id": decision_id,
            "approved": False,
            "clinician_id": "dr-deny",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    # Denial → no state change, asset stays in monitored_mode (FR-06)
    assert body["final_action"] == "monitored_mode"

    verify = client.get("/audit/verify").json()
    assert verify["ok"] is True


def test_clinician_decision_denial_honors_final_action_override(client):
    """The Shuffle sim passes final_action explicitly once it knows the real
    per-asset outcome (enforcement.has_clinical_peers) — an asset with a
    configured clinical-peer group stays quarantined on denial instead of
    the engine's own conservative monitored_mode default."""
    decide_resp = client.post("/decide", json=_make_tier3_alert())
    decision_id = decide_resp.json()["decision_id"]

    resp = client.post(
        "/clinician-decision",
        json={
            "decision_id": decision_id,
            "approved": False,
            "clinician_id": "dr-deny",
            "final_action": "quarantine",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["final_action"] == "quarantine"

    verify = client.get("/audit/verify").json()
    assert verify["ok"] is True


def test_clinician_decisions_summary(client):
    # Create two Tier 3 decisions on different assets
    a = client.post(
        "/decide",
        json=_make_tier3_alert(alert_id="alert-t3-AAA", asset_id="ASSET-A"),
    ).json()
    b = client.post(
        "/decide",
        json=_make_tier3_alert(alert_id="alert-t3-BBB", asset_id="ASSET-B"),
    ).json()

    # Approve A, deny B
    client.post("/clinician-decision", json={
        "decision_id": a["decision_id"], "approved": True, "clinician_id": "dr-x",
    })
    client.post("/clinician-decision", json={
        "decision_id": b["decision_id"], "approved": False, "clinician_id": "dr-y",
    })

    summary = client.get("/clinician-decisions").json()
    assert a["decision_id"] in summary
    assert b["decision_id"] in summary
    assert summary[a["decision_id"]]["approved"] is True
    assert summary[a["decision_id"]]["final_action"] == "isolate_host"
    assert summary[b["decision_id"]]["approved"] is False
    assert summary[b["decision_id"]]["final_action"] == "monitored_mode"


def test_clinician_decisions_summary_returns_latest_when_revised(client):
    """If a clinician revises their decision, the summary surfaces the latest.

    The audit chain still records every transition (immutability is preserved);
    only the convenience read-side endpoint returns the most recent entry.
    """
    decide = client.post("/decide", json=_make_tier3_alert()).json()
    did = decide["decision_id"]

    # First denied
    client.post("/clinician-decision", json={
        "decision_id": did, "approved": False, "clinician_id": "dr-1",
    })
    # Then approved (revision)
    client.post("/clinician-decision", json={
        "decision_id": did, "approved": True, "clinician_id": "dr-1",
    })

    summary = client.get("/clinician-decisions").json()
    assert summary[did]["approved"] is True
    assert summary[did]["final_action"] == "isolate_host"

    # But the audit log records BOTH events
    log = client.get("/audit").json()
    followups = [e for e in log if e.get("followup")]
    assert len(followups) == 2


def test_decide_works_without_shuffle_webhook(client, monkeypatch):
    """Confirm /decide returns normally when SHUFFLE_WEBHOOK_URL is unset.

    The shuffle push is fire-and-forget; this test exercises the no-op path.
    """
    monkeypatch.delenv("SHUFFLE_WEBHOOK_URL", raising=False)
    resp = client.post("/decide", json=_make_tier3_alert())
    assert resp.status_code == 200
    assert resp.json()["tier"] == 3
