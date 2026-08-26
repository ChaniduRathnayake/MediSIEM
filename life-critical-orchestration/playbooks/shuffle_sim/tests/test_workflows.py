"""Tests for the workflow modules.

Both workflows are pure functions over (decision, log) so they're trivially
testable without spinning up FastAPI. Server-level behaviour (HTTP routing,
engine callback) is tested separately in test_server.py.
"""

from __future__ import annotations

from shuffle_sim.workflows import monitored_mode, tier3_dispatch


# ---------- monitored_mode ----------

class TestMonitoredMode:
    def test_writes_three_components(self, tmp_log, tier2_decision):
        written = monitored_mode.run(tier2_decision, log=tmp_log)
        steps = [e["step"] for e in written]
        assert steps == ["deep_telemetry", "shadow_auditing", "zero_interference"]

    def test_all_entries_share_decision_and_asset(self, tmp_log, tier2_decision):
        written = monitored_mode.run(tier2_decision, log=tmp_log)
        for entry in written:
            assert entry["decision_id"] == tier2_decision["decision_id"]
            assert entry["asset_id"] == tier2_decision["asset_id"]
            assert entry["workflow"] == "monitored_mode"

    def test_zero_interference_is_an_assertion(self, tmp_log, tier2_decision):
        # The status MUST be 'asserted' (not 'triggered') because we are
        # explicitly recording what we are NOT doing — that's the safety story.
        written = monitored_mode.run(tier2_decision, log=tmp_log)
        zi = next(e for e in written if e["step"] == "zero_interference")
        assert zi["status"] == "asserted"
        assert zi["extra"]["blocked_ports"] == []
        assert zi["extra"]["native_functionality_preserved"] is True

    def test_deep_telemetry_carries_capture_metadata(self, tmp_log, tier2_decision):
        written = monitored_mode.run(tier2_decision, log=tmp_log)
        dt = next(e for e in written if e["step"] == "deep_telemetry")
        assert dt["extra"]["packet_capture"] is True
        assert isinstance(dt["extra"]["duration_minutes"], int)


# ---------- tier3_dispatch ----------

class TestTier3Dispatch:
    def test_runs_monitored_mode_first_then_dispatches(self, tmp_log, tier3_decision):
        written = tier3_dispatch.run(tier3_decision, log=tmp_log)
        steps = [e["step"] for e in written]
        # Monitored Mode (3) THEN clinician dispatch — order matters because
        # the safety property is "asset is contained BEFORE the human gets paged"
        assert steps == [
            "deep_telemetry",
            "shadow_auditing",
            "zero_interference",
            "clinician_dispatch",
        ]

    def test_first_three_actions_are_monitored_mode_workflow(self, tmp_log, tier3_decision):
        written = tier3_dispatch.run(tier3_decision, log=tmp_log)
        # The first three should be tagged as the monitored_mode workflow
        # (they came from monitored_mode.run), and the dispatch is its own.
        assert [e["workflow"] for e in written[:3]] == ["monitored_mode"] * 3
        assert written[3]["workflow"] == "tier3_dispatch"

    def test_dispatch_carries_proposed_action(self, tmp_log, tier3_decision):
        written = tier3_dispatch.run(tier3_decision, log=tmp_log)
        dispatch = written[-1]
        assert dispatch["status"] == "dispatched"
        assert dispatch["extra"]["proposed_action_if_approved"] == "isolate_host"

    def test_dispatch_default_when_proposed_action_missing(self, tmp_log):
        # Defensive: if a Tier 3 decision somehow reaches the playbook
        # without proposed_action_if_approved set, we still dispatch
        # rather than silently dropping it.
        decision = {
            "decision_id": "dec-edge-1",
            "asset_id": "ASSET-X",
            "tier": 3,
            "action": "await_clinician_approval",
            "rationale": "edge",
        }
        written = tier3_dispatch.run(decision, log=tmp_log)
        dispatch = next(e for e in written if e["step"] == "clinician_dispatch")
        # Falls back to isolate_host as the safest default
        assert dispatch["extra"]["proposed_action_if_approved"] == "isolate_host"

    def test_record_clinician_response_approved(self, tmp_log, tier3_decision):
        entry = tier3_dispatch.record_clinician_response(
            decision_id=tier3_decision["decision_id"],
            asset_id=tier3_decision["asset_id"],
            approved=True,
            clinician_id="dr-test",
            log=tmp_log,
        )
        assert entry["step"] == "clinician_response"
        assert entry["status"] == "approved"
        assert entry["extra"]["approved"] is True
        assert entry["extra"]["clinician_id"] == "dr-test"
        assert "isolate_host" in entry["detail"]

    def test_record_clinician_response_denied_mentions_fr06(self, tmp_log, tier3_decision):
        entry = tier3_dispatch.record_clinician_response(
            decision_id=tier3_decision["decision_id"],
            asset_id=tier3_decision["asset_id"],
            approved=False,
            clinician_id="dr-test",
            log=tmp_log,
        )
        assert entry["status"] == "denied"
        # Quarantine is off by default (needs site-specific segment definitions),
        # so on denial the device stays in Monitored Mode — the non-disruptive
        # containment applied throughout the Tier 3 wait — per FR-06.
        assert "Monitored Mode" in entry["detail"]
        assert "FR-06" in entry["detail"]
