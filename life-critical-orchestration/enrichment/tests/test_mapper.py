"""Tests for the Wazuh -> engine alert mapper.

These tests cover the three responsibilities of the mapper:
  1. Restructure Wazuh's shape into the engine's typed blocks.
  2. Derive threat fields (category, severity, cvss hint).
  3. Enrich with registry context, or trigger the fail-safe path on miss.
"""

from pathlib import Path

import pytest

from enrichment.src.mapper import map_wazuh_alert
from enrichment.src.registry import AssetRegistry


REGISTRY_PATH = Path(__file__).resolve().parent.parent / "data" / "asset_registry.json"


@pytest.fixture(scope="module")
def registry() -> AssetRegistry:
    return AssetRegistry(REGISTRY_PATH)


# ---------- Shape tests ----------

def test_minimal_wazuh_alert_produces_valid_engine_alert(registry: AssetRegistry) -> None:
    wazuh = {
        "id": "1",
        "timestamp": "2026-05-04T08:30:00.000+0000",
        "rule": {"id": "5710", "level": 5, "description": "test"},
        "agent": {"name": "rad-linac-01.hospital.local", "ip": "10.0.9.5"},
    }
    enriched = map_wazuh_alert(wazuh, registry)
    # Top-level required fields are present
    for key in ["alert_id", "timestamp", "source", "threat", "asset",
                "clinical_context", "enrichment_meta"]:
        assert key in enriched
    # Asset id is required by the engine model
    assert enriched["asset"]["asset_id"]


def test_alert_id_is_namespaced_with_wazuh_prefix(registry: AssetRegistry) -> None:
    wazuh = {"id": "abc-123", "rule": {"id": "1"}, "agent": {}}
    enriched = map_wazuh_alert(wazuh, registry)
    assert enriched["alert_id"].startswith("wazuh-")


# ---------- Threat-derivation tests ----------

def test_ransomware_group_maps_to_ransomware_category(registry: AssetRegistry) -> None:
    wazuh = {
        "id": "1",
        "rule": {"id": "87105", "level": 15, "description": "Encryption activity",
                 "groups": ["malware", "ransomware"]},
        "agent": {"name": "rad-linac-01.hospital.local"},
    }
    enriched = map_wazuh_alert(wazuh, registry)
    assert enriched["threat"]["category"] == "ransomware"


def test_exploit_group_maps_to_active_exploitation(registry: AssetRegistry) -> None:
    wazuh = {
        "id": "1",
        "rule": {"id": "61603", "level": 14, "description": "RCE",
                 "groups": ["exploit", "active_exploit"]},
        "agent": {"name": "or-anaesthesia-02.hospital.local"},
    }
    enriched = map_wazuh_alert(wazuh, registry)
    assert enriched["threat"]["category"] == "active_exploitation"


def test_brute_force_maps_to_credential_attack(registry: AssetRegistry) -> None:
    wazuh = {
        "id": "1",
        "rule": {"id": "5712", "level": 10, "description": "SSH bruteforce",
                 "groups": ["authentication_failed", "brute_force"]},
        "agent": {"name": "admin-laptop-14.hospital.local"},
    }
    enriched = map_wazuh_alert(wazuh, registry)
    assert enriched["threat"]["category"] == "credential_attack"


def test_description_fallback_detects_ransomware(registry: AssetRegistry) -> None:
    """If groups are empty, description-keyword matching kicks in."""
    wazuh = {
        "id": "1",
        "rule": {"id": "1", "level": 12,
                 "description": "Ransomware encryption behaviour detected"},
        "agent": {"name": "rad-linac-01.hospital.local"},
    }
    enriched = map_wazuh_alert(wazuh, registry)
    assert enriched["threat"]["category"] == "ransomware"


def test_severity_buckets_by_rule_level(registry: AssetRegistry) -> None:
    cases = [(2, "low"), (6, "medium"), (10, "high"), (14, "critical")]
    for level, expected in cases:
        wazuh = {"id": "1", "rule": {"id": "1", "level": level}, "agent": {}}
        enriched = map_wazuh_alert(wazuh, registry)
        assert enriched["threat"]["technical_severity"] == expected, \
            f"level {level} should map to {expected}"


def test_explicit_cvss_score_wins_over_level_hint(registry: AssetRegistry) -> None:
    """If Wazuh provides a real CVSS in data, we honour it over our level hint."""
    wazuh = {
        "id": "1",
        "rule": {"id": "1", "level": 5},  # would hint cvss=4.0
        "agent": {"name": "rad-linac-01.hospital.local"},
        "data": {"cvss_score": 9.7},      # but real CVSS is 9.7
    }
    enriched = map_wazuh_alert(wazuh, registry)
    assert enriched["threat"]["cvss_score"] == 9.7


def test_level_hint_used_when_no_explicit_cvss(registry: AssetRegistry) -> None:
    wazuh = {
        "id": "1",
        "rule": {"id": "1", "level": 14},
        "agent": {"name": "rad-linac-01.hospital.local"},
    }
    enriched = map_wazuh_alert(wazuh, registry)
    assert enriched["threat"]["cvss_score"] == 9.5  # level >= 14 hint


# ---------- Enrichment tests ----------

def test_known_hostname_enriches_with_full_clinical_context(registry: AssetRegistry) -> None:
    wazuh = {
        "id": "1",
        "rule": {"id": "1", "level": 15, "groups": ["ransomware"]},
        "agent": {"name": "rad-linac-01.hospital.local", "ip": "10.0.9.5"},
    }
    enriched = map_wazuh_alert(wazuh, registry)
    assert enriched["asset"]["asset_id"] == "RAD-LINAC-001"
    assert enriched["asset"]["department"] == "Radiology"
    assert enriched["asset"]["device_category"] == "linear_accelerator"
    assert enriched["clinical_context"]["criticality_score"] == 10
    assert enriched["clinical_context"]["patient_dependency"] == "life_critical"
    assert enriched["enrichment_meta"]["confidence"] == 1.0


def test_unknown_asset_leaves_clinical_context_empty(registry: AssetRegistry) -> None:
    """Registry miss → empty clinical_context so engine fail-safe triggers."""
    wazuh = {
        "id": "1",
        "rule": {"id": "1", "level": 12},
        "agent": {"name": "ghost-host.hospital.local", "ip": "10.0.99.99"},
    }
    enriched = map_wazuh_alert(wazuh, registry)
    # asset_id is synthesised from whatever Wazuh gave us
    assert enriched["asset"]["asset_id"] == "ghost-host.hospital.local"
    # clinical_context is empty — engine fail-safe will substitute
    assert enriched["clinical_context"] == {}
    # And confidence reflects the miss
    assert enriched["enrichment_meta"]["confidence"] == 0.0


def test_unknown_asset_falls_back_to_ip_for_id(registry: AssetRegistry) -> None:
    wazuh = {
        "id": "1",
        "rule": {"id": "1", "level": 5},
        "agent": {"ip": "10.0.99.99"},  # no name
    }
    enriched = map_wazuh_alert(wazuh, registry)
    assert enriched["asset"]["asset_id"] == "10.0.99.99"
