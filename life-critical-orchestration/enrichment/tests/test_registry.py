"""Tests for the asset registry loader and lookup."""

from pathlib import Path

import pytest

from enrichment.src.registry import AssetRegistry


REGISTRY_PATH = Path(__file__).resolve().parent.parent / "data" / "asset_registry.json"


@pytest.fixture(scope="module")
def registry() -> AssetRegistry:
    return AssetRegistry(REGISTRY_PATH)


def test_registry_loads_all_twelve_assets(registry: AssetRegistry) -> None:
    assert len(registry) == 12, "Registry should mirror the 12 stub alerts"


def test_lookup_by_hostname_hits(registry: AssetRegistry) -> None:
    asset = registry.lookup(hostname="rad-linac-01.hospital.local")
    assert asset is not None
    assert asset["asset_id"] == "RAD-LINAC-001"
    assert asset["criticality_score"] == 10
    assert asset["department"] == "Radiology"


def test_lookup_by_hostname_is_case_insensitive(registry: AssetRegistry) -> None:
    asset = registry.lookup(hostname="RAD-LINAC-01.HOSPITAL.LOCAL")
    assert asset is not None
    assert asset["asset_id"] == "RAD-LINAC-001"


def test_lookup_by_ip_hits(registry: AssetRegistry) -> None:
    asset = registry.lookup(ip_address="10.0.5.23")
    assert asset is not None
    assert asset["asset_id"] == "ICU-VENT-003"


def test_lookup_unknown_returns_none(registry: AssetRegistry) -> None:
    assert registry.lookup(hostname="not-a-real-host") is None
    assert registry.lookup(ip_address="192.0.2.1") is None
    assert registry.lookup() is None


def test_hostname_takes_precedence_over_ip(registry: AssetRegistry) -> None:
    """If both are passed, hostname wins (deterministic resolution order)."""
    asset = registry.lookup(
        hostname="rad-linac-01.hospital.local",
        ip_address="10.0.5.23",  # belongs to ICU-VENT-003
    )
    assert asset is not None
    assert asset["asset_id"] == "RAD-LINAC-001"


def test_missing_registry_file_raises(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        AssetRegistry(tmp_path / "does-not-exist.json")
