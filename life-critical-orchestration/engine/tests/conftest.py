"""
Shared pytest fixtures.

Loads the stub alert dataset (data/sample-alerts/*.json) and exposes it to
every test in this package. Tests that need specific alerts can pull them by
ID without each test re-loading the JSON.
"""

import json
from pathlib import Path
from typing import Dict, List

import pytest


# Repository layout:  <repo-root>/engine/tests/conftest.py
#                     <repo-root>/data/sample-alerts/*.json
REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_ALERTS_DIR = REPO_ROOT / "data" / "sample-alerts"


def _load_tier_file(filename: str) -> List[dict]:
    path = SAMPLE_ALERTS_DIR / filename
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data["alerts"]


@pytest.fixture(scope="session")
def tier1_alerts() -> List[dict]:
    return _load_tier_file("tier1-cases.json")


@pytest.fixture(scope="session")
def tier2_alerts() -> List[dict]:
    return _load_tier_file("tier2-cases.json")


@pytest.fixture(scope="session")
def tier3_alerts() -> List[dict]:
    return _load_tier_file("tier3-cases.json")


@pytest.fixture(scope="session")
def all_alerts(tier1_alerts, tier2_alerts, tier3_alerts) -> Dict[int, List[dict]]:
    """All stub alerts grouped by expected tier."""
    return {1: tier1_alerts, 2: tier2_alerts, 3: tier3_alerts}
