"""Pytest config — make `enrichment.src.*` importable from the repo root.

Allows tests to run with the same import path that the live shim uses:
    from enrichment.src.registry import AssetRegistry
"""
import sys
from pathlib import Path

# Add the repo root to sys.path so `enrichment.src.foo` resolves cleanly.
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))
