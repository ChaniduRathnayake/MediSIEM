"""
Asset registry lookup.

Loads the JSON registry once at startup and indexes assets by both
hostname and IP address so callers can look up by whichever field
the upstream alert provides.

Lookup miss => returns None. The decision engine's fail-safe rule
(missing criticality_score => substitute score=10, band=life_critical)
is the safety net for unknown assets — the conservative default that
matches the safety-preserving spirit of the project.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Dict, Any


class AssetRegistry:
    """Hostname/IP -> clinical context lookup, backed by a JSON file."""

    def __init__(self, registry_path: str | Path):
        self.path = Path(registry_path)
        self._by_hostname: Dict[str, Dict[str, Any]] = {}
        self._by_ip: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            raise FileNotFoundError(f"Asset registry not found: {self.path}")

        with self.path.open(encoding="utf-8") as f:
            data = json.load(f)

        # Skip the _meta block — it's documentation, not data.
        for asset in data.get("assets", []):
            if hostname := asset.get("hostname"):
                self._by_hostname[hostname.lower()] = asset
            if ip := asset.get("ip_address"):
                self._by_ip[ip] = asset

    def lookup(
        self,
        hostname: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Find an asset by hostname or IP. Hostname takes precedence.

        Returns the asset dict (clinical context plus identity fields) or
        None if no match is found. Callers should treat None as "unknown
        asset, let the engine's fail-safe handle it."
        """
        if hostname:
            hit = self._by_hostname.get(hostname.lower())
            if hit:
                return hit
        if ip_address:
            hit = self._by_ip.get(ip_address)
            if hit:
                return hit
        return None

    def __len__(self) -> int:
        return len(self._by_hostname)
