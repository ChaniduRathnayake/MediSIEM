"""
Wazuh alert -> engine v1.0 schema mapper.

Wazuh's native alert JSON looks roughly like:

    {
      "timestamp": "2026-05-04T08:30:00.000+0000",
      "id": "1714809000.123456",            # alert id
      "rule": {
        "id": "87105",
        "level": 15,
        "description": "Ransomware encryption behaviour detected",
        "groups": ["malware", "ransomware"]
      },
      "agent": {
        "id": "012",
        "name": "rad-linac-01.hospital.local",
        "ip": "10.0.9.5"
      },
      "data": {                              # rule-specific payload
        "files_modified_per_minute": 412,
        "extensions_observed": [".locked"]
      }
    }

Our engine wants the v1.0 schema (see docs/alert-schema.md):

    {
      "alert_id": "...",
      "timestamp": "...",
      "source": { siem, rule_id, rule_description, rule_level },
      "threat": { category, technical_severity, cvss_score, indicators },
      "asset":  { asset_id, hostname, ip_address, asset_type, device_category,
                  department, patient_facing },
      "clinical_context": { criticality_score, patient_dependency,
                            time_sensitivity, shift },
      "enrichment_meta": { enriched_at, enricher_version, confidence }
    }

The mapper does three jobs:
  1. Restructure Wazuh's flat-ish shape into the engine's typed blocks.
  2. Derive threat fields the engine cares about (category, CVSS hint,
     technical severity) from Wazuh's rule groups and level.
  3. Enrich with clinical context from the registry — or leave the
     clinical_context block empty so the engine's fail-safe triggers.

Threat-derivation choices are conservative on purpose: when Wazuh's
event clearly signals ransomware or active exploitation, we tag it so
the engine's "extreme threat" rule fires correctly. When it doesn't,
we let the cvss_score (if Wazuh provided one) drive the decision — and
otherwise let the engine's lower tiers handle it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .registry import AssetRegistry


# Wazuh rule-level (1-15) to a rough technical_severity bucket.
# Wazuh's own scale: 0-3 informational, 4-7 low/medium-low, 8-11 medium,
# 12-15 high/critical. We compress into our 4 buckets.
def _level_to_severity(level: Optional[int]) -> Optional[str]:
    if level is None:
        return None
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


# Wazuh rule-level (1-15) to a CVSS-ish hint when no real CVSS is present.
# This is a stand-in, not a true CVSS score; the engine's extreme_threat
# logic uses cvss_score >= 9 as one trigger, so we want catastrophic
# Wazuh rules to surface as cvss >= 9 if and only if no real score exists.
def _level_to_cvss_hint(level: Optional[int]) -> Optional[float]:
    if level is None:
        return None
    if level >= 14:
        return 9.5
    if level >= 12:
        return 8.0
    if level >= 8:
        return 6.0
    if level >= 4:
        return 4.0
    return 1.0


# Wazuh rule groups => our threat category vocabulary.
# Order matters: more specific tags win. We check for ransomware and
# active_exploitation first because they trigger the engine's
# extreme_threat path independently of CVSS.
_GROUP_TO_CATEGORY = [
    ("ransomware", "ransomware"),
    ("exploit", "active_exploitation"),
    ("active_exploit", "active_exploitation"),
    ("malware", "malware"),
    ("intrusion", "intrusion_attempt"),
    ("authentication_failed", "credential_attack"),
    ("brute_force", "credential_attack"),
    ("policy", "policy_violation"),
]


def _derive_category(rule: Dict[str, Any]) -> Optional[str]:
    groups = rule.get("groups") or []
    groups_lower = {g.lower() for g in groups if isinstance(g, str)}
    for needle, category in _GROUP_TO_CATEGORY:
        if needle in groups_lower:
            return category
    description = (rule.get("description") or "").lower()
    if "ransomware" in description or "encryption behaviour" in description:
        return "ransomware"
    if "exploit" in description or "remote code execution" in description:
        return "active_exploitation"
    return None


def map_wazuh_alert(
    wazuh_alert: Dict[str, Any],
    registry: AssetRegistry,
    enricher_version: str = "stub-1.0.0",
) -> Dict[str, Any]:
    """Convert one Wazuh-shape alert into an engine-shape alert.

    Returns a dict ready to be POSTed to the engine's /decide endpoint.
    Pydantic will validate it on the engine side; callers don't need to
    pre-validate here.
    """
    rule = wazuh_alert.get("rule") or {}
    agent = wazuh_alert.get("agent") or {}
    data = wazuh_alert.get("data") or {}

    # Identity & timestamp.
    # Wazuh's "id" looks like "1714809000.123456"; we wrap it for clarity.
    raw_id = wazuh_alert.get("id") or wazuh_alert.get("alert_id")
    alert_id = f"wazuh-{raw_id}" if raw_id else f"wazuh-unidentified-{datetime.now(timezone.utc).isoformat()}"
    timestamp = wazuh_alert.get("timestamp") or datetime.now(timezone.utc).isoformat()

    # Source block — straight Wazuh metadata.
    rule_level = rule.get("level")
    source = {
        "siem": "wazuh",
        "rule_id": str(rule.get("id")) if rule.get("id") is not None else None,
        "rule_description": rule.get("description"),
        "rule_level": int(rule_level) if rule_level is not None else None,
    }

    # Threat block — derived from Wazuh's rule + any data already in the alert.
    # Honour an explicit cvss_score if Wazuh provided one (some integrations do);
    # otherwise fall back to the level-derived hint.
    explicit_cvss = data.get("cvss_score") if isinstance(data.get("cvss_score"), (int, float)) else None
    threat = {
        "category": _derive_category(rule),
        "technical_severity": _level_to_severity(rule_level),
        "cvss_score": float(explicit_cvss) if explicit_cvss is not None else _level_to_cvss_hint(rule_level),
        "indicators": data or None,
    }

    # Asset block — start from the agent identity, then enrich from the registry.
    hostname = agent.get("name")
    ip_address = agent.get("ip")
    enriched = registry.lookup(hostname=hostname, ip_address=ip_address)

    if enriched:
        asset = {
            "asset_id": enriched["asset_id"],
            "hostname": enriched.get("hostname") or hostname,
            "ip_address": enriched.get("ip_address") or ip_address,
            "asset_type": enriched.get("asset_type"),
            "device_category": enriched.get("device_category"),
            "department": enriched.get("department"),
            "patient_facing": enriched.get("patient_facing"),
        }
        clinical_context = {
            "criticality_score": enriched.get("criticality_score"),
            "patient_dependency": enriched.get("patient_dependency"),
            "time_sensitivity": enriched.get("time_sensitivity"),
            "shift": enriched.get("shift"),
        }
        confidence = 1.0
    else:
        # Unknown asset. We still need an asset_id (engine requires it),
        # so we synthesise one from whatever Wazuh told us. Clinical
        # context is left empty — the engine's fail-safe will treat this
        # as life_critical, which is the conservative default.
        asset = {
            "asset_id": hostname or ip_address or "UNKNOWN-ASSET",
            "hostname": hostname,
            "ip_address": ip_address,
            "asset_type": None,
            "device_category": None,
            "department": None,
            "patient_facing": None,
        }
        clinical_context = {}  # triggers engine fail-safe
        confidence = 0.0  # we know nothing about this asset

    enrichment_meta = {
        "enriched_at": datetime.now(timezone.utc).isoformat(),
        "enricher_version": enricher_version,
        "confidence": confidence,
    }

    return {
        "alert_id": alert_id,
        "timestamp": timestamp,
        "source": source,
        "threat": threat,
        "asset": asset,
        "clinical_context": clinical_context,
        "enrichment_meta": enrichment_meta,
    }
