"""
Pydantic models for the enriched alert schema (v1.0).

These models mirror docs/alert-schema.md and provide:
  - Automatic validation of incoming JSON
  - Type-safe access to alert fields throughout the engine
  - Clear error messages when fields are missing or malformed

Schema philosophy: "be generous about what you accept, strict about what you produce."
Most fields are Optional with sensible fallbacks. The fail-safe rule
(missing/invalid criticality_score => treat as life_critical / score 10) is
implemented in the classifier, not here, so that the model accurately
represents what the enricher sent us.
"""

from datetime import datetime
from typing import Optional, Literal, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


# ---------- Top-level blocks ----------

class Source(BaseModel):
    """Where the raw alert came from."""
    model_config = ConfigDict(extra="allow")  # Tolerate extra fields from upstream

    siem: str = "unknown"
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    rule_level: Optional[int] = None


class Threat(BaseModel):
    """What kind of threat, and how severe."""
    model_config = ConfigDict(extra="allow")

    category: Optional[str] = None
    technical_severity: Optional[Literal["low", "medium", "high", "critical"]] = None
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    # MediSIEM's CAAP-blended severity score (0-10 — same scale/range as
    # cvss_score, NOT 0-1). When present, this is the authoritative severity
    # signal the classifier reads instead of cvss_score: it already folds in
    # technical risk, attack exploitability and time context, which a raw
    # CVSS baseline doesn't. cvss_score remains the fallback for producers
    # that don't compute a CAS-style blended score.
    cas_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    # Optional breakdown of the components behind cas_score (TR/CC/TS/AE/TC
    # sub-scores etc.) — display-only, the classifier never reads this.
    cas_breakdown: Optional[Dict[str, Any]] = None
    indicators: Optional[Dict[str, Any]] = None


class Asset(BaseModel):
    """Which device or system the alert is about."""
    model_config = ConfigDict(extra="allow")

    asset_id: str  # required — engine refuses alerts without this
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    asset_type: Optional[Literal[
        "medical_device", "workstation", "server", "network", "other"
    ]] = None
    device_category: Optional[str] = None
    department: Optional[str] = None
    patient_facing: Optional[bool] = None


class ClinicalContext(BaseModel):
    """The heart of the schema: clinical criticality of the asset.

    The enrichment module produces a single authoritative signal
    (`criticality_score`, 1–10) plus three display-only metadata fields.
    The engine reads ONLY `criticality_score` for tier decisions; the
    metadata fields are surfaced on the dashboard for SOC analysts.

    Note on field naming: the enrichment module's internal column for
    `criticality_score` is named `cc_score`. It is mapped to
    `criticality_score` at ingest. Both names refer to the same value
    on the same 1–10 scale.
    """
    model_config = ConfigDict(extra="allow")

    # Authoritative signal — the only field the engine reads for tier logic.
    # Optional at the model level so the classifier can apply its fail-safe;
    # the classifier MUST substitute score=10 / band=life_critical when this
    # is None or out-of-range.
    criticality_score: Optional[int] = Field(default=None, ge=1, le=10)

    # Display-only metadata (engine ignores; surfaced on dashboard).
    # Vocabulary defined by the enrichment module — kept as open str/float
    # rather than Literals so the contract stays flexible.
    patient_dependency: Optional[str] = None
    time_sensitivity: Optional[float] = None
    shift: Optional[str] = None


class EnrichmentMeta(BaseModel):
    """Provenance of the enrichment (which version produced this alert)."""
    model_config = ConfigDict(extra="allow")

    enriched_at: Optional[datetime] = None
    enricher_version: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)


# ---------- The full alert ----------

class Alert(BaseModel):
    """A fully-enriched alert as consumed by the decision engine."""
    model_config = ConfigDict(extra="allow")

    alert_id: str  # required — used as audit log key
    timestamp: datetime
    source: Source = Field(default_factory=Source)
    threat: Threat = Field(default_factory=Threat)
    asset: Asset
    clinical_context: ClinicalContext = Field(default_factory=ClinicalContext)
    enrichment_meta: EnrichmentMeta = Field(default_factory=EnrichmentMeta)
