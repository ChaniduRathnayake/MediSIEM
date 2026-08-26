from typing import Any, Optional

from pydantic import BaseModel, Field


# =========================================================
# IP LOOKUP
# =========================================================

class IPLookupRequest(BaseModel):
    ip: str = Field(
        ...,
        description="IPv4 or IPv6 address to investigate",
        examples=["8.8.8.8"]
    )


# =========================================================
# IP CLASSIFICATION
# =========================================================

class IPClassification(BaseModel):
    ip: str
    version: int
    category: str

    is_global: bool
    is_private: bool
    is_loopback: bool
    is_link_local: bool
    is_multicast: bool
    is_reserved: bool
    is_unspecified: bool

    external_reputation_applicable: bool

    reason: str


# =========================================================
# THREAT INTELLIGENCE PROVIDERS
# =========================================================

class ProviderResult(BaseModel):
    provider: str
    configured: bool
    available: bool
    status: str

    http_status: Optional[int] = None
    error: Optional[str] = None

    evidence: Optional[
        dict[str, Any]
    ] = None


class ProviderSummary(BaseModel):
    configured: int
    successful: int
    total: int


class ThreatIntelligenceResult(BaseModel):
    providers: dict[
        str,
        ProviderResult
    ]

    provider_summary: ProviderSummary


# =========================================================
# REPUTATION ENGINE
# =========================================================

class ReputationSignal(BaseModel):
    provider: str
    signal: float

    evidence: dict[
        str,
        Any
    ]


class ReputationAnalysis(BaseModel):
    score: Optional[float] = None

    score_based_risk_level: Optional[str] = None

    evidence_floor_level: Optional[str] = None

    risk_level: str

    decision: str

    confidence: str

    provider_agreement: str

    provider_signal_count: int

    signals: list[
        ReputationSignal
    ]

    explanation: list[str]

    recommended_action: str


# =========================================================
# MAIN REPUTATION RESPONSE
# =========================================================

class ReputationLookupResponse(BaseModel):
    ip: str

    classification: IPClassification

    reputation_status: str

    reputation_score: Optional[float] = None

    risk_level: Optional[str] = None

    confidence: Optional[str] = None

    threat_intelligence: Optional[
        ThreatIntelligenceResult
    ] = None

    reputation_analysis: Optional[
        ReputationAnalysis
    ] = None

    internal_intelligence: Optional[
        dict[str, Any]
    ] = None

    explanation: list[str]


# =========================================================
# INTERNAL ALLOW / WATCH / BLOCK LIST
# =========================================================

class ReputationListRequest(BaseModel):
    ip: str

    list_type: str = Field(
        ...,
        description="allow, watch, or block",
        examples=["watch"]
    )

    reason: str = Field(
        default="",
        max_length=1000
    )

    actor: str = Field(
        default="analyst",
        max_length=200
    )


class ReputationListResponse(BaseModel):
    ip: str

    list_type: str

    reason: str

    actor: str

    created_at: str

    updated_at: str


# =========================================================
# ANALYST VERDICT
# =========================================================

class AnalystVerdictRequest(BaseModel):
    ip: str

    verdict: str = Field(
        ...,
        description=(
            "benign, suspicious, malicious, "
            "or undetermined"
        ),
        examples=["suspicious"]
    )

    reason: str = Field(
        default="",
        max_length=2000
    )

    actor: str = Field(
        default="analyst",
        max_length=200
    )


# =========================================================
# ANALYST NOTE
# =========================================================

class AnalystNoteRequest(BaseModel):
    ip: str

    note: str = Field(
        ...,
        min_length=1,
        max_length=5000
    )

    actor: str = Field(
        default="analyst",
        max_length=200
    )
