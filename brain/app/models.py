"""Pydantic models shared by the Bastionscan analysis brain.

The engine's ScanResult is mirrored loosely (extra fields allowed) so the brain
keeps working even as the Go engine grows new fields.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Status = Literal["pass", "warn", "fail", "info"]
Severity = Literal["critical", "high", "medium", "low", "info"]


class Finding(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str = ""
    module: str = ""
    category: str = ""
    title: str = ""
    status: Status = "info"
    severity: Severity = "info"
    points: int = 0
    maxPoints: int = 0
    detail: str = ""
    fix: str | None = None
    reference: str | None = None
    evidence: str | None = None


class CategoryScore(BaseModel):
    model_config = ConfigDict(extra="allow")

    category: str
    label: str = ""
    score: int = 0


class ScanResult(BaseModel):
    """Loose mirror of the Go engine's scan result."""

    model_config = ConfigDict(extra="allow")

    target: str = ""
    host: str = ""
    domain: str = ""
    profile: str = ""
    grade: str = ""
    score: int = 0
    categories: list[CategoryScore] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


class RemediationItem(BaseModel):
    priority: str  # P1..P4
    severity: Severity
    category: str
    title: str
    detail: str
    fix: str | None = None
    reference: str | None = None
    effort: str  # Quick / Moderate / Involved
    points_lost: int


class CategoryRisk(BaseModel):
    category: str
    label: str
    risk: int  # 0..100 (higher = worse)
    open_issues: int


class CVEMatch(BaseModel):
    product: str
    version: str
    fixed_in: str
    severity: Severity
    cves: list[str]
    summary: str
    source: str = "curated"  # "curated" (built-in DB) or "osv" (live OSV.dev feed)
    url: str | None = None  # advisory link, when available (OSV)


class ScamVerdict(BaseModel):
    """The consumer-facing bottom line: is this site safe to interact with?

    Derived from the engine's `phishing` module findings so the frontend can
    render one unmistakable banner without re-deriving anything.
    """

    verdict: str  # SAFE / LOW RISK / SUSPICIOUS / DANGEROUS
    level: int  # 0..3 (SAFE..DANGEROUS) for easy UI thresholding
    is_scam: bool  # convenience: level >= 2
    brand: str | None = None  # impersonated brand, if detected
    headline: str  # one plain-English sentence for the banner
    reasons: list[str] = Field(default_factory=list)  # supporting red flags
    advice: str  # what the user should do


class RiskAnalysis(BaseModel):
    target: str
    grade: str
    score: int
    risk_index: int  # 0..100 (higher = more risk)
    risk_level: str  # Minimal / Low / Medium / High / Critical
    headline: str
    summary: list[str]
    strengths: list[str]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    category_risk: list[CategoryRisk]
    cve_matches: list[CVEMatch]
    remediation: list[RemediationItem]
    scam: ScamVerdict | None = None  # present when the phishing module ran
    generated_by: str = "bastionscan-brain"


class AssessRequest(BaseModel):
    target: str
    profile: str = "standard"
    verified: bool = False
    # Enterprise Active scope: path exclusions, module allow/deny, rate caps.
    # Forwarded to the engine only for profile=active (ownership-gated DAST).
    scope: dict[str, Any] | None = None


class AssessResponse(BaseModel):
    scan: dict[str, Any]
    analysis: RiskAnalysis
