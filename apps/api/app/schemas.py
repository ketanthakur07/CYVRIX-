from pydantic import BaseModel, Field, field_validator
from typing import Optional
from uuid import UUID
from datetime import datetime
from enum import Enum


# ── Enums ──────────────────────────────────────────────────────────

class ScanStatus(str, Enum):
    QUEUED = "QUEUED"
    CLONING = "CLONING"
    SCANNING = "SCANNING"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"


class InvestigationStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    UNLIKELY = "UNLIKELY"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    UNKNOWN = "UNKNOWN"


class Exploitability(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    UNKNOWN = "UNKNOWN"


class Exposure(str, Enum):
    INTERNAL = "INTERNAL"
    EXTERNAL = "EXTERNAL"
    UNKNOWN = "UNKNOWN"


class RiskLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ── Evidence ───────────────────────────────────────────────────────

class EvidenceItem(BaseModel):
    file: str
    line: int = 0
    reason: str


# ── Investigation Result (LLM contract) ───────────────────────────

class InvestigationResult(BaseModel):
    verdict: Verdict
    exploitability: Exploitability
    exposure: Exposure
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(min_length=1, max_length=500)
    evidence: list[EvidenceItem] = []
    assumptions: list[str] = []
    uncertainties: list[str] = []
    recommendation: str = Field(min_length=1, max_length=500)


# ── Risk Assessment ────────────────────────────────────────────────

class RiskFactors(BaseModel):
    base_score: int
    exposure_mod: int = 0
    exploit_mod: int = 0
    confidence_mod: int = 0
    ai_available: bool = True
    degraded: bool = False


class RiskAssessmentResponse(BaseModel):
    id: UUID
    finding_id: UUID
    risk_score: int
    risk_level: RiskLevel
    risk_version: int
    factors: RiskFactors
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ── User ───────────────────────────────────────────────────────────

class UserResponse(BaseModel):
    id: UUID
    email: str
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ── GitHub Installation ────────────────────────────────────────────

class GithubInstallationResponse(BaseModel):
    id: UUID
    installation_id: int
    account_login: str
    account_type: str
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ── Repository ─────────────────────────────────────────────────────

class RepositoryResponse(BaseModel):
    id: UUID
    github_repo_id: int
    owner: str
    name: str
    default_branch: str
    is_active: bool
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class RepositoryToggleRequest(BaseModel):
    is_active: bool


# ── Scan ───────────────────────────────────────────────────────────

class ScanResponse(BaseModel):
    id: UUID
    repository_id: UUID
    status: ScanStatus
    trigger: str
    error_reason: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    commit_sha: Optional[str] = None
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ScanCreateRequest(BaseModel):
    repository_id: UUID


# ── Dependency ─────────────────────────────────────────────────────

class DependencyResponse(BaseModel):
    id: UUID
    name: str
    version: str
    ecosystem: str
    manifest_path: str

    model_config = {"from_attributes": True}


# ── Finding ────────────────────────────────────────────────────────

class FindingResponse(BaseModel):
    id: UUID
    scan_id: UUID
    repository_id: UUID
    fingerprint: str
    scanner: str
    vulnerability_id: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: Severity
    status: FindingStatus
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class FindingDetailResponse(FindingResponse):
    investigation: Optional["InvestigationResponse"] = None
    risk_assessment: Optional[RiskAssessmentResponse] = None


# ── Investigation ──────────────────────────────────────────────────

class InvestigationResponse(BaseModel):
    id: UUID
    finding_id: UUID
    status: InvestigationStatus
    verdict: Optional[Verdict] = None
    exploitability: Optional[Exploitability] = None
    exposure: Optional[Exposure] = None
    confidence: Optional[float] = None
    summary: Optional[str] = None
    evidence: Optional[list[EvidenceItem]] = None
    assumptions: Optional[list[str]] = None
    uncertainties: Optional[list[str]] = None
    recommendation: Optional[str] = None
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ── Dashboard Aggregates ──────────────────────────────────────────

class SeverityCount(BaseModel):
    severity: str
    count: int


class DashboardSummary(BaseModel):
    total_repositories: int
    total_scans: int
    total_findings: int
    findings_by_severity: list[SeverityCount]
    recent_scans: list[ScanResponse]


class RepositorySummary(BaseModel):
    repository: RepositoryResponse
    total_findings: int
    findings_by_severity: list[SeverityCount]
    latest_scan: Optional[ScanResponse] = None
    risk_score: Optional[int] = None


# ── Audit Event ────────────────────────────────────────────────────

class AuditEventResponse(BaseModel):
    id: UUID
    event_type: str
    metadata: Optional[dict] = None
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# Rebuild models with forward references
FindingDetailResponse.model_rebuild()
