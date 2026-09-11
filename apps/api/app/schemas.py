from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import Annotated, Literal, Optional, Union
from uuid import UUID
from datetime import datetime
from enum import Enum

from app.services.action_model import ActionType, ProposalStatus  # V3.1 allowlists


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


class SourceType(str, Enum):
    DEPENDENCY = "DEPENDENCY"
    CONTAINER = "CONTAINER"
    LOG = "LOG"


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
    source_type: str = "DEPENDENCY"
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
    recommendation: Optional["RecommendationResponse"] = None


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


class RecommendationResponse(BaseModel):
    id: UUID
    finding_id: UUID
    status: str
    trust_level: Optional[str] = None
    title: str
    description: Optional[str] = None
    what: Optional[str] = None
    why: Optional[str] = None
    change: Optional[str] = None
    uncertainty: Optional[str] = None
    risk: Optional[str] = None
    validation: Optional[str] = None
    validation_state: Optional[str] = None
    validation_details: Optional[dict] = None
    validated_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ReportResponse(BaseModel):
    id: UUID
    scan_id: UUID
    repository_id: UUID
    report_type: str
    format: str
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ReportDetailResponse(ReportResponse):
    content: Optional[str] = None


# ── V3.1 Action Proposals ──────────────────────────────────────────


class UpdateDependencyVersionOp(BaseModel):
    """Exact-pin dependency upgrade. No ranges, no new packages."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["UPDATE_DEPENDENCY_VERSION"]
    file: str = Field(min_length=1, max_length=1000)
    name: str = Field(min_length=1, max_length=200)
    ecosystem: Literal["npm", "pypi"]
    from_version: str = Field(min_length=1, max_length=100)
    to_version: str = Field(min_length=1, max_length=100)


class UpdateDockerfileInstructionOp(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["UPDATE_DOCKERFILE_INSTRUCTION"]
    file: str = Field(min_length=1, max_length=1000)
    line_no: int = Field(ge=1, le=100_000)
    old_text: str = Field(min_length=1, max_length=5000)
    new_text: str = Field(default="", max_length=5000)


class AppendDockerfileInstructionOp(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["APPEND_DOCKERFILE_INSTRUCTION"]
    file: str = Field(min_length=1, max_length=1000)
    after_line: int = Field(ge=0, le=100_000)
    instruction: str = Field(min_length=1, max_length=5000)


class RemoveDockerfileInstructionOp(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["REMOVE_DOCKERFILE_INSTRUCTION"]
    file: str = Field(min_length=1, max_length=1000)
    line_no: int = Field(ge=1, le=100_000)


class UpdateConfigurationValueOp(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["UPDATE_CONFIGURATION_VALUE"]
    file: str = Field(min_length=1, max_length=1000)
    key: str = Field(min_length=1, max_length=500)
    value: str = Field(min_length=1, max_length=5000)


class ReplaceTextOp(BaseModel):
    """Documentation-only text replacement (DOCUMENTED_SECURITY_FIX)."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["REPLACE_TEXT"]
    file: str = Field(min_length=1, max_length=1000)
    old_text: str = Field(min_length=1, max_length=5000)
    new_text: str = Field(default="", max_length=5000)


ActionOperation = Annotated[
    Union[
        UpdateDependencyVersionOp,
        UpdateDockerfileInstructionOp,
        AppendDockerfileInstructionOp,
        RemoveDockerfileInstructionOp,
        UpdateConfigurationValueOp,
        ReplaceTextOp,
    ],
    Field(discriminator="type"),
]


class ActionProposalCreate(BaseModel):
    """Create a proposal. Never executes anything.

    Expiry, risk, validation state, ownership and policy inputs are all
    server-derived; the client supplies only the action content.
    """

    model_config = ConfigDict(extra="forbid")

    recommendation_id: UUID
    action_type: ActionType
    files: list[str] = Field(min_length=1, max_length=10)
    operations: list[ActionOperation] = Field(min_length=1, max_length=50)
    expected_diff: str = Field(default="", max_length=50_000)
    target_branch: str = Field(min_length=1, max_length=255)
    base_commit_sha: str = Field(min_length=40, max_length=40)
    rationale: str = Field(default="", max_length=2000)


class PolicyDecisionResponse(BaseModel):
    decision: str
    policy_version: str
    reason_code: str
    explanation: Optional[str] = None
    matched_rule: str
    approval_level: Optional[str] = None


class ActionProposalResponse(BaseModel):
    """Read-only proposal response. Contains no secrets by construction."""

    id: UUID
    finding_id: UUID
    recommendation_id: UUID
    repository_id: UUID
    action_type: ActionType
    status: ProposalStatus
    base_commit_sha: str
    target_branch: str
    files: list[str]
    operations: list[dict]
    expected_diff: str
    rationale: Optional[str] = None
    risk_score: int
    risk_level: str
    recommendation_trust: Optional[str] = None
    validation_state: Optional[str] = None
    policy_version: str
    policy_decision: str
    policy_reason_code: str
    policy_matched_rule: str
    policy_explanation: Optional[str] = None
    action_digest: str
    expires_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# Rebuild models with forward references
FindingDetailResponse.model_rebuild()
