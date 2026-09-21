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


# ── V3.2 Action Approvals (authorization data only — no execution) ──


class ApprovalCreate(BaseModel):
    """Approve (or reject) an action proposal.

    The client supplies only human metadata. The action digest is
    recalculated server-side; expiry, policy, and eligibility are all
    server-derived. Never executes anything.
    """

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="", max_length=2000)
    # Second principal identity for HIGH/CRITICAL risk proposals.
    # The SERVER verifies step-up freshness for both principals.
    second_approver_user_id: Optional[UUID] = None


class RejectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="", max_length=2000)


class RevocationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="", max_length=2000)


class TokenConsumeRequest(BaseModel):
    """Present a one-time authorization token. Non-executing verification
    endpoint (executor consumes authorization through this in V3.4+)."""

    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=8, max_length=256)


class ApprovalResponse(BaseModel):
    """Approval metadata. NEVER contains token material — the plaintext
    one-time token is returned exactly once, only in ApprovalIssuedResponse."""

    id: UUID
    action_proposal_id: UUID
    action_digest: str
    approver_user_id: UUID
    second_approver_user_id: Optional[UUID] = None
    approval_state: str
    approval_reason: Optional[str] = None
    policy_version: str
    policy_decision: str
    approval_level: Optional[str] = None
    approved_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    authorization_issued_at: Optional[datetime] = None
    authorization_used_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ApprovalIssuedResponse(ApprovalResponse):
    """One-time issuance response: the ONLY place the plaintext token exists."""

    authorization_token: str


# ── V3.3 Execution authorization (the final deterministic gate — still no execution) ──


class ExecutionAuthorizationCreate(BaseModel):
    """Request to authorize execution of an approved action.

    The client supplies NOTHING security-relevant: no digest, no policy
    decision, no risk, no approval state, no authorized=true. Every
    security value is loaded and recomputed server-side (§31).
    """

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="", max_length=2000)


class ExecutionAuthorizationResponse(BaseModel):
    """Authorization metadata. Non-executable: contains authorization
    identity and scope bindings, never commands, credentials, URLs, or
    secrets. The one-time approval token is NEVER present here."""

    id: UUID
    action_proposal_id: UUID
    approval_id: UUID
    action_digest: str
    repository_id: UUID
    base_commit_sha: str
    target_branch: str
    policy_version: str
    policy_decision: str
    authorization_state: str
    contract: dict
    contract_digest: str
    contract_version: str
    authorized_by_user_id: UUID
    consumed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ExecutionAuthorizationConsumeRequest(BaseModel):
    """Present the one-time approval token to consume the authorization.
    Atomic, single-use; exactly one concurrent consumer succeeds."""

    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=8, max_length=256)


class ExecutionAuthorizationRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="", max_length=2000)


# ── V3.4 — sandboxed execution ───────────────────────────────────────


class ExecutionAdmissionRequest(BaseModel):
    """Internal executor admission request (§87/§88).

    NOT user-facing: service identity only. The client supplies nothing
    security-relevant — the run binds to the authorization record named
    by execution_authorization_id, verified server-side in the admission
    transaction. Forged authorized/decision/state fields are rejected
    (extra="forbid"), never honored.
    """

    model_config = ConfigDict(extra="forbid")

    execution_authorization_id: UUID
    token: str = Field(min_length=8, max_length=256)  # the one-time approval token


class GitRemediationStartRequest(BaseModel):
    """User request to start Git/GitHub remediation for a verified run.

    Supplies NOTHING security-relevant: no branch name, no stage ceiling,
    no digest, no repository identity. Every authorization value is
    server-derived (extra="forbid" rejects authority parameters).
    """

    model_config = ConfigDict(extra="forbid")


# ── V3.5 — controlled Git/GitHub remediation ─────────────────────────


class GitRemediationResponse(BaseModel):
    """Bounded remediation metadata. No credentials, no tokens, no
    workspace content, no unbounded logs."""

    id: UUID
    execution_run_id: UUID
    execution_authorization_id: UUID
    action_proposal_id: UUID
    repository_id: UUID
    action_digest: str
    remediation_state: str
    fail_reason_code: Optional[str] = None
    fail_detail: Optional[str] = None
    repo_owner: str
    repo_name: str
    base_commit_sha: str
    source_branch: str
    target_branch: str
    remediation_branch: str
    committed_sha: Optional[str] = None
    pushed_sha: Optional[str] = None
    pr_number: Optional[int] = None
    pr_url: Optional[str] = None
    pr_state: Optional[str] = None
    stage_ceiling: str
    cleanup_status: str
    created_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ── V3.6 — verification + rollback ─────────────────────────────────


class VerificationStartRequest(BaseModel):
    """User request to verify a committed remediation.

    Supplies NOTHING security-relevant (extra="forbid" rejects authority
    parameters like verified=true, result=PASS, plan overrides). Every
    verification input is server-derived from the frozen plan."""

    model_config = ConfigDict(extra="forbid")


class VerificationCheckResponse(BaseModel):
    """One deterministic check + its bounded evidence. Evidence contains
    expected/observed conditions only — never raw repository output."""

    check_type: str
    check_version: str
    result: str
    reason_code: str
    evidence: dict

    model_config = {"from_attributes": True}


class VerificationRunResponse(BaseModel):
    """Bounded verification metadata. No credentials, no tokens, no
    workspace content, no unbounded repository output."""

    id: UUID
    git_remediation_id: UUID
    execution_run_id: UUID
    repository_id: UUID
    action_digest: str
    verification_state: str
    result: Optional[str] = None
    reason_code: Optional[str] = None
    detail: Optional[str] = None
    plan_version: str
    plan_digest: str
    checks_total: int
    checks_passed: int
    checks_failed: int
    checks_other: int
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    verification_plan: dict

    model_config = {"from_attributes": True}


class RollbackStartRequest(BaseModel):
    """User request to roll back a pushed remediation.

    Supplies NOTHING security-relevant: NO SHA, no branch name, no
    target (extra="forbid" rejects rollback_sha=... style authority
    parameters). The rollback target is server-derived from the frozen
    contract."""

    model_config = ConfigDict(extra="forbid")


class RollbackRunResponse(BaseModel):
    """Bounded rollback metadata. The target SHA here is the server-
    derived constant copied from the frozen contract — accepting it as
    input is impossible by construction."""

    id: UUID
    git_remediation_id: UUID
    repository_id: UUID
    action_digest: str
    rollback_state: str
    fail_reason_code: Optional[str] = None
    fail_detail: Optional[str] = None
    rollback_target_sha: str
    expected_branch_sha: str
    revert_branch: str
    revert_sha: Optional[str] = None
    revert_pr_number: Optional[int] = None
    revert_pr_url: Optional[str] = None
    cleanup_status: str
    created_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ExecutionRunResponse(BaseModel):
    """Bounded execution-run metadata (§48). No secrets, no workspace
    content, no credentials, no unbounded logs. Status words are
    ADMISSION_PENDING/EXECUTING/RESULT_READY/COMPLETED/FAILED/
    CLEANUP_FAILED — never VERIFIED/FIXED/SAFE (V3.6 does not exist)."""

    id: UUID
    execution_authorization_id: UUID
    action_proposal_id: UUID
    repository_id: UUID
    action_digest: str
    contract_digest: str
    run_state: str
    fail_reason_code: Optional[str] = None
    fail_detail: Optional[str] = None
    execution_profile: str
    resource_profile: dict
    cleanup_status: str
    cleanup_detail: Optional[str] = None
    result: Optional[dict] = None
    diff_digest: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}
