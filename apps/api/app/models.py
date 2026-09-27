import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Text, Boolean, Integer, BigInteger, Numeric,
    ForeignKey, UniqueConstraint, Index, DateTime, text
)
from sqlalchemy.dialects.postgresql import UUID
from app.types import JSONBCompat as JSONB
from sqlalchemy.orm import relationship
from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


def gen_uuid():
    return uuid.uuid4()


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    email = Column(Text, unique=True, nullable=False)
    github_id = Column(Integer, unique=True, nullable=True)
    github_login = Column(Text, nullable=True)
    role = Column(Text, nullable=False, server_default="USER", default="USER")  # USER|OPERATOR|ADMIN
    created_at = Column(DateTime(timezone=True), default=utcnow)

    installations = relationship("GithubInstallation", back_populates="user")


class GithubInstallation(Base):
    __tablename__ = "github_installations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    installation_id = Column(BigInteger, unique=True, nullable=False)
    account_login = Column(Text, nullable=False)
    account_type = Column(Text, nullable=False)  # 'User' | 'Organization'
    # V4.0 tenancy: the organization that owns this integration. Nullable so
    # the migration can backfill existing rows (one personal org per owner)
    # without breaking V3 ownership (user_id remains the legacy owner and is
    # still honored when organization_id is NULL).
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True
    )
    created_at = Column(DateTime(timezone=True), default=utcnow)

    user = relationship("User", back_populates="installations")
    organization = relationship("Organization", back_populates="installations")
    repositories = relationship("Repository", back_populates="installation")


class Repository(Base):
    __tablename__ = "repositories"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    installation_id = Column(UUID(as_uuid=True), ForeignKey("github_installations.id"), nullable=False)
    github_repo_id = Column(BigInteger, unique=True, nullable=False)
    owner = Column(Text, nullable=False)
    name = Column(Text, nullable=False)
    default_branch = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("owner", "name", name="uq_owner_name"),
    )

    installation = relationship("GithubInstallation", back_populates="repositories")
    scans = relationship("Scan", back_populates="repository")
    findings = relationship("Finding", back_populates="repository")
    reports = relationship("Report", back_populates="repository")
    action_proposals = relationship("ActionProposal", back_populates="repository")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False)
    status = Column(Text, nullable=False, default="QUEUED")  # QUEUED|CLONING|SCANNING|ANALYZING|COMPLETED|FAILED
    trigger = Column(Text, nullable=False, default="manual")  # manual|api|webhook|ci
    error_reason = Column(Text)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    commit_sha = Column(Text)
    # V4.1 — the exact commit this request is bound to. SERVER-SET ONLY:
    # public endpoints never accept it from the caller; the API/CI/webhook
    # paths set it server-side, and the worker refuses (COMMIT_MISMATCH)
    # when the actual clone SHA differs.
    requested_commit_sha = Column(Text)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    repository = relationship("Repository", back_populates="scans")
    dependencies = relationship("Dependency", back_populates="scan")
    findings = relationship("Finding", back_populates="scan")
    reports = relationship("Report", back_populates="scan")


class Dependency(Base):
    __tablename__ = "dependencies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    name = Column(Text, nullable=False)
    version = Column(Text, nullable=False)
    ecosystem = Column(Text, nullable=False)  # npm | PyPI
    manifest_path = Column(Text, nullable=False)

    scan = relationship("Scan", back_populates="dependencies")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False)
    fingerprint = Column(Text, nullable=False)
    scanner = Column(Text, nullable=False, default="dependency")
    source_type = Column(Text, nullable=False, default="DEPENDENCY")  # DEPENDENCY|CONTAINER|LOG
    vulnerability_id = Column(Text)
    package_name = Column(Text)
    package_version = Column(Text)
    title = Column(Text, nullable=False)
    description = Column(Text)
    severity = Column(Text, nullable=False)  # LOW|MEDIUM|HIGH|CRITICAL
    status = Column(Text, nullable=False, default="OPEN")  # OPEN|CONFIRMED|FALSE_POSITIVE|RESOLVED
    evidence = Column(JSONB)  # source-specific evidence metadata
    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("repository_id", "fingerprint", name="uq_repo_fingerprint"),
        Index("ix_findings_scan_id", "scan_id"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_source_type", "source_type"),
    )

    scan = relationship("Scan", back_populates="findings")
    repository = relationship("Repository", back_populates="findings")
    investigation = relationship("Investigation", back_populates="finding", uselist=False)
    risk_assessment = relationship("RiskAssessment", back_populates="finding", uselist=False)
    recommendation = relationship("Recommendation", back_populates="finding", uselist=False)
    action_proposals = relationship("ActionProposal", back_populates="finding")


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False, unique=True)
    status = Column(Text, nullable=False, default="PENDING")  # PENDING|RUNNING|COMPLETED|FAILED
    verdict = Column(Text)  # CONFIRMED|LIKELY|UNLIKELY|FALSE_POSITIVE|UNKNOWN
    exploitability = Column(Text)  # LOW|MEDIUM|HIGH|UNKNOWN
    exposure = Column(Text)  # INTERNAL|EXTERNAL|UNKNOWN
    confidence = Column(Numeric(3, 2))
    summary = Column(Text)
    evidence = Column(JSONB)
    assumptions = Column(JSONB)
    uncertainties = Column(JSONB)
    recommendation = Column(Text)
    raw_model_response = Column(JSONB)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    finding = relationship("Finding", back_populates="investigation")


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False)
    risk_score = Column(Integer, nullable=False)  # 0-100
    risk_level = Column(Text, nullable=False)  # INFO|LOW|MEDIUM|HIGH|CRITICAL
    risk_version = Column(Integer, nullable=False)
    factors = Column(JSONB, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    finding = relationship("Finding", back_populates="risk_assessment")


class Recommendation(Base):
    __tablename__ = "recommendations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False)
    status = Column(Text, nullable=False, default="PENDING")  # PENDING|COMPLETED|FAILED
    trust_level = Column(Text)  # SUPPORTED|LIKELY|UNCERTAIN
    title = Column(Text, nullable=False)
    description = Column(Text)
    what = Column(Text)  # What is the problem
    why = Column(Text)   # Why does it matter
    change = Column(Text)  # What change is recommended
    uncertainty = Column(Text)  # What uncertainty exists
    risk = Column(Text)  # What could break
    validation = Column(Text)  # How should it be validated
    evidence = Column(JSONB)
    raw_model_response = Column(JSONB)
    validation_state = Column(Text)  # VALIDATED|PARTIALLY_VALIDATED|UNVERIFIED|UNSAFE
    validation_details = Column(JSONB)  # evidence checks, reasons
    validated_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow)

    finding = relationship("Finding", back_populates="recommendation")
    action_proposals = relationship("ActionProposal", back_populates="recommendation")


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False)
    report_type = Column(Text, nullable=False)  # SCAN|REPOSITORY
    format = Column(Text, nullable=False, default="markdown")  # markdown|json
    content = Column(Text)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    scan = relationship("Scan")
    repository = relationship("Repository")


class ActionProposal(Base):
    """V3.1 — proposed (never executed) remediation action.

    Security properties:
    - Binds to repository + base_commit_sha + target_branch (no cross-repo drift)
    - action_digest is the canonical SHA-256 of the action's executable
      semantics; future approvals (V3.2) bind to this digest
    - Policy decision fields are persisted with policy_version
    - Identity is (recommendation_id, base_commit_sha, action_digest):
      duplicate submissions return the existing proposal (idempotency)
    - Inherits repository ownership: repository → installation → user
    """

    __tablename__ = "action_proposals"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False)
    recommendation_id = Column(UUID(as_uuid=True), ForeignKey("recommendations.id"), nullable=False)
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False)
    # V4.2 completion: NULL when the proposal was created by an
    # organization API key (public API). The actor is then witnessed in
    # the V3.8 chain by key prefix — a user attribution is never
    # fabricated for a credential.
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    action_type = Column(Text, nullable=False)  # ActionType values only
    status = Column(Text, nullable=False, default="PROPOSED")  # PROPOSED|POLICY_CHECKED|REJECTED|EXPIRED|STALE
    base_commit_sha = Column(Text, nullable=False)
    target_branch = Column(Text, nullable=False)
    files = Column(JSONB, nullable=False)  # list[str], canonical relative paths
    operations = Column(JSONB, nullable=False)  # list[dict], validated operation schemas
    expected_diff = Column(Text, nullable=False)
    rationale = Column(Text)
    evidence = Column(JSONB)

    # Risk/recommendation binding (snapshot at proposal time)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(Text, nullable=False)
    recommendation_trust = Column(Text)
    validation_state = Column(Text)

    # Policy evaluation result (deterministic, versioned)
    policy_version = Column(Text, nullable=False)
    policy_decision = Column(Text, nullable=False)  # ALLOW|REQUIRE_APPROVAL|DENY
    policy_reason_code = Column(Text, nullable=False)
    policy_matched_rule = Column(Text, nullable=False)
    policy_explanation = Column(Text)

    action_digest = Column(Text, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint(
            "recommendation_id", "base_commit_sha", "action_digest",
            name="uq_proposal_identity",
        ),
        Index("ix_action_proposals_repo_status", "repository_id", "status"),
        Index("ix_action_proposals_status_expiry", "status", "expires_at"),
        Index("ix_action_proposals_digest", "action_digest"),
    )

    finding = relationship("Finding", back_populates="action_proposals")
    recommendation = relationship("Recommendation", back_populates="action_proposals")
    repository = relationship("Repository", back_populates="action_proposals")
    approvals = relationship(
        "Approval", back_populates="proposal", cascade="all, delete-orphan"
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    repository_id = Column(UUID(as_uuid=True))
    finding_id = Column(UUID(as_uuid=True))
    event_type = Column(Text, nullable=False)
    event_metadata = Column("metadata", JSONB)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Approval(Base):
    """V3.2 — human approval of an action proposal (authorization data only).

    Security properties:
    - Binds to the exact proposal via action_digest (recalculated server-side
      at approval time; mismatch ⇒ denial + audit event, never repair)
    - authorization_token_hash is a keyed HMAC — the plaintext token is
      shown once at issuance and never persisted
    - authorization_token_hash is NULL while PENDING; set exactly once when
      the approval is granted (immutability of authorization material)
    - One live (PENDING/APPROVED) approval per proposal: uq_approvals_live
    - Second-principal rule for HIGH/CRITICAL: distinct approver_user_id /
      second_approver_user_id enforced by uq_approvals_principal
    - State transitions follow ALLOWED_TRANSITIONS in approval_model.py
    - V3.2 has NO executor: an APPROVED approval authorizes nothing by
      itself and can only be consumed by the future execution phase
    """

    __tablename__ = "approvals"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    action_proposal_id = Column(
        UUID(as_uuid=True), ForeignKey("action_proposals.id"), nullable=False
    )
    action_digest = Column(Text, nullable=False)  # copied from proposal, immutable
    approver_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    second_approver_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))

    approval_state = Column(Text, nullable=False, default="PENDING")  # ApprovalState values
    approval_reason = Column(Text)
    policy_version = Column(Text, nullable=False)
    policy_decision = Column(Text, nullable=False)  # REQUIRE_APPROVAL (never ALLOW/DENY)
    approval_level = Column(Text)  # LOW|MEDIUM|HIGH|CRITICAL snapshot

    approved_at = Column(DateTime(timezone=True))
    expires_at = Column(DateTime(timezone=True), nullable=False)  # server-derived
    authorization_token_hash = Column(Text)
    authorization_issued_at = Column(DateTime(timezone=True))
    authorization_used_at = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        # At most one live (non-terminal) approval per proposal
        Index(
            "uq_approvals_live",
            "action_proposal_id",
            unique=True,
            postgresql_where=text(
                "approval_state IN ('PENDING', 'APPROVED')"
            ),
            sqlite_where=text(
                "approval_state IN ('PENDING', 'APPROVED')"
            ),
        ),
        # Distinct principals per proposal for the second-principal rule
        # (live rounds only — terminal rounds never block later approvals)
        Index(
            "uq_approvals_principal",
            "action_proposal_id",
            "approver_user_id",
            "second_approver_user_id",
            unique=True,
            postgresql_where=text(
                "approval_state IN ('PENDING', 'APPROVED')"
            ),
            sqlite_where=text(
                "approval_state IN ('PENDING', 'APPROVED')"
            ),
        ),
        Index("ix_approvals_proposal_state", "action_proposal_id", "approval_state"),
        Index("ix_approvals_digest", "action_digest"),
    )

    proposal = relationship("ActionProposal", back_populates="approvals")
    approver = relationship("User", foreign_keys=[approver_user_id])


class ExecutionAuthorization(Base):
    """V3.3 — immutable execution authorization record (the final
    deterministic gate between APPROVED and FUTURE EXECUTION).

    Security properties:
    - Binds approval + proposal + digest + repository + commit + branch
      + policy into a frozen, digestable contract (non-executable: no
      commands, no credentials, no URLs, no secrets — the future
      executor reconstructs operations from the authoritative proposal)
    - contract_digest is computed at creation from the frozen contract;
      a later mismatch is a tamper event, never repaired
    - One live (AUTHORIZED) authorization per proposal: enforced by the
      partial unique index uq_execution_authorizations_live
    - One-time consumption: AUTHORIZED → CONSUMED is atomic with the
      approval's APPROVED → USED transition (single DB transaction,
      proposal row lock), so a token can never authorize twice
    - No independent TTL: the authorization window is exactly the
      approval window (expires with its approval; never extends it)
    - DENIED is not a state: denials produce audit events, not records
    - Records authorization decisions ONLY — no execution capability
      exists in V3.3 and nothing here enqueues or runs anything
    """

    __tablename__ = "execution_authorizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    action_proposal_id = Column(
        UUID(as_uuid=True), ForeignKey("action_proposals.id"), nullable=False
    )
    approval_id = Column(UUID(as_uuid=True), ForeignKey("approvals.id"), nullable=False)
    action_digest = Column(Text, nullable=False)  # copied, immutable
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False)
    base_commit_sha = Column(Text, nullable=False)
    target_branch = Column(Text, nullable=False)
    policy_version = Column(Text, nullable=False)
    policy_decision = Column(Text, nullable=False)  # REQUIRE_APPROVAL snapshot
    authorization_state = Column(Text, nullable=False, default="AUTHORIZED")

    # Frozen contract (JSON) + its canonical digest — tamper evidence
    contract = Column(JSONB, nullable=False)
    contract_digest = Column(Text, nullable=False)
    contract_version = Column(Text, nullable=False)

    authorized_by_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        # At most one live (AUTHORIZED) authorization per proposal
        Index(
            "uq_execution_authorizations_live",
            "action_proposal_id",
            unique=True,
            postgresql_where=text("authorization_state = 'AUTHORIZED'"),
            sqlite_where=text("authorization_state = 'AUTHORIZED'"),
        ),
        Index("ix_execution_authorizations_digest", "action_digest"),
        Index("ix_execution_authorizations_state", "authorization_state"),
        Index("ix_execution_authorizations_approval", "approval_id"),
    )


class ExecutionRun(Base):
    """V3.4 — one sandboxed execution lifecycle, bound to exactly one V3.3
    execution authorization.

    Security properties:
    - Admission is atomic: a partial UNIQUE live index
      (ADMISSION_PENDING/EXECUTING per authorization) + in-lock re-checks
      guarantee two executors can never both reserve one authorization
    - At-most-once logical effect (V4.2 Phase 6: at-least-once delivery
      + idempotent processing): a UNIQUE completed index makes replayed
      admissions fail at the database level
    - run_state follows ExecutionRunState transitions; FAILED and
      CLEANUP_FAILED are terminal; there is no VERIFIED state (V3.6)
    - cleanup_status records teardown independently of run success so a
      leaked sandbox can never be reported as a clean success
    - result is bounded metadata only: no secrets, no credentials,
      no workspace content, no executable material
    - resource_profile freezes the limits the run executed under
    """

    __tablename__ = "execution_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    execution_authorization_id = Column(
        UUID(as_uuid=True), ForeignKey("execution_authorizations.id"), nullable=False
    )
    action_proposal_id = Column(
        UUID(as_uuid=True), ForeignKey("action_proposals.id"), nullable=False
    )
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False)
    action_digest = Column(Text, nullable=False)  # copied, immutable
    contract_digest = Column(Text, nullable=False)
    run_state = Column(Text, nullable=False, default="ADMISSION_PENDING")
    fail_reason_code = Column(Text)  # stable taxonomy, not raw errors
    fail_detail = Column(Text)       # bounded, non-secret
    execution_profile = Column(Text, nullable=False)  # server-derived
    resource_profile = Column(JSONB, nullable=False)  # frozen limits
    cleanup_status = Column(Text, nullable=False, default="NOT_STARTED")
    cleanup_detail = Column(Text)
    result = Column(JSONB)           # bounded ExecutorResult metadata
    diff_digest = Column(Text)       # change-set digest (V3.6/V3.7 input)
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index(
            "uq_execution_runs_live",
            "execution_authorization_id",
            unique=True,
            postgresql_where=text(
                "run_state IN ('ADMISSION_PENDING', 'EXECUTING')"
            ),
            sqlite_where=text(
                "run_state IN ('ADMISSION_PENDING', 'EXECUTING')"
            ),
        ),
        Index(
            "uq_execution_runs_done",
            "execution_authorization_id",
            unique=True,
            postgresql_where=text(
                "run_state IN ('RESULT_READY', 'COMPLETED', 'CLEANUP_FAILED')"
            ),
            sqlite_where=text(
                "run_state IN ('RESULT_READY', 'COMPLETED', 'CLEANUP_FAILED')"
            ),
        ),
        Index("ix_execution_runs_state", "run_state"),
        Index("ix_execution_runs_digest", "action_digest"),
        Index("ix_execution_runs_repository", "repository_id"),
    )


class WorkspaceSnapshot(Base):
    """V3.4 — content-addressed BEFORE/AFTER workspace snapshot for one
    execution run. Hashes only; file content is never persisted. This is
    the base/result evidence later consumed by V3.6 verification and
    V3.7 rollback.
    """

    __tablename__ = "workspace_snapshots"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    execution_run_id = Column(
        UUID(as_uuid=True), ForeignKey("execution_runs.id"), nullable=False
    )
    phase = Column(Text, nullable=False)  # BEFORE | AFTER
    file_path = Column(Text, nullable=False)
    content_sha256 = Column(Text, nullable=False)
    size_bytes = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint(
            "execution_run_id", "phase", "file_path",
            name="uq_workspace_snapshots_file",
        ),
        Index("ix_workspace_snapshots_run", "execution_run_id"),
    )


class SystemControl(Base):
    """V3.3 — server-owned operational control flags (kill switch etc.).

    Unknown/missing/unreadable controls fail closed in the services that
    consult them. Values are plain strings; interpretation is per-key.
    """

    __tablename__ = "system_controls"

    key = Column(Text, primary_key=True, nullable=False)
    value = Column(Text, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class GitRemediation(Base):
    """V3.5 — controlled Git/GitHub remediation of one verified V3.4 run.

    Security properties:
    - Created ONLY from server-side verified run state (RESULT_READY or
      COMPLETED with host-side scope verification) — never from client
      claims; the client supplies nothing security-relevant
    - At-most-once logical effect (V4.2 Phase 6: at-least-once delivery
      + idempotent processing): UNIQUE execution_run_id means a replayed
      remediation is refused at the database level
    - One live pipeline per authorization (partial unique index); one
      deterministic remediation branch per repository among live rows
    - The full Git/GitHub contract (repo identity, base SHA, branches,
      authorized file set, stage ceiling) is frozen at creation into a
      digestable contract; later mismatch is a tamper event, never repaired
    - Stage ceiling is server-derived (LOCAL_ONLY < COMMIT_ALLOWED <
      PUSH_ALLOWED < PR_ALLOWED); no implicit privilege escalation
    - GitHub credential issuances are audit-recorded WITHOUT token material
    - NO force push, NO default-branch push — enforced in the Git layer
    """

    __tablename__ = "git_remediations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    execution_run_id = Column(
        UUID(as_uuid=True), ForeignKey("execution_runs.id"), nullable=False
    )
    execution_authorization_id = Column(
        UUID(as_uuid=True), ForeignKey("execution_authorizations.id"), nullable=False
    )
    action_proposal_id = Column(
        UUID(as_uuid=True), ForeignKey("action_proposals.id"), nullable=False
    )
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False)
    action_digest = Column(Text, nullable=False)  # copied, immutable

    # Frozen contract + its canonical digest (tamper evidence)
    remediation_contract = Column(JSONB, nullable=False)
    remediation_contract_digest = Column(Text, nullable=False)
    contract_version = Column(Text, nullable=False)

    # Canonical repository identity (verified against ownership chain AND
    # the GitHub remote before any push)
    repo_owner = Column(Text, nullable=False)
    repo_name = Column(Text, nullable=False)
    installation_id = Column(BigInteger, nullable=False)
    base_commit_sha = Column(Text, nullable=False)
    source_branch = Column(Text, nullable=False)
    target_branch = Column(Text, nullable=False)

    remediation_state = Column(Text, nullable=False, default="PENDING")
    fail_reason_code = Column(Text)
    fail_detail = Column(Text)

    remediation_branch = Column(Text, nullable=False)  # server-generated
    committed_sha = Column(Text)
    pushed_sha = Column(Text)
    pr_number = Column(Integer)
    pr_url = Column(Text)
    pr_state = Column(Text)

    stage_ceiling = Column(Text, nullable=False)
    cleanup_status = Column(Text, nullable=False, default="NOT_STARTED")
    cleanup_detail = Column(Text)

    created_by_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    finished_at = Column(DateTime(timezone=True))

    __table_args__ = (
        # At-most-once logical effect per execution run
        Index("uq_git_remediations_run", "execution_run_id", unique=True),
        # At most one live pipeline per authorization
        Index(
            "uq_git_remediations_live",
            "execution_authorization_id",
            unique=True,
            postgresql_where=text(
                "remediation_state IN ('PENDING', 'VERIFYING', 'COMMITTING', "
                "'COMMITTED', 'PUSHING', 'PUSHED', 'PR_CREATING')"
            ),
            sqlite_where=text(
                "remediation_state IN ('PENDING', 'VERIFYING', 'COMMITTING', "
                "'COMMITTED', 'PUSHING', 'PUSHED', 'PR_CREATING')"
            ),
        ),
        # Branch-name collision guard among live rows
        Index(
            "uq_git_remediations_branch_live",
            "repository_id", "remediation_branch",
            unique=True,
            postgresql_where=text(
                "remediation_state IN ('PENDING', 'VERIFYING', 'COMMITTING', "
                "'COMMITTED', 'PUSHING', 'PUSHED', 'PR_CREATING', 'PR_CREATED')"
            ),
            sqlite_where=text(
                "remediation_state IN ('PENDING', 'VERIFYING', 'COMMITTING', "
                "'COMMITTED', 'PUSHING', 'PUSHED', 'PR_CREATING', 'PR_CREATED')"
            ),
        ),
        Index("ix_git_remediations_state", "remediation_state"),
        Index("ix_git_remediations_repo", "repository_id"),
        Index("ix_git_remediations_digest", "action_digest"),
    )


class VerificationRun(Base):
    """V3.6 — one verification lifecycle for one committed Git remediation.

    Security properties:
    - Created ONLY from server-side remediation state (PR_CREATED/
      PUSHED/COMMITTED with committed_sha present) — never client claims;
      the request body carries NOTHING security-relevant
    - At-most-once logical effect per remediation (V4.2 Phase 6:
      at-least-once delivery + idempotent processing): UNIQUE
      git_remediation_id; a verification verdict is final;
      re-verification is a new decision made through a new remediation,
      never a state rewrite
    - The frozen VerificationPlan + its canonical digest are persisted;
      a later plan-digest mismatch is a tamper event, never repaired
    - result ∈ PASS/FAIL/INCONCLUSIVE/SKIPPED/BLOCKED (Phase 3); COMPLETED
      is recorded only after ALL planned checks have evidence rows
    - evidence is bounded + scrubbed; repository output is untrusted data
    """

    __tablename__ = "verification_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    git_remediation_id = Column(
        UUID(as_uuid=True), ForeignKey("git_remediations.id"), nullable=False
    )
    execution_run_id = Column(
        UUID(as_uuid=True), ForeignKey("execution_runs.id"), nullable=False
    )
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False)
    action_digest = Column(Text, nullable=False)  # copied, immutable

    verification_state = Column(Text, nullable=False, default="PENDING")
    result = Column(Text)  # PASS|FAIL|INCONCLUSIVE|SKIPPED|BLOCKED (on COMPLETED)
    reason_code = Column(Text)
    detail = Column(Text)

    # Frozen plan + digest (tamper evidence)
    verification_plan = Column(JSONB, nullable=False)
    plan_digest = Column(Text, nullable=False)
    plan_version = Column(Text, nullable=False)

    checks_total = Column(Integer, nullable=False, default=0)
    checks_passed = Column(Integer, nullable=False, default=0)
    checks_failed = Column(Integer, nullable=False, default=0)
    checks_other = Column(Integer, nullable=False, default=0)

    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        # At-most-once logical effect per remediation (UNIQUE guard)
        Index("uq_verification_runs_remediation", "git_remediation_id", unique=True),
        Index("ix_verification_runs_state", "verification_state"),
        Index("ix_verification_runs_repo", "repository_id"),
    )


class VerificationCheck(Base):
    """V3.6 — one deterministic verification check + its bounded evidence.

    One row per planned check per verification run. Evidence contains
    expected/observed conditions (scrubbed, bounded) — never raw command
    output, never secret-shaped material, never repository claims.
    """

    __tablename__ = "verification_checks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    verification_run_id = Column(
        UUID(as_uuid=True), ForeignKey("verification_runs.id"), nullable=False
    )
    check_type = Column(Text, nullable=False)
    check_version = Column(Text, nullable=False)
    result = Column(Text, nullable=False)  # PASS|FAIL|INCONCLUSIVE|SKIPPED|BLOCKED
    reason_code = Column(Text, nullable=False)
    evidence = Column(JSONB, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint(
            "verification_run_id", "check_type", name="uq_verification_checks_type"
        ),
        Index("ix_verification_checks_run", "verification_run_id"),
    )


class RollbackRun(Base):
    """V3.6 — one controlled rollback of one pushed Git remediation.

    Security properties:
    - Created ONLY for remediations whose push actually happened
      (pushed_sha present) — there is no rollback of a local-only commit
    - The rollback TARGET is server-derived: the frozen contract's
      base_commit_sha. The client can never name a SHA (no arbitrary-SHA
      rollback endpoint exists by design)
    - At-most-once logical effect per remediation (V4.2 Phase 6:
      at-least-once delivery + idempotent processing; UNIQUE
      git_remediation_id — the idempotency key IS the remediation
      identity)
    - Pre-flight state verification: the remote remediation branch tip
      must still equal the remediation's pushed_sha; a moved/stale branch
      → CONFLICT (fail closed, no blind rollback)
    - Mechanism: NEW revert branch + revert commit + PR (Phase 19) —
      NO force push, NO history rewrite, NO default-branch mutation
    - COMPLETED is recorded only after post-rollback verification proved
      the revert landed on the remote (never success-before-proof)
    """

    __tablename__ = "rollback_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    git_remediation_id = Column(
        UUID(as_uuid=True), ForeignKey("git_remediations.id"), nullable=False
    )
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False)
    action_digest = Column(Text, nullable=False)  # copied, immutable

    rollback_state = Column(Text, nullable=False, default="PENDING")
    fail_reason_code = Column(Text)
    fail_detail = Column(Text)

    # Server-derived target + verification context (no client input)
    rollback_target_sha = Column(Text, nullable=False)   # contract base_commit_sha
    expected_branch_sha = Column(Text, nullable=False)   # remediation pushed_sha at request time
    revert_branch = Column(Text, nullable=False)         # server-generated
    revert_sha = Column(Text)
    revert_pr_number = Column(Integer)
    revert_pr_url = Column(Text)

    cleanup_status = Column(Text, nullable=False, default="NOT_STARTED")
    cleanup_detail = Column(Text)

    # V4.2 completion: NULL when the rollback was requested by an
    # organization API key (public API); the key identity is witnessed
    # in the V3.8 chain instead of fabricating a user attribution.
    requested_by_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    finished_at = Column(DateTime(timezone=True))

    __table_args__ = (
        # V4.2 terminology (Phase 6): delivery is at-least-once; the
        # application-layer idempotency (unique index on the remediation
        # identity + terminal-state guards) yields at-most-once logical
        # EFFECT. "Exactly-once" below means exactly that combination.
        Index("uq_rollback_runs_remediation", "git_remediation_id", unique=True),
        # Branch-name collision guard among live rows
        Index(
            "uq_rollback_runs_branch_live",
            "repository_id", "revert_branch",
            unique=True,
            postgresql_where=text(
                "rollback_state IN ('PENDING', 'PRECHECK', 'ROLLING_BACK', 'VERIFYING')"
            ),
            sqlite_where=text(
                "rollback_state IN ('PENDING', 'PRECHECK', 'ROLLING_BACK', 'VERIFYING')"
            ),
        ),
        Index("ix_rollback_runs_state", "rollback_state"),
        Index("ix_rollback_runs_repo", "repository_id"),
    )


class RepositoryControl(Base):
    """V3.7 — per-repository operational control (tenant-owned).

    One row per repository. ENABLED is the only state that permits new
    execution/mutation for the repo. PAUSED contains the repo while
    preserving verification (read-only) work; BLOCKED stops everything.
    Only authorized operators may change it; clients can never select or
    set arbitrary repository controls. Unknown/missing state fails closed
    in the services that consult it.
    """

    __tablename__ = "repository_controls"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    repository_id = Column(
        UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False, unique=True
    )
    control_state = Column(Text, nullable=False, default="ENABLED")  # ENABLED|PAUSED|BLOCKED
    reason = Column(Text)  # bounded, non-secret
    updated_by_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ix_repository_controls_state", "control_state"),
    )


class CircuitBreaker(Base):
    """V3.7 — per-repository, per-scope circuit breaker.

    Bounded consecutive failures open the breaker; only an explicit
    operator reset closes it again. OPEN denies new automatic execution
    for that (repository, scope, action_type). Unprovisioned/unknown
    state fails closed.
    """

    __tablename__ = "circuit_breakers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False)
    scope = Column(Text, nullable=False)  # EXECUTION|REMEDIATION|VERIFICATION|ROLLBACK
    action_type = Column(Text, nullable=False, server_default="ANY")
    breaker_state = Column(Text, nullable=False, default="CLOSED")  # CLOSED|OPEN
    consecutive_failures = Column(Integer, nullable=False, server_default="0", default=0)
    max_consecutive_failures = Column(Integer, nullable=False, server_default="3", default=3)
    opened_at = Column(DateTime(timezone=True))
    opened_reason_code = Column(Text)
    reset_by_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    __table_args__ = (
        UniqueConstraint("repository_id", "scope", "action_type", name="uq_circuit_breakers_scope"),
        Index("ix_circuit_breakers_state", "breaker_state"),
    )


class ExecutionLease(Base):
    """V3.7 — explicit job ownership for long-running pipelines.

    At most one ACTIVE lease per subject. A lease records the owner,
    the attempt, a heartbeat and an expiry. Expired leases never authorize
    anything by themselves: recovery goes through the reconciliation
    engine, which reconciles external state before any retry. Lease rows
    are diagnostic + coordination data — never authorization material.
    """

    __tablename__ = "execution_leases"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    subject_type = Column(Text, nullable=False)  # GIT_REMEDIATION|ROLLBACK|EXECUTION_RUN
    subject_id = Column(UUID(as_uuid=True), nullable=False)
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False)
    lease_owner_id = Column(Text, nullable=False)  # worker/executor identity, not a user
    attempt = Column(Integer, nullable=False, server_default="1", default=1)
    lease_state = Column(Text, nullable=False, default="ACTIVE")  # ACTIVE|EXPIRED|RELEASED
    heartbeat_at = Column(DateTime(timezone=True), default=utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index(
            "uq_execution_leases_active",
            "subject_id",
            unique=True,
            postgresql_where=text("lease_state = 'ACTIVE'"),
            sqlite_where=text("lease_state = 'ACTIVE'"),
        ),
        Index("ix_execution_leases_state", "lease_state"),
        Index("ix_execution_leases_subject", "subject_type", "subject_id"),
    )


class ReconciliationRun(Base):
    """V3.7 — one deterministic, idempotent reconciliation pass.

    Records what the engine inspected and what it decided (counts and
    bounded findings). Reconciliation never mutates repositories and
    never authorizes anything; it classifies state and marks rows for
    operator-visible recovery.
    """

    __tablename__ = "reconciliation_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    trigger = Column(Text, nullable=False, default="OPERATOR")  # OPERATOR|STARTUP|PERIODIC
    status = Column(Text, nullable=False, default="RUNNING")  # RUNNING|COMPLETED|FAILED
    findings = Column(JSONB)  # bounded list of {subject, classification, reason}
    stats = Column(JSONB)     # bounded counters (inspected/reconciled/orphans)
    detail = Column(Text)     # bounded failure detail when FAILED
    started_by_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), default=utcnow)
    finished_at = Column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_reconciliation_runs_status", "status"),
    )


class OperationalEvent(Base):
    """V3.7 — operational audit event (Phase 47).

    Structured, secret-free operational telemetry: state transitions,
    circuit changes, lease expiry, reconciliation results, quota denials.
    Complements audit_events (remediation security events) — never
    replaces them. V3.8's immutable chain remains future work.
    """

    __tablename__ = "operational_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    event_type = Column(Text, nullable=False)
    repository_id = Column(UUID(as_uuid=True))
    subject_type = Column(Text)  # REMEDIATION|ROLLBACK|RUN|BREAKER|LEASE|...
    subject_id = Column(UUID(as_uuid=True))
    reason_code = Column(Text)
    detail = Column(Text)        # bounded, non-secret
    created_by_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index("ix_operational_events_type", "event_type"),
        Index("ix_operational_events_created", "created_at"),
    )


class AuditChain(Base):
    """V3.8 — one append-only hash chain per tenant installation.

    The chain row itself is metadata (identity + head bookkeeping); the
    security property lives in audit_events (hash-linked events) and
    audit_checkpoints (independently verifiable signed heads).
    TAMPER-EVIDENT, not physically immutable: see docs/v3-audit-integrity.md.

    V4.1: an organization may hold ZERO installations (a key-only tenant),
    so key-lifecycle and API events chain into a per-ORGANIZATION chain
    instead (organization_id set, installation_id NULL). Exactly one of
    the two owners is set per chain row; the partial unique indexes in
    migration 013 enforce that at the database level.
    """

    __tablename__ = "audit_chains"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    installation_id = Column(
        UUID(as_uuid=True), ForeignKey("github_installations.id"), nullable=True, unique=True
    )
    # V4.1 — org-level chain owner (mutually exclusive with installation_id).
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True, unique=True
    )
    # Trusted head bookkeeping — advisory for monitoring/perf only. The
    # verifier recomputes everything from events; checkpoints (signed,
    # separate table) are the truncation-detection anchor.
    last_sequence = Column(BigInteger, nullable=False, default=0)
    last_event_digest = Column(Text)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow)


class AuditChainEvent(Base):
    """V3.8 — one hash-linked, sequence-ordered integrity event.

    Security properties:
    - event_digest = SHA-256(domain || prev_digest_hex || 0x1f || canonical_payload)
      (see audit_service.canonical_event_payload / compute_event_digest)
    - (chain_id, seq) unique and (chain_id, prev_digest) unique: no two
      committed events may claim the same position or the same predecessor
    - genesis: seq == 1 with prev_digest == GENESIS_PREV_DIGEST
    - append-only through the application; UPDATE/DELETE are never issued
      (DB role separation documented in docs/v3-audit-integrity.md)
    - actor/event identity are server-derived; payloads are secret-free
      (centralized redaction before canonicalization)
    """

    __tablename__ = "audit_chain_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    chain_id = Column(UUID(as_uuid=True), ForeignKey("audit_chains.id"), nullable=False)
    seq = Column(BigInteger, nullable=False)
    event_type = Column(Text, nullable=False)
    event_version = Column(Integer, nullable=False, default=1)
    actor_type = Column(Text, nullable=False)  # USER|ADMIN|WORKER|EXECUTOR|SYSTEM|RECONCILER|GITHUB_INTEGRATION
    actor_id = Column(Text)                    # server-derived identity (user uuid, worker name, ...)
    actor_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"))
    action_id = Column(UUID(as_uuid=True))
    authorization_id = Column(UUID(as_uuid=True))
    execution_run_id = Column(UUID(as_uuid=True))
    verification_id = Column(UUID(as_uuid=True))
    rollback_id = Column(UUID(as_uuid=True))
    reason_code = Column(Text)
    result = Column(Text)                      # trusted server-side outcome
    payload = Column(JSONB)                    # secret-free evidence (redacted)
    occurred_at = Column(DateTime(timezone=True), nullable=False)
    recorded_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    prev_digest = Column(Text, nullable=False)
    event_digest = Column(Text, nullable=False)

    __table_args__ = (
        Index("uq_audit_chain_events_seq", "chain_id", "seq", unique=True),
        Index("uq_audit_chain_events_prev", "chain_id", "prev_digest", unique=True),
        Index("uq_audit_chain_events_digest", "event_digest", unique=True),
        Index("ix_audit_chain_events_type", "event_type"),
        Index("ix_audit_chain_events_repo", "repository_id"),
        Index("ix_audit_chain_events_recorded", "recorded_at"),
    )


class AuditCheckpoint(Base):
    """V3.8 — signed chain head (truncation-detection anchor).

    Checkpoints are HMAC-Signed with a key held OUTSIDE the database
    (settings.audit_checkpoint_key; 0 disables checkpointing). An
    attacker with DB write access can rewrite rows, but cannot produce a
    valid MAC over a forged (chain, seq, digest) tuple — tampering with
    the tail or with checkpoint rows is detectable wherever a trusted
    checkpoint (or offline export) exists outside the attacker's reach.
    """

    __tablename__ = "audit_checkpoints"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    chain_id = Column(UUID(as_uuid=True), ForeignKey("audit_chains.id"), nullable=False)
    through_sequence = Column(BigInteger, nullable=False)
    head_digest = Column(Text, nullable=False)
    event_count = Column(BigInteger, nullable=False)
    payload_digest = Column(Text, nullable=False)  # canonical checkpoint material (MAC input)
    mac = Column(Text, nullable=False)             # HMAC-SHA-256(payload_digest)
    mac_key_version = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index("uq_audit_checkpoints_seq", "chain_id", "through_sequence", unique=True),
    )


class GithubCredentialIssuance(Base):
    """V3.5 — audit-only record of a short-lived, repo-scoped GitHub
    credential issuance bound to one remediation.

    The token itself is NEVER persisted (no plaintext, no hash): it lives
    only in process memory for the duration of the authorized push/PR step.
    This record makes issuance observable and revocation semantics
    auditable without creating a credential store.
    """

    __tablename__ = "github_credential_issuances"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    git_remediation_id = Column(
        UUID(as_uuid=True), ForeignKey("git_remediations.id"), nullable=False
    )
    execution_authorization_id = Column(
        UUID(as_uuid=True), ForeignKey("execution_authorizations.id"), nullable=False
    )
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False)
    installation_id = Column(BigInteger, nullable=False)
    repo_owner = Column(Text, nullable=False)
    repo_name = Column(Text, nullable=False)
    issued_at = Column(DateTime(timezone=True), default=utcnow)
    expires_at = Column(DateTime(timezone=True))
    result = Column(Text, nullable=False, default="ISSUED")  # ISSUED | DENIED
    # What the credential authorizes: the remediation pipeline push or the
    # V3.6 rollback revert push. One ISSUED issuance per (remediation,
    # purpose) — a rollback is a distinct audited authorization, not a
    # replay of the original push credential.
    purpose = Column(Text, nullable=False, server_default="REMEDIATION_PUSH")
    fail_reason_code = Column(Text)
    # NOTE: intentionally NO token column of any kind.
    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index(
            "uq_github_credential_issuances_key",
            "git_remediation_id", "purpose", "result",
            unique=True,
            postgresql_where=text("result = 'ISSUED'"),
            sqlite_where=text("result = 'ISSUED'"),
        ),
        Index("ix_github_credential_issuances_remediation",
              "git_remediation_id"),
    )


# ══════════════════════════════════════════════════════════════════════
# V4.0 — Platform foundation (organizations, memberships, API keys)
#
# An organization is a NAMESPACE, not a security boundary by itself:
# every request still resolves authenticated identity → active membership
# → resource ownership → capability. The organization is derived
# server-side from the resource, never trusted from a request field.
# ══════════════════════════════════════════════════════════════════════


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    name = Column(Text, nullable=False)
    slug = Column(Text, unique=True, nullable=False)
    # ACTIVE | DELETION_REQUESTED | ARCHIVED | DELETED (Phase 33)
    state = Column(Text, nullable=False, server_default="ACTIVE", default="ACTIVE")
    # Auto-provisioned personal organization created by the V4 migration for
    # each pre-existing installation owner. Kept distinguishable so future
    # ownership migrations can treat it deliberately.
    is_personal = Column(Boolean, nullable=False, default=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    # Versioned organization policy (Phase 12/14). The live policy is stored
    # here with its version; every superseded version is preserved in
    # organization_policy_revisions (monotonic history, never rewritten).
    policy = Column(JSONB, nullable=False, default=dict)
    policy_version = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    memberships = relationship(
        "OrganizationMembership", back_populates="organization",
        cascade="all, delete-orphan",
    )
    installations = relationship("GithubInstallation", back_populates="organization")
    invitations = relationship(
        "OrganizationInvitation", back_populates="organization",
        cascade="all, delete-orphan",
    )
    api_keys = relationship(
        "ApiKey", back_populates="organization",
        cascade="all, delete-orphan",
    )
    policy_revisions = relationship(
        "OrganizationPolicyRevision", back_populates="organization",
        cascade="all, delete-orphan",
    )


class OrganizationMembership(Base):
    """Membership is server-side state, not an `is_member` boolean.

    Only state=ACTIVE confers capabilities (see services/v4_rbac.py).
    """

    __tablename__ = "organization_memberships"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    role = Column(Text, nullable=False, default="VIEWER")
    state = Column(Text, nullable=False, default="ACTIVE")  # ACTIVE|SUSPENDED|INVITED|REMOVED
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    __table_args__ = (
        UniqueConstraint("organization_id", "user_id",
                         name="uq_org_membership"),
        Index("ix_org_memberships_user", "user_id", "state"),
        Index("ix_org_memberships_org", "organization_id", "state"),
    )

    organization = relationship("Organization", back_populates="memberships")
    user = relationship("User")


class OrganizationInvitation(Base):
    """One-time, expiring, hashed organization invitation (Phase 4).

    The plaintext token is returned exactly once at creation; only its
    SHA-256 hash is stored. The invitation is bound to the organization and
    (when provided) to a lowercase email, so a leaked link cannot be
    replayed or redirected to another org.
    """

    __tablename__ = "organization_invitations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    email = Column(Text, nullable=True)  # lowercased when present
    role = Column(Text, nullable=False, default="VIEWER")
    token_hash = Column(Text, unique=True, nullable=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    accepted_at = Column(DateTime(timezone=True))
    accepted_by_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    revoked_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index("ix_org_invitations_org", "organization_id"),
        Index("ix_org_invitations_email", "email"),
    )

    organization = relationship("Organization", back_populates="invitations")


class OrganizationPolicyRevision(Base):
    """Immutable policy history (Phase 14): a policy change never rewrites
    the version an action was evaluated against."""

    __tablename__ = "organization_policy_revisions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    version = Column(Integer, nullable=False)
    policy = Column(JSONB, nullable=False)
    changed_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("organization_id", "version",
                         name="uq_org_policy_version"),
    )

    organization = relationship("Organization", back_populates="policy_revisions")


class ApiKey(Base):
    """Scoped, hashed, revocable organization API key (Phase 23/24).

    - Only a SHA-256 hash of the secret is stored; the secret is shown once.
    - `prefix` allows identification without revealing the secret.
    - Scopes are a closed world (services/v4_rbac.py API_SCOPES).
    - The key is bound to ONE organization; it can never be used for another
      and can never manage members/policy/operations.
    """

    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    name = Column(Text, nullable=False)
    prefix = Column(Text, unique=True, nullable=False)
    key_hash = Column(Text, unique=True, nullable=False)
    scopes = Column(JSONB, nullable=False, default=list)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), default=utcnow)
    expires_at = Column(DateTime(timezone=True))
    last_used_at = Column(DateTime(timezone=True))
    revoked_at = Column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_api_keys_org", "organization_id"),
    )

    organization = relationship("Organization", back_populates="api_keys")


# ══════════════════════════════════════════════════════════════════════
# V4.1 — Idempotency / replay protection
#
# ONE primitive serves two problems that are structurally identical:
#
#   - API idempotency: `Idempotency-Key` on a public mutation, so a retry
#     of "submit a scan" cannot create a second scan.
#   - Webhook replay protection: a provider delivery id, so a re-delivered
#     GitHub event cannot be processed twice.
#
# Both reduce to: a server-side record of (tenant, namespace, client key)
# → the outcome that was produced, with a digest of the request so that
# "same key, different request" is detectable rather than silently
# returning the wrong result.
#
# The row is TENANT-SCOPED and namespaced. A key value presented by
# organization A can never match a record owned by organization B, and the
# same client key used against two different operations is two distinct
# records.
# ══════════════════════════════════════════════════════════════════════


class ApiIdempotencyKey(Base):
    """A completed (or in-flight) idempotent operation.

    Invariants enforced by the database, not by convention:
      - UNIQUE(organization_id, scope, key_value)  → one record per tenant
        per operation namespace per client key. This is what makes a
        concurrent duplicate deterministic: the loser cannot insert.
      - `request_digest` binds the record to the exact request, so replay
        with a DIFFERENT body is a conflict rather than a false replay.

    `response_status`/`response_body` store the ORIGINAL outcome so a
    legitimate retry receives the same answer instead of re-executing.
    """

    __tablename__ = "api_idempotency_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    # Operation namespace (e.g. "POST /api/v1/scans", "webhook:push").
    scope = Column(Text, nullable=False)
    # The client-supplied Idempotency-Key or provider delivery id.
    key_value = Column(Text, nullable=False)
    request_digest = Column(Text, nullable=False)
    # IN_PROGRESS | COMPLETED
    state = Column(Text, nullable=False, default="IN_PROGRESS")
    response_status = Column(Integer)
    response_body = Column(JSONB)
    # Which API key / integration produced it (audit + rotation forensics).
    actor_api_key_prefix = Column(Text)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    completed_at = Column(DateTime(timezone=True))
    # Bounded retention: replay protection must not grow without limit.
    expires_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "scope", "key_value",
            name="uq_idempotency_org_scope_key",
        ),
        Index("ix_idempotency_expiry", "expires_at"),
        Index("ix_idempotency_org_created", "organization_id", "created_at"),
    )


# ══════════════════════════════════════════════════════════════════════
# V4.1 — Inbound GitHub webhook ingestion
#
# A delivery row is a SECURITY RECORD, not a log line: it is the server's
# structured account of what GitHub sent, whether the signature was
# genuine, and what was done about it. Raw payloads are never persisted —
# only bounded, non-sensitive metadata — so the table cannot become a
# shadow store of repository content.
#
# Replay protection: UNIQUE(organization_id, delivery_id). The idempotency
# primitive reserves (org, scope="webhook:<event>", key=<delivery id>)
# inside the SAME transaction that claims this row, so a redelivered
# event is refused by the database before any processing happens.
# ══════════════════════════════════════════════════════════════════════


class WebhookDelivery(Base):
    """One received (and admitted or refused) GitHub webhook delivery.

    Fields are deliberately limited to identity/binding/outcome. There is
    no payload column: anything that could carry repository content,
    branch names, commit messages or secrets is summarized as a bounded,
    allowlisted reason code or a redacted count.
    """

    __tablename__ = "webhook_deliveries"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    # The tenant that owns this delivery. For an ADMITTED event this is
    # derived from trusted installation state. For a REFUSED event the
    # installation cannot be trusted, so the row is stored tenant-less
    # (organization_id NULL) and still counts for rate-limiting and metrics.
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True
    )
    github_delivery_id = Column(Text, nullable=False)
    event_type = Column(Text, nullable=False)
    # Signature state: VALID | INVALID | MISSING | MALFORMED
    signature_state = Column(Text, nullable=False)
    # Outcome: ACCEPTED | REJECTED
    outcome = Column(Text, nullable=False)
    reason_code = Column(Text)  # bounded, allowlisted refusal taxonomy
    # Resolved trusted state (NULL unless ADMITTED and fully bound)
    installation_pk = Column(
        UUID(as_uuid=True), ForeignKey("github_installations.id"), nullable=True
    )
    repository_pk = Column(
        UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=True
    )
    # Commit binding for push events (the exact observed head).
    commit_sha = Column(Text)
    ref = Column(Text)
    # Derived effect reference (the scan this delivery caused), so a
    # delivery can never silently duplicate a side effect.
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True)
    received_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        # One row per tenant per delivery id. Refused deliveries (no
        # trusted tenant) are exempt from uniqueness in the DB layer by
        # being NULL-keyed; the reservation primitive still blocks their
        # replay for the rate-limit window.
        UniqueConstraint(
            "organization_id", "github_delivery_id",
            name="uq_webhook_deliveries_org_delivery",
        ),
        Index("ix_webhook_deliveries_org", "organization_id"),
        Index("ix_webhook_deliveries_outcome", "outcome"),
        Index("ix_webhook_deliveries_received", "received_at"),
    )


# ══════════════════════════════════════════════════════════════════════
# V4.2 COMPLETION — Outbound webhooks (organization-scoped subscriptions)
#
# organization → endpoint (https URL + encrypted signing secret) →
# subscribed events → deliveries (signed, retried, dead-lettered).
#
# SECURITY MODEL:
#   - The signing secret is stored ENCRYPTED AT REST (Fernet, key held
#     OUTSIDE the database via settings) and is returned exactly once at
#     creation; it is never logged, never audited, never exported.
#   - The endpoint URL is validated at creation/update AND re-validated
#     at the connection (IP allowlist at socket time) — SSRF defense
#     does not trust a string prefix or a single DNS resolution.
#   - Delivery identity: (organization, endpoint, event_type,
#     delivery_id) is UNIQUE at the DB level; retries reuse the SAME
#     delivery_id, so a retry can never mint a duplicate logical event.
# ══════════════════════════════════════════════════════════════════════


class OutboundWebhookEndpoint(Base):
    """One subscribed HTTPS receiver owned by one organization.

    secret_ciphertext is Fernet-encrypted (settings-owned key). It is
    readable by the dispatcher because HMAC signing requires the secret,
    but it is NEVER serialized by any route and NEVER written to audit,
    logs, metrics, or exports. `secret_hint` (first 4 chars) exists only
    so an operator can tell which secret generation a receiver uses.
    """

    __tablename__ = "outbound_webhook_endpoints"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    url = Column(Text, nullable=False)  # https-only, SSRF-validated
    description = Column(Text)
    # ACTIVE | DISABLED (disabled endpoints receive nothing new)
    status = Column(Text, nullable=False, default="ACTIVE")
    # Closed-world event-type allowlist (subset of OUTBOUND_EVENT_TYPES).
    events = Column(JSONB, nullable=False, default=list)
    # Fernet token over the signing secret. The plaintext secret never
    # appears in any column of any table.
    secret_ciphertext = Column(Text, nullable=False)
    secret_hint = Column(Text, nullable=False, default="")
    secret_key_version = Column(Integer, nullable=False, default=1)
    disabled_at = Column(DateTime(timezone=True))
    created_by_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ix_outbound_endpoints_org", "organization_id"),
        Index(
            "ix_outbound_endpoints_org_active",
            "organization_id",
            postgresql_where=text("status = 'ACTIVE'"),
            sqlite_where=text("status = 'ACTIVE'"),
        ),
    )


class OutboundWebhookDelivery(Base):
    """One logical outbound delivery (identity is stable across retries).

    Invariants:
      - UNIQUE(organization_id, endpoint_id, event_type, delivery_id):
        the same event delivered to the same endpoint is ONE row, no
        matter how many times it is retried or re-enqueued.
      - state machine is closed-world: PENDING → DELIVERING →
        DELIVERED | RETRYING | FAILED → DEAD_LETTER; illegal transitions
        raise (fail closed in the dispatcher).
      - `payload` is the bounded, secret-free body that was signed; the
        HMAC secret itself is reconstructed in memory per attempt only.
    """

    __tablename__ = "outbound_webhook_deliveries"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    endpoint_id = Column(
        UUID(as_uuid=True),
        ForeignKey("outbound_webhook_endpoints.id"),
        nullable=False,
    )
    event_type = Column(Text, nullable=False)  # OUTBOUND_EVENT_TYPES member
    event_version = Column(Integer, nullable=False, default=1)
    # Stable identity across retries — this is the id the receiver sees
    # and the id the state machine keys on.
    delivery_id = Column(Text, nullable=False)
    # PENDING | DELIVERING | DELIVERED | RETRYING | FAILED | DEAD_LETTER
    state = Column(Text, nullable=False, default="PENDING")
    attempt = Column(Integer, nullable=False, default=0)
    next_attempt_at = Column(DateTime(timezone=True))
    # Bounded, secret-free event body (already redacted by the producer).
    payload = Column(JSONB, nullable=False, default=dict)
    last_http_status = Column(Integer)
    last_error = Column(Text)  # bounded classification, never raw secrets
    delivered_at = Column(DateTime(timezone=True))
    dead_lettered_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "endpoint_id", "event_type", "delivery_id",
            name="uq_outbound_deliveries_identity",
        ),
        Index(
            "ix_outbound_deliveries_due",
            "state", "next_attempt_at",
            postgresql_where=text(
                "state IN ('PENDING', 'RETRYING')"
            ),
            sqlite_where=text(
                "state IN ('PENDING', 'RETRYING')"
            ),
        ),
        Index("ix_outbound_deliveries_org", "organization_id"),
        Index("ix_outbound_deliveries_state", "state"),
    )


# ══════════════════════════════════════════════════════════════════════
# V4.2 COMPLETION — Dedicated CI event intake (POST /api/ci/events)
#
# A CI event is a SECURITY RECORD of what an authenticated CI credential
# reported. Identity chain: CI API key → organization → installation →
# repository, ALL resolved from trusted server state — the payload can
# never nominate any of them. Commit binding reuses the V4.1 mechanism:
# requested_commit_sha is server-set and worker-VERIFIED at clone time.
# ══════════════════════════════════════════════════════════════════════


class CiEvent(Base):
    """One received CI event (accepted, replayed, or refused).

    Fields are identity/binding/outcome only. CI metadata (run ids,
    workflow names) is stored bounded and redacted; CI can never claim
    security outcome through any column here — result is SERVER-set.
    """

    __tablename__ = "ci_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True
    )
    # The credential that produced this event (audit forensics only).
    api_key_prefix = Column(Text)
    # Server-side idempotency identity: the caller-supplied event_id,
    # scoped by (organization, repository). UNIQUE backstop below.
    event_id = Column(Text, nullable=False)
    repository_id = Column(
        UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=True
    )
    commit_sha = Column(Text)
    ref = Column(Text)
    provider = Column(Text, nullable=False, default="github")
    # ACCEPTED | REJECTED | REPLAY
    outcome = Column(Text, nullable=False)
    result = Column(Text)  # SERVER-computed only (never CI-declared)
    reason_code = Column(Text)  # bounded allowlist
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True)
    received_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        # One logical CI event per tenant per repository. Replays are
        # refused at the DB level even if the reservation TTL lapsed.
        UniqueConstraint(
            "organization_id", "repository_id", "event_id",
            name="uq_ci_events_org_repo_event",
        ),
        Index("ix_ci_events_org", "organization_id"),
        Index("ix_ci_events_outcome", "outcome"),
        Index("ix_ci_events_received", "received_at"),
    )
