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
    created_at = Column(DateTime(timezone=True), default=utcnow)

    installations = relationship("GithubInstallation", back_populates="user")


class GithubInstallation(Base):
    __tablename__ = "github_installations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    installation_id = Column(BigInteger, unique=True, nullable=False)
    account_login = Column(Text, nullable=False)
    account_type = Column(Text, nullable=False)  # 'User' | 'Organization'
    created_at = Column(DateTime(timezone=True), default=utcnow)

    user = relationship("User", back_populates="installations")
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
    trigger = Column(Text, nullable=False, default="manual")
    error_reason = Column(Text)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    commit_sha = Column(Text)
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
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

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
    - Exactly-once: a UNIQUE completed index makes replayed admissions
      fail at the database level
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
