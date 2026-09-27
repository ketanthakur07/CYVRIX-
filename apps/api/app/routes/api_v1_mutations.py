"""CYVRIX V4.2 completion — mutation-scope endpoints (`/api/v1`).

The scopes `actions:create`, `executions:create`, `rollback:create`,
`integrations:manage` and `audit:export` are now ISSUABLE because the
endpoints below enforce them. Each endpoint:

    authentication (hashed API key)
      → organization (derived FROM THE KEY)
        → scope (the mutation scope; HIGH_IMPACT — issuance required
          ORG_ADMIN standing)
          → resource authorization (resource's own organization, 404
            on cross-tenant)
            → the EXISTING V3 chain services (policy engine, rollback
              service, exactly-once DB guards) — nothing here is a
              parallel security implementation
            → V3.8 audit (MUTATION_REQUESTED + chain events)

Deliberate semantics (the V3 chain is PRESERVED, never bypassed):

- actions:create   creates a PROPOSAL and nothing else. Policy may
                   DENY; the proposal is persisted REJECTED for audit.
                   No approval, no authorization, no execution.
- executions:create is a validated REQUEST VIEW of an authorization:
                   it never consumes, mints, or executes anything. The
                   one-time token and the internal executor boundary
                   remain session/service-only (V3.3/V3.4).
- rollback:create  delegates to the V3.6 rollback service: the TARGET
                   is server-derived (frozen contract base SHA); the
                   request body carries NOTHING security-relevant; the
                   exactly-once guard is the database.
- integrations:manage toggles repository scan-eligibility inside the
                   organization's own installation. No credential is
                   ever created, returned, or logged.
- audit:export     streams the tenant's own chain as deterministic
                   NDJSON; another organization's chain is 404.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.metrics import increment as metric
from app.models import (
    ActionProposal,
    AuditChain,
    AuditChainEvent,
    AuditCheckpoint,
    Approval,
    ExecutionAuthorization,
    Finding,
    GithubInstallation,
    Recommendation,
    Repository,
    RiskAssessment,
    RollbackRun,
)
from app.services import action_model
from app.services import audit_service
from app.services import rollback_service
from app.services.action_digest import compute_action_digest
from app.services.policy_engine import (
    DECISION_DENY,
    PolicyContext,
    evaluate,
)
from app.services.org_auth import require_api_scope

from app.routes.api_v1 import (
    MAX_PAGE_SIZE,
    PublicApiError,
    WRITE_BUCKET,
    WRITE_LIMIT_PER_HOUR,
    _org_repositories,
    _rate_limit,
    _uuid_or_400,
)

logger = logging.getLogger("cyvrix.api_v1_mutations")
settings = get_settings()

router = APIRouter(prefix="/api/v1", tags=["public-api-mutations"])

_SHA_HEX = set("0123456789abcdef")


def _validate_commit_sha(value: str) -> str:
    value = value.strip().lower()
    if len(value) != 40 or any(c not in _SHA_HEX for c in value):
        raise ValueError("base_commit_sha must be a full 40-character hex SHA")
    return value


# ── Request/response models ──────────────────────────────────────────


class PublicActionCreate(BaseModel):
    """Same contract as the V3.1 console proposal: action CONTENT only.
    Expiry, risk, validation state, ownership and policy inputs are all
    server-derived."""

    model_config = ConfigDict(extra="forbid")

    recommendation_id: str = Field(min_length=8, max_length=64)
    action_type: str = Field(min_length=3, max_length=40)
    files: list[str] = Field(min_length=1, max_length=10)
    operations: list[dict] = Field(min_length=1, max_length=50)
    expected_diff: str = Field(default="", max_length=50_000)
    target_branch: str = Field(min_length=1, max_length=255)
    base_commit_sha: str = Field(min_length=40, max_length=40)
    rationale: str = Field(default="", max_length=2000)

    @field_validator("base_commit_sha")
    @classmethod
    def _sha(cls, v: str) -> str:
        return _validate_commit_sha(v)


class PublicActionCreated(BaseModel):
    """Proposal view. A DENIED proposal is persisted REJECTED for audit
    and can never be approved (V3.2 binds approvals to digest+decision)."""

    proposal_id: str
    repository_id: str
    action_type: str
    status: str
    policy_decision: str
    policy_reason_code: str
    action_digest: str
    expires_at: Optional[str] = None


class PublicExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution_authorization_id: str = Field(min_length=8, max_length=64)


class PublicExecutionRequestOut(BaseModel):
    """Request view of an authorization. NEVER consumes, mints, or
    executes: `execution_state` restates the SERVER's current state and
    `next_step` documents the human/console path."""

    execution_authorization_id: str
    execution_state: str
    proposal_status: str
    approval_state: Optional[str] = None
    next_step: str


class PublicRollbackCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    remediation_id: str = Field(min_length=8, max_length=64)


class PublicRollbackCreated(BaseModel):
    rollback_id: str
    remediation_id: str
    rollback_state: str
    rollback_target_sha: str
    expected_branch_sha: str
    revert_branch: str


class IntegrationRepositoryOut(BaseModel):
    installation_id: str
    repository_id: str
    owner: str
    name: str
    is_active: bool


def _iso(value) -> Optional[str]:
    return value.isoformat() if value else None


async def _audit_mutation(
    db: AsyncSession,
    *,
    organization_id,
    mutation: str,
    resource_kind: str,
    resource_id: str,
    repository_id=None,
    extra: Optional[dict] = None,
) -> None:
    """MUTATION_REQUESTED witness on the org chain (best-effort: the
    mutation's own SECURITY-CRITICAL chain events are emitted by the V3
    services; this event records the KEY-actor request)."""
    try:
        await audit_service.emit_security_event(
            db,
            organization_id=organization_id,
            event_type="MUTATION_REQUESTED",
            actor_type=audit_service.ActorType.SYSTEM,
            reason_code=mutation,
            repository_id=repository_id,
            payload={
                "mutation": mutation,
                "resource_kind": resource_kind,
                "resource_id": resource_id,
                **(extra or {}),
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "mutation_audit_failed mutation=%s err=%s", mutation, type(exc).__name__
        )


# ── actions:create — request-only proposal creation ──────────────────


@router.post("/actions", response_model=PublicActionCreated,
             status_code=status.HTTP_201_CREATED)
async def create_action(
    body: PublicActionCreate,
    request: Request,
    response: Response,
    key=Depends(require_api_scope("actions:create")),
    db: AsyncSession = Depends(get_db),
):
    """Create an action PROPOSAL. The V3 chain continues exclusively
    through the session-authenticated console: this endpoint cannot
    approve, authorize, execute, verify or roll anything back."""
    await _rate_limit(
        request, response, key.organization_id,
        bucket=WRITE_BUCKET, limit=WRITE_LIMIT_PER_HOUR,
    )

    # Resolve recommendation → finding → repository THROUGH the org
    # boundary (404 on any mismatch — no tenant discovery).
    try:
        recommendation_uuid = _uuid_or_400(
            body.recommendation_id, field_name="recommendation_id"
        )
    except PublicApiError:
        raise PublicApiError(
            404, "RECOMMENDATION_NOT_FOUND",
            "No such recommendation in this organization.",
        )
    row = (
        await db.execute(
            select(Recommendation, Finding, Repository)
            .join(Finding, Finding.id == Recommendation.finding_id)
            .join(Repository, Repository.id == Finding.repository_id)
            .join(
                GithubInstallation,
                GithubInstallation.id == Repository.installation_id,
            )
            .where(
                Recommendation.id == recommendation_uuid,
                GithubInstallation.organization_id == key.organization_id,
            )
        )
    ).first()
    if row is None:
        raise PublicApiError(
            404, "RECOMMENDATION_NOT_FOUND",
            "No such recommendation in this organization.",
        )
    recommendation, finding, repo = row

    # Schema validation — identical rules to the V3.1 console path.
    payload = body.model_dump(mode="json")
    payload.pop("recommendation_id", None)
    payload["action_type"] = body.action_type.strip().upper()
    from app.schemas import ActionType

    if payload["action_type"] not in {a.value for a in ActionType}:
        raise PublicApiError(
            422, "VALIDATION_ERROR", "The request is not valid.",
            {"errors": [{"field": "action_type", "type": "unknown_action_type"}]},
        )
    try:
        content = action_model.validate_proposal_content(payload)
    except action_model.ProposalValidationError as exc:
        raise PublicApiError(
            422, "VALIDATION_ERROR", "The request is not valid.",
            {"errors": list(exc.errors)[:20]},
        )

    files_match = action_model.files_match_action_type(
        content.action_type, content.files, finding.evidence
    )
    action_digest = compute_action_digest({
        "action_type": content.action_type,
        "repository_id": str(repo.id),
        "base_commit_sha": content.base_commit_sha,
        "target_branch": content.target_branch,
        "files": content.files,
        "operations": content.operations,
        "expected_diff": content.expected_diff,
    })

    # Idempotency: same (recommendation, base commit, digest) returns
    # the EXISTING proposal (V3.1 identity semantics).
    existing = (
        await db.execute(
            select(ActionProposal).where(
                ActionProposal.recommendation_id == recommendation.id,
                ActionProposal.base_commit_sha == content.base_commit_sha,
                ActionProposal.action_digest == action_digest,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return PublicActionCreated(
            proposal_id=str(existing.id),
            repository_id=str(existing.repository_id),
            action_type=existing.action_type,
            status=existing.status,
            policy_decision=existing.policy_decision,
            policy_reason_code=existing.policy_reason_code,
            action_digest=existing.action_digest,
            expires_at=_iso(existing.expires_at),
        )

    # Server-derived policy context (identical inputs to the console).
    from app.schemas import ProposalStatus

    now = datetime.now(timezone.utc)
    latest_risk = (
        await db.execute(
            select(RiskAssessment)
            .where(RiskAssessment.finding_id == finding.id)
            .order_by(RiskAssessment.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    protected_categories = tuple(
        cat for cat in (
            action_model.is_protected_path(p) for p in content.files
        ) if cat is not None
    )
    context = PolicyContext(
        action_type=content.action_type,
        repository_active=bool(repo.is_active),
        environment=settings.environment,
        actor_role="owner",  # V3.1 single-role model (unchanged)
        validation_state=recommendation.validation_state,
        trust_level=recommendation.trust_level,
        risk_level=latest_risk.risk_level if latest_risk else None,
        risk_score=latest_risk.risk_score if latest_risk else None,
        finding_status=finding.status,
        kill_switch=False,
        files=tuple(content.files),
        operations=tuple(content.operations),
        target_branch=content.target_branch,
        base_commit_sha=content.base_commit_sha,
        paths_valid=True,
        files_match_type=files_match,
        operations_valid=True,
        protected_path_categories=protected_categories,
        diff_lines=content.expected_diff.count("\n") + (1 if content.expected_diff else 0),
        expires_at=action_model.proposal_expiry(now),
    )
    decision = evaluate(context, now)
    proposal_status = "REJECTED" if decision.decision == DECISION_DENY else "POLICY_CHECKED"

    proposal = ActionProposal(
        finding_id=finding.id,
        recommendation_id=recommendation.id,
        repository_id=repo.id,
        created_by=None,  # key actor: witnessed by key prefix in the chain
        action_type=content.action_type,
        status=proposal_status,
        base_commit_sha=content.base_commit_sha,
        target_branch=content.target_branch,
        files=content.files,
        operations=content.operations,
        expected_diff=content.expected_diff,
        rationale=content.rationale,
        evidence=finding.evidence,
        risk_score=latest_risk.risk_score if latest_risk else 0,
        risk_level=latest_risk.risk_level if latest_risk else "UNKNOWN",
        recommendation_trust=recommendation.trust_level,
        validation_state=recommendation.validation_state,
        policy_version=decision.policy_version,
        policy_decision=decision.decision,
        policy_reason_code=decision.reason_code,
        policy_matched_rule=decision.matched_rule,
        policy_explanation=decision.explanation,
        action_digest=action_digest,
        expires_at=context.expires_at,
    )
    db.add(proposal)
    await db.flush()

    await _audit_mutation(
        db,
        organization_id=key.organization_id,
        mutation="actions:create",
        resource_kind="action_proposal",
        resource_id=str(proposal.id),
        repository_id=repo.id,
        extra={
            "action_digest": action_digest,
            "policy_decision": decision.decision,
            "key_prefix": key.prefix,
        },
    )
    await db.commit()
    await db.refresh(proposal)
    metric("api_requests_total", {"outcome": "ACTION_CREATED"})
    return PublicActionCreated(
        proposal_id=str(proposal.id),
        repository_id=str(proposal.repository_id),
        action_type=proposal.action_type,
        status=proposal.status,
        policy_decision=proposal.policy_decision,
        policy_reason_code=proposal.policy_reason_code,
        action_digest=proposal.action_digest,
        expires_at=_iso(proposal.expires_at),
    )


# ── executions:create — request view ONLY (never consumes/executes) ──


@router.post("/executions", response_model=PublicExecutionRequestOut,
             status_code=status.HTTP_200_OK)
async def create_execution_request(
    body: PublicExecutionRequest,
    request: Request,
    response: Response,
    key=Depends(require_api_scope("executions:create")),
    db: AsyncSession = Depends(get_db),
):
    """Submit an execution REQUEST VIEW for an authorization that already
    exists in this organization.

    This endpoint is deliberately NOT an execution: the one-time approval
    token and the executor boundary (V3.3 §4 / V3.4) live behind session
    and service identities, and a key can never hold either. It restates
    the server's CURRENT state so an integrator can observe where the
    request stands — it changes nothing.
    """
    await _rate_limit(
        request, response, key.organization_id,
        bucket=WRITE_BUCKET, limit=WRITE_LIMIT_PER_HOUR,
    )
    try:
        authz_uuid = _uuid_or_400(
            body.execution_authorization_id,
            field_name="execution_authorization_id",
        )
    except PublicApiError:
        raise PublicApiError(
            404, "EXECUTION_AUTHORIZATION_NOT_FOUND",
            "No such execution authorization in this organization.",
        )
    row = (
        await db.execute(
            select(ExecutionAuthorization, ActionProposal, Approval)
            .join(
                ActionProposal,
                ActionProposal.id == ExecutionAuthorization.action_proposal_id,
            )
            .join(Approval, Approval.id == ExecutionAuthorization.approval_id)
            .join(Repository, Repository.id == ActionProposal.repository_id)
            .join(
                GithubInstallation,
                GithubInstallation.id == Repository.installation_id,
            )
            .where(
                ExecutionAuthorization.id == authz_uuid,
                GithubInstallation.organization_id == key.organization_id,
            )
        )
    ).first()
    if row is None:
        raise PublicApiError(
            404, "EXECUTION_AUTHORIZATION_NOT_FOUND",
            "No such execution authorization in this organization.",
        )
    authorization, proposal, approval = row

    await _audit_mutation(
        db,
        organization_id=key.organization_id,
        mutation="executions:create",
        resource_kind="execution_authorization",
        resource_id=str(authorization.id),
        repository_id=authorization.repository_id,
        extra={"observed_state": authorization.authorization_state},
    )
    await db.commit()
    metric("api_requests_total", {"outcome": "EXECUTION_REQUEST_VIEWED"})

    next_step = (
        "Execution is performed by the platform executor after the "
        "authorization is consumed through the console workflow."
        if authorization.authorization_state == "AUTHORIZED"
        else "The authorization is no longer live; request a new "
             "approval + authorization through the console."
    )
    return PublicExecutionRequestOut(
        execution_authorization_id=str(authorization.id),
        execution_state=authorization.authorization_state,
        proposal_status=proposal.status,
        approval_state=approval.approval_state,
        next_step=next_step,
    )


# ── rollback:create — server-derived target via the V3.6 service ─────


@router.post("/rollbacks", response_model=PublicRollbackCreated,
             status_code=status.HTTP_201_CREATED)
async def create_rollback(
    body: PublicRollbackCreate,
    request: Request,
    response: Response,
    key=Depends(require_api_scope("rollback:create")),
    db: AsyncSession = Depends(get_db),
):
    """Create the exactly-once rollback REQUEST for a pushed remediation
    in this organization. The rollback TARGET is server-derived (the
    frozen contract's base SHA); the body carries NOTHING
    security-relevant; execution remains the internal executor's step."""
    await _rate_limit(
        request, response, key.organization_id,
        bucket=WRITE_BUCKET, limit=WRITE_LIMIT_PER_HOUR,
    )
    try:
        remediation_uuid = _uuid_or_400(
            body.remediation_id, field_name="remediation_id"
        )
    except PublicApiError:
        raise PublicApiError(
            404, "REMEDIATION_NOT_FOUND",
            "No such remediation in this organization.",
        )

    from app.models import GitRemediation

    remediation = (
        await db.execute(
            select(GitRemediation)
            .join(Repository, Repository.id == GitRemediation.repository_id)
            .join(
                GithubInstallation,
                GithubInstallation.id == Repository.installation_id,
            )
            .where(
                GitRemediation.id == remediation_uuid,
                GithubInstallation.organization_id == key.organization_id,
            )
        )
    ).scalar_one_or_none()
    if remediation is None:
        raise PublicApiError(
            404, "REMEDIATION_NOT_FOUND",
            "No such remediation in this organization.",
        )

    try:
        rollback = await rollback_service.start_rollback(
            db, remediation=remediation, actor_id=None,
        )
    except rollback_service.RollbackDenied as exc:
        await db.rollback()
        raise PublicApiError(
            409, exc.reason_code or "ROLLBACK_DENIED",
            "The rollback request was refused by the V3.6 rollback service.",
            {"reason_code": exc.reason_code, "detail": (exc.detail or "")[:120]},
        )
    await db.commit()
    await db.refresh(rollback)

    await _audit_mutation(
        db,
        organization_id=key.organization_id,
        mutation="rollback:create",
        resource_kind="rollback_run",
        resource_id=str(rollback.id),
        repository_id=rollback.repository_id,
        extra={"key_prefix": key.prefix},
    )
    await db.commit()
    metric("api_requests_total", {"outcome": "ROLLBACK_REQUESTED"})
    return PublicRollbackCreated(
        rollback_id=str(rollback.id),
        remediation_id=str(rollback.git_remediation_id),
        rollback_state=rollback.rollback_state,
        rollback_target_sha=rollback.rollback_target_sha,
        expected_branch_sha=rollback.expected_branch_sha,
        revert_branch=rollback.revert_branch,
    )


# ── integrations:manage — repository eligibility, no credentials ─────


@router.get("/integrations/repositories",
            response_model=list[IntegrationRepositoryOut])
async def list_integration_repositories(
    key=Depends(require_api_scope("integrations:manage")),
    db: AsyncSession = Depends(get_db),
):
    """Repositories visible to integrations:manage for this org."""
    q = _org_repositories(key.organization_id).limit(MAX_PAGE_SIZE)
    rows = (await db.execute(q)).scalars().all()
    return [
        IntegrationRepositoryOut(
            installation_id=str(r.installation_id),
            repository_id=str(r.id),
            owner=r.owner,
            name=r.name,
            is_active=bool(r.is_active),
        )
        for r in rows
    ]


@router.post("/integrations/repositories/{repository_id}/activate",
             response_model=IntegrationRepositoryOut)
async def activate_repository(
    repository_id: UUID,
    request: Request,
    response: Response,
    key=Depends(require_api_scope("integrations:manage")),
    db: AsyncSession = Depends(get_db),
):
    return await _set_repo_active(
        db, request, response, key, repository_id, True
    )


@router.post("/integrations/repositories/{repository_id}/deactivate",
             response_model=IntegrationRepositoryOut)
async def deactivate_repository(
    repository_id: UUID,
    request: Request,
    response: Response,
    key=Depends(require_api_scope("integrations:manage")),
    db: AsyncSession = Depends(get_db),
):
    return await _set_repo_active(
        db, request, response, key, repository_id, False
    )


async def _set_repo_active(db, request, response, key, repository_id, active: bool):
    """Toggle scan-eligibility for a repository INSIDE the org's own
    installation. The GitHub integration itself is owned by the
    installation (connected through the console); no credential is ever
    created, returned, or logged here."""
    await _rate_limit(
        request, response, key.organization_id,
        bucket=WRITE_BUCKET, limit=WRITE_LIMIT_PER_HOUR,
    )
    repo = (
        await db.execute(
            _org_repositories(key.organization_id).where(
                Repository.id == repository_id
            )
        )
    ).scalar_one_or_none()
    if repo is None:
        raise PublicApiError(
            404, "REPOSITORY_NOT_FOUND",
            "No such repository in this organization.",
        )
    repo.is_active = active
    repo.installation  # noqa: B018 — ensure loaded before commit
    await _audit_mutation(
        db,
        organization_id=key.organization_id,
        mutation="integrations:manage",
        resource_kind="repository",
        resource_id=str(repo.id),
        repository_id=repo.id,
        extra={"is_active": active, "key_prefix": key.prefix},
    )
    await audit_service.emit_security_event(
        db,
        organization_id=key.organization_id,
        event_type="INTEGRATION_MANAGED",
        actor_type=audit_service.ActorType.SYSTEM,
        repository_id=repo.id,
        reason_code="REPOSITORY_ACTIVATE" if active else "REPOSITORY_DEACTIVATE",
        payload={"key_prefix": key.prefix},
    )
    await db.commit()
    await db.refresh(repo)
    return IntegrationRepositoryOut(
        installation_id=str(repo.installation_id),
        repository_id=str(repo.id),
        owner=repo.owner,
        name=repo.name,
        is_active=bool(repo.is_active),
    )


# ── audit:export — tenant-scoped deterministic NDJSON ─────────────────


@router.get("/audit/export")
async def export_audit(
    request: Request,
    response: Response,
    chain_id: str = Query(min_length=8, max_length=64),
    key=Depends(require_api_scope("audit:export")),
    db: AsyncSession = Depends(get_db),
):
    """Export THIS organization's audit chain as deterministic NDJSON
    (independently verifiable via audit_service.verify_export_ndjson).
    A chain outside the key's organization is 404 — never exported."""
    await _rate_limit(
        request, response, key.organization_id,
        bucket=WRITE_BUCKET, limit=WRITE_LIMIT_PER_HOUR,
    )
    try:
        chain_uuid = _uuid_or_400(chain_id, field_name="chain_id")
    except PublicApiError:
        raise PublicApiError(
            404, "AUDIT_CHAIN_NOT_FOUND",
            "No such audit chain in this organization.",
        )
    chain = (
        await db.execute(
            select(AuditChain).where(
                AuditChain.id == chain_uuid,
                AuditChain.organization_id == key.organization_id,
            )
        )
    ).scalar_one_or_none()
    if chain is None:
        # Installation-owned chains are reachable through the console;
        # the public key-scoped export serves the ORG chain (key-only
        # tenants and org-level events).
        raise PublicApiError(
            404, "AUDIT_CHAIN_NOT_FOUND",
            "No such audit chain in this organization.",
        )

    rows = (
        await db.execute(
            select(AuditChainEvent)
            .where(AuditChainEvent.chain_id == chain.id)
            .order_by(AuditChainEvent.seq.asc())
        )
    ).scalars().all()
    cps = (
        await db.execute(
            select(AuditCheckpoint)
            .where(AuditCheckpoint.chain_id == chain.id)
            .order_by(AuditCheckpoint.through_sequence.asc())
        )
    ).scalars().all()
    text = audit_service.export_chain_ndjson(rows, cps, chain)

    await _audit_mutation(
        db,
        organization_id=key.organization_id,
        mutation="audit:export",
        resource_kind="audit_chain",
        resource_id=str(chain.id),
        extra={"events": len(rows), "key_prefix": key.prefix},
    )
    await audit_service.emit_security_event(
        db,
        organization_id=key.organization_id,
        event_type="AUDIT_EXPORTED",
        actor_type=audit_service.ActorType.SYSTEM,
        reason_code="NDJSON",
        payload={"chain_id": str(chain.id), "events": len(rows)},
    )
    await db.commit()
    metric("api_requests_total", {"outcome": "AUDIT_EXPORTED"})
    return PlainTextResponse(
        text,
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": (
                f'attachment; filename="cyvrix-audit-{str(chain.id)[:8]}.ndjson"'
            )
        },
    )
