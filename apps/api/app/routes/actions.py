"""CYVRIX V3.1 — Action Proposal Routes.

READ-ONLY + PROPOSAL-CREATION ONLY.

V3.1 explicitly has NO execution capability:
- No git operations, no GitHub writes, no shell, no subprocess
- No approval workflow (V3.2), no sandbox/executor (V3.4)
- The only side effects are database rows (proposal + audit events)

Authorization: full V2 ownership chain (user → installation → repository)
on every route; cross-tenant access returns 404.
"""
import logging
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import (
    ActionProposal, AuditEvent, Finding, Recommendation,
    Repository, GithubInstallation, RiskAssessment, User,
)
from app.schemas import ActionProposalCreate, ActionProposalResponse, ProposalStatus
from app.auth import get_current_user
from app.rate_limit import check_rate_limit
from app.config import get_settings
from app.services import action_model
from app.services.action_digest import compute_action_digest
from app.services.policy_engine import (
    DECISION_DENY,
    PolicyContext,
    evaluate,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/actions", tags=["actions"])
settings = get_settings()

DIGEST_EXCLUDED_KEYS = frozenset(
    {"password", "secret", "token", "api_key", "credential"}
)


async def check_proposal_rate_limit(user: User = Depends(get_current_user)):
    """Rate-limit proposal creation per user (fail closed via check_rate_limit)."""
    allowed, _ = await check_rate_limit(
        key=f"actions:{user.id}",
        max_requests=settings.action_proposal_rate_limit_per_hour,
        window_seconds=3600,
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many action proposals. Please try again later.",
        )
    return user


def _policy_status(decision: str) -> str:
    """Map a policy decision to a persisted status. No execution exists."""
    return "REJECTED" if decision == DECISION_DENY else "POLICY_CHECKED"


@router.post("", response_model=ActionProposalResponse, status_code=201)
async def create_action_proposal(
    body: ActionProposalCreate,
    response: Response,
    user: User = Depends(check_proposal_rate_limit),
    db: AsyncSession = Depends(get_db),
):
    """Create (validate + policy-evaluate + persist) an action proposal.

    This endpoint NEVER executes anything: no repository writes, no git,
    no GitHub API, no jobs enqueued. Denied proposals are persisted with
    status REJECTED for audit purposes and can never be approved (V3.2
    binds approvals to digest + decision).
    """
    # 1. Load recommendation + finding + repository through the ownership chain
    result = await db.execute(
        select(Recommendation, Finding, Repository)
        .join(Finding, Finding.id == Recommendation.finding_id)
        .join(Repository, Repository.id == Finding.repository_id)
        .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
        .where(
            Recommendation.id == body.recommendation_id,
            GithubInstallation.user_id == user.id,
        )
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Recommendation not found or access denied")
    recommendation, finding, repo = row

    # 2. Validate proposal content (shape, paths, operations, caps, bindings)
    payload = body.model_dump(mode="json")
    payload.pop("recommendation_id", None)  # server-derived binding, not proposal content
    payload["action_type"] = body.action_type.value
    try:
        content = action_model.validate_proposal_content(payload)
    except action_model.ProposalValidationError as e:
        raise HTTPException(status_code=422, detail={"errors": e.errors})

    # 3. Evidence narrowing (stricter than basename rules) — mismatches are
    #    policy-level denials, persisted for audit, not silent 422s.
    files_match = action_model.files_match_action_type(
        content.action_type, content.files, finding.evidence
    )

    # 4. Digest over canonical action semantics
    action_digest = compute_action_digest({
        "action_type": content.action_type,
        "repository_id": str(repo.id),
        "base_commit_sha": content.base_commit_sha,
        "target_branch": content.target_branch,
        "files": content.files,
        "operations": content.operations,
        "expected_diff": content.expected_diff,
    })

    # 5. Idempotency: same (recommendation, base commit, digest) returns existing
    existing_result = await db.execute(
        select(ActionProposal).where(
            ActionProposal.recommendation_id == recommendation.id,
            ActionProposal.base_commit_sha == content.base_commit_sha,
            ActionProposal.action_digest == action_digest,
            ActionProposal.created_by == user.id,
        )
    )
    existing = existing_result.scalar_one_or_none()
    if existing:
        response.status_code = 200  # idempotent re-submission
        return ActionProposalResponse.model_validate(existing)

    # 6. Server-derived security context for the policy engine
    now = datetime.now(timezone.utc)
    risk_result = await db.execute(
        select(RiskAssessment)
        .where(RiskAssessment.finding_id == finding.id)
        .order_by(RiskAssessment.created_at.desc())
        .limit(1)
    )
    latest_risk = risk_result.scalar_one_or_none()

    protected_categories = tuple(
        cat
        for cat in (
            action_model.is_protected_path(path) for path in content.files
        )
        if cat is not None
    )

    context = PolicyContext(
        action_type=content.action_type,
        repository_active=bool(repo.is_active),
        environment=settings.environment,
        actor_role="owner",  # V3.1: single-role model; roles arrive in V3.2
        validation_state=recommendation.validation_state,
        trust_level=recommendation.trust_level,
        risk_level=latest_risk.risk_level if latest_risk else None,
        risk_score=latest_risk.risk_score if latest_risk else None,
        finding_status=finding.status,
        kill_switch=False,  # kill switch lands with execution (V3.4)
        files=tuple(content.files),
        operations=tuple(content.operations),
        target_branch=content.target_branch,
        base_commit_sha=content.base_commit_sha,
        paths_valid=True,  # enforced upstream; invalid input never reaches here
        files_match_type=files_match,
        operations_valid=True,
        protected_path_categories=protected_categories,
        diff_lines=content.expected_diff.count("\n") + (1 if content.expected_diff else 0),
        expires_at=action_model.proposal_expiry(now),
    )

    # 7. Deterministic policy evaluation
    decision = evaluate(context, now)
    status = _policy_status(decision.decision)

    # 8. Persist proposal (no execution of any kind)
    proposal = ActionProposal(
        finding_id=finding.id,
        recommendation_id=recommendation.id,
        repository_id=repo.id,
        created_by=user.id,
        action_type=content.action_type,
        status=status,
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

    # 9. Audit trail (V3.8 formalizes; V3.1 records the essentials)
    db.add(AuditEvent(
        repository_id=repo.id,
        finding_id=finding.id,
        event_type="ACTION_PROPOSAL_CREATED",
        event_metadata={
            "proposer": str(user.id),
            "action_type": content.action_type,
            "action_digest": action_digest,
            "policy_version": decision.policy_version,
            "policy_decision": decision.decision,
            "policy_reason_code": decision.reason_code,
            "policy_matched_rule": decision.matched_rule,
            "recommendation_id": str(recommendation.id),
            "base_commit_sha": content.base_commit_sha,
            "status": status,
        },
    ))
    await db.commit()
    await db.refresh(proposal)

    logger.info(
        "action_proposal_created proposal_id=%s decision=%s reason=%s",
        proposal.id, decision.decision, decision.reason_code,
    )
    return ActionProposalResponse.model_validate(proposal)


async def _get_owned_proposal(
    proposal_id: UUID, user: User, db: AsyncSession
) -> ActionProposal:
    """Load a proposal through the full ownership chain (404 on cross-tenant)."""
    result = await db.execute(
        select(ActionProposal)
        .join(Repository, Repository.id == ActionProposal.repository_id)
        .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
        .where(
            ActionProposal.id == proposal_id,
            GithubInstallation.user_id == user.id,
        )
    )
    proposal = result.scalar_one_or_none()
    if not proposal:
        raise HTTPException(status_code=404, detail="Action proposal not found or access denied")

    # On-read expiry reconciliation (same pattern as V2 scan reconciliation)
    now = datetime.now(timezone.utc)
    if proposal.status == ProposalStatus.POLICY_CHECKED.value and proposal.expires_at:
        expires = proposal.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if now >= expires:
            proposal.status = ProposalStatus.EXPIRED.value
            await db.commit()
            await db.refresh(proposal)
    return proposal


@router.get("")
async def list_action_proposals(
    status: str = None,
    action_type: str = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List action proposals for repositories owned by the current user."""
    query = (
        select(ActionProposal)
        .join(Repository, Repository.id == ActionProposal.repository_id)
        .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
        .where(GithubInstallation.user_id == user.id)
    )
    if status:
        query = query.where(ActionProposal.status == status.upper())
    if action_type:
        query = query.where(ActionProposal.action_type == action_type.upper())
    query = query.order_by(ActionProposal.created_at.desc()).limit(100)

    result = await db.execute(query)
    proposals = result.scalars().all()
    return [ActionProposalResponse.model_validate(p) for p in proposals]


@router.get("/{proposal_id}")
async def get_action_proposal(
    proposal_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get one action proposal (ownership enforced, 404 for other users)."""
    proposal = await _get_owned_proposal(proposal_id, user, db)
    return ActionProposalResponse.model_validate(proposal)
