"""CYVRIX V3.2 — Approval Routes.

HUMAN APPROVAL of action proposals: authorization data ONLY.

V3.2 explicitly has NO execution capability:
- No git operations, no GitHub writes, no shell, no subprocess
- No file writes, no Docker, no worker enqueue of any executor
- POST /approve, /reject, /revoke are state transitions + audit events
- POST /consume-token is a non-executing verification endpoint reserved
  for the future executor phase (V3.4+)

Authorization: full V2 ownership chain (user → installation → repository)
on every route; cross-tenant access returns 404. Approvals additionally
require fresh step-up authentication (GitHub re-auth round-trip) and
satisfy the second-principal rule for HIGH/CRITICAL risk.
"""
import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Approval, ActionProposal, GithubInstallation, Repository, User
from app.schemas import (
    ApprovalCreate, ApprovalIssuedResponse, ApprovalResponse,
    RejectionCreate, RevocationCreate, TokenConsumeRequest,
)
from app.auth import get_current_user
from app.rate_limit import check_rate_limit
from app.config import get_settings
from app.session import get_redis
from app.services import approval_service
from app.services.approval_model import APPROVAL_TTL_MINUTES

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/actions", tags=["approvals"])
settings = get_settings()


async def check_approval_rate_limit(user: User = Depends(get_current_user)):
    """Rate-limit approval operations per user (fail closed via check_rate_limit)."""
    allowed, _ = await check_rate_limit(
        key=f"approvals:{user.id}",
        max_requests=settings.approval_rate_limit_per_hour,
        window_seconds=3600,
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many approval operations. Please try again later.",
        )
    return user


async def _owned_proposal_or_404(proposal_id: UUID, user: User, db: AsyncSession):
    proposal = await approval_service.get_owned_proposal(db, proposal_id, user.id)
    if proposal is None:
        raise HTTPException(
            status_code=404, detail="Action proposal not found or access denied"
        )
    return proposal


async def _owned_approval_or_404(
    proposal_id: UUID, approval_id: UUID, user: User, db: AsyncSession
) -> Approval:
    result = await db.execute(
        select(Approval)
        .join(ActionProposal, ActionProposal.id == Approval.action_proposal_id)
        .join(Repository, Repository.id == ActionProposal.repository_id)
        .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
        .where(
            Approval.id == approval_id,
            Approval.action_proposal_id == proposal_id,
            GithubInstallation.user_id == user.id,
        )
    )
    approval = result.scalar_one_or_none()
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found or access denied")
    return approval


# ── Step-up authentication (honest, real flow) ───────────────────────


@router.post("/step-up")
async def begin_step_up(user: User = Depends(get_current_user)):
    """Begin step-up authentication for approval operations.

    Returns a single-use state token that must accompany the GitHub OAuth
    re-authentication round-trip. The approval session is ONLY granted when
    GitHub verifies the user again — no fake MFA, no password prompts.
    """
    import secrets

    import redis.asyncio as aioredis

    state = secrets.token_urlsafe(32)
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        await r.setex(f"stepup_state:{state}", 600, str(user.id))
    finally:
        await r.aclose()
    return {"state": state, "redirect": "/api/auth/step-up/login"}


@router.get("/step-up/status")
async def step_up_status(user: User = Depends(get_current_user)):
    """Whether the current user has a fresh step-up approval session."""
    try:
        r = await get_redis()
        raw = await r.get(f"stepup:{user.id}")
    except Exception:
        return {"step_up_valid": False}
    if not raw:
        return {"step_up_valid": False}
    from app.services import approval_model

    try:
        step_at = datetime.fromtimestamp(int(raw), tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        return {"step_up_valid": False}
    return {
        "step_up_valid": approval_model.is_step_up_fresh(step_at, datetime.now(timezone.utc)),
        "max_age_minutes": settings.step_up_max_age_minutes,
    }


# ── Approval lifecycle ───────────────────────────────────────────────


@router.get("/{proposal_id}/approval", response_model=ApprovalResponse)
async def get_approval(
    proposal_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the current approval for a proposal (404 when none exists)."""
    proposal = await _owned_proposal_or_404(proposal_id, user, db)
    approval = (
        await db.execute(
            select(Approval)
            .where(Approval.action_proposal_id == proposal.id)
            .order_by(Approval.created_at.desc())
        )
    ).scalars().first()
    if approval is None:
        raise HTTPException(status_code=404, detail="No approval for this proposal")
    return ApprovalResponse.model_validate(approval)


@router.post("/{proposal_id}/approve", response_model=ApprovalIssuedResponse)
async def approve_proposal(
    proposal_id: UUID,
    body: ApprovalCreate,
    user: User = Depends(check_approval_rate_limit),
    db: AsyncSession = Depends(get_db),
):
    """Approve an action proposal (authorization data only — NO execution).

    Server-side guarantees: digest recomputed and verified; policy
    re-evaluated against current state; DENY can never be overridden;
    expired/stale proposals denied; eligibility and step-up enforced;
    one unconsumed approval per proposal; plaintext token returned once.
    """
    proposal = await _owned_proposal_or_404(proposal_id, user, db)

    # Second principal must be a real user (server-side identity, never a
    # client-controlled role/flag).
    second_id = body.second_approver_user_id
    if second_id is not None:
        second_user = (
            await db.execute(select(User).where(User.id == second_id))
        ).scalar_one_or_none()
        if second_user is None:
            raise HTTPException(status_code=422, detail="Unknown second approver")

    outcome = await approval_service.grant_approval(
        db,
        proposal=proposal,
        approver=user,
        second_approver_user_id=second_id,
        reason=body.reason,
    )
    if not outcome.ok and outcome.reason_code not in ("ALREADY_APPROVED",):
        raise HTTPException(
            status_code=409 if outcome.reason_code in (
                "POLICY_DENIED", "ACTION_DIGEST_MISMATCH", "PROPOSAL_EXPIRED",
                "PROPOSAL_STALE", "RECOMMENDATION_CHANGED", "RISK_CHANGED",
                "POLICY_VERSION_STALE", "POLICY_DECISION_NOT_APPROVABLE",
            ) else 403,
            detail={
                "reason_code": outcome.reason_code,
                "message": "Approval denied",
            },
        )
    if outcome.approval is None:
        raise HTTPException(status_code=500, detail="Approval state error")
    return ApprovalIssuedResponse(
        **ApprovalResponse.model_validate(outcome.approval).model_dump(),
        # Idempotent re-approval of the same live approval returns NO token:
        # the plaintext token was shown exactly once, at first grant.
        authorization_token=outcome.authorization_token or "",
    )


@router.post("/{proposal_id}/reject", response_model=ApprovalResponse)
async def reject_proposal(
    proposal_id: UUID,
    body: RejectionCreate,
    user: User = Depends(check_approval_rate_limit),
    db: AsyncSession = Depends(get_db),
):
    """Reject a pending approval request (state transition only)."""
    proposal = await _owned_proposal_or_404(proposal_id, user, db)
    outcome = await approval_service.reject_approval(
        db, proposal=proposal, actor=user, reason=body.reason,
    )
    if not outcome.ok:
        raise HTTPException(
            status_code=409,
            detail={"reason_code": outcome.reason_code, "message": "Reject denied"},
        )
    return ApprovalResponse.model_validate(outcome.approval)


@router.post("/{proposal_id}/approval/{approval_id}/revoke", response_model=ApprovalResponse)
async def revoke_approval(
    proposal_id: UUID,
    approval_id: UUID,
    body: RevocationCreate,
    user: User = Depends(check_approval_rate_limit),
    db: AsyncSession = Depends(get_db),
):
    """Revoke an APPROVED approval (state transition only, no resurrection).

    The caller has already proven ownership of the proposal via the
    ownership chain (creator or co-owner); the approver of record may also
    revoke their own approval when they hold repository access.
    """
    approval = await _owned_approval_or_404(proposal_id, approval_id, user, db)
    outcome = await approval_service.revoke_approval(
        db, approval=approval, actor=user, reason=body.reason,
    )
    if not outcome.ok:
        raise HTTPException(
            status_code=409,
            detail={"reason_code": outcome.reason_code, "message": "Revoke denied"},
        )
    return ApprovalResponse.model_validate(outcome.approval)


@router.post("/{proposal_id}/approval/{approval_id}/consume-token")
async def consume_token(
    proposal_id: UUID,
    approval_id: UUID,
    body: TokenConsumeRequest,
    user: User = Depends(check_approval_rate_limit),
    db: AsyncSession = Depends(get_db),
):
    """Verify a one-time authorization token. NON-EXECUTING.

    Reserved as the single audited consumption point for the future
    executor phase. Verifies: approval state, expiry, single use, token
    hash, and digest binding. Returns verification metadata only — it
    starts no job, runs no code, writes no repository.
    """
    approval = await _owned_approval_or_404(proposal_id, approval_id, user, db)
    proposal = await _owned_proposal_or_404(proposal_id, user, db)

    # Digest binding: token is bound to this exact action
    if not approval_service.verify_proposal_digest(proposal):
        raise HTTPException(
            status_code=409,
            detail={"reason_code": "ACTION_DIGEST_MISMATCH", "message": "Digest mismatch"},
        )

    outcome = await approval_service.consume_authorization(
        db, approval=approval, presented_token=body.token,
    )
    if not outcome.ok:
        raise HTTPException(
            status_code=403,
            detail={"reason_code": outcome.reason_code, "message": "Authorization denied"},
        )
    return {
        "ok": True,
        "approval_id": str(approval.id),
        "action_digest": approval.action_digest,
        "used_at": outcome.approval.authorization_used_at.isoformat()
        if outcome.approval.authorization_used_at else None,
        "note": "Authorization verified. No execution exists in V3.2.",
    }
