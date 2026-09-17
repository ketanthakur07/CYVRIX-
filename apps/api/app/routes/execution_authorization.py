"""CYVRIX V3.3 — Execution Authorization Routes.

The FINAL DETERMINISTIC AUTHORIZATION GATE between an APPROVED action and
FUTURE EXECUTION. Authorization data only — NO execution capability:

- No git operations, no GitHub writes, no shell, no subprocess
- No file writes, no Docker, no sandbox, no worker enqueue of any executor
- No credentials are issued (no installation tokens, no secrets)
- POST /authorize creates an immutable, digest-bound contract record
- POST /authorization/{id}/consume atomically consumes the one-time
  authorization (AUTHORIZED → CONSUMED + approval → USED) and returns
  the machine-readable contract for the FUTURE executor phase (V3.4+)
- POST /authorization/{id}/revoke revokes a live authorization

Authorization: full V2 ownership chain (user → installation → repository)
on every route; cross-tenant access returns 404. All rate limits fail
closed. No GET authorizes, consumes, or mutates anything.
"""
import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import ExecutionAuthorization
from app.schemas import (
    ExecutionAuthorizationConsumeRequest,
    ExecutionAuthorizationCreate,
    ExecutionAuthorizationRevokeRequest,
    ExecutionAuthorizationResponse,
)
from app.auth import get_current_user
from app.rate_limit import check_rate_limit
from app.config import get_settings
from app.models import User
from app.services import execution_authorization_service as exec_auth_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/actions", tags=["execution-authorization"])
settings = get_settings()

# Stable reason codes that mean "stale/conflict state" (409) rather than
# "you may not do this" (403). Everything else unauthorized → 403.
_CONFLICT_CODES = {
    "ACTION_DIGEST_MISMATCH", "APPROVAL_DIGEST_MISMATCH",
    "CONTRACT_DIGEST_MISMATCH", "CONTRACT_INVALID",
    "AUTHORIZATION_REPLAY", "APPROVAL_CONSUMED", "TOKEN_REPLAY",
    "POLICY_DENIED", "POLICY_VERSION_STALE", "ACTION_EXPIRED",
    "ACTION_STALE", "APPROVAL_EXPIRED", "RECOMMENDATION_CHANGED",
    "RISK_CHANGED", "AUTHORIZATION_CONFLICT", "KILL_SWITCH_ACTIVE",
}


async def check_execution_auth_rate_limit(user: User = Depends(get_current_user)):
    """Rate-limit execution-authorization operations per user (fail closed)."""
    allowed, _ = await check_rate_limit(
        key=f"exec_auth:{user.id}",
        max_requests=settings.execution_authorization_rate_limit_per_hour,
        window_seconds=3600,
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many authorization operations. Please try again later.",
        )
    return user


def _error(reason_code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=409 if reason_code in _CONFLICT_CODES else 403,
        detail={"reason_code": reason_code, "message": message},
    )


@router.post("/{proposal_id}/authorize", response_model=ExecutionAuthorizationResponse)
async def authorize_execution(
    proposal_id: UUID,
    body: ExecutionAuthorizationCreate,
    user: User = Depends(check_execution_auth_rate_limit),
    db: AsyncSession = Depends(get_db),
):
    """Authorize execution of an APPROVED action (authorization data only).

    Server-side guarantees: ownership chain; kill switch (fail closed,
    checked twice); digest recomputed and verified (never repaired);
    approval valid/unconsumed/unexpired; proposal fresh; policy
    re-evaluated against current state (DENY can never be overridden);
    idempotent (one live authorization per proposal); immutable
    digest-bound contract record created with a durable audit event.

    This endpoint executes NOTHING and issues NO credentials.
    """
    proposal = await exec_auth_service.get_owned_proposal(db, proposal_id, user.id)
    if proposal is None:
        raise HTTPException(
            status_code=404, detail="Action proposal not found or access denied"
        )
    outcome = await exec_auth_service.authorize_execution(
        db, proposal=proposal, actor=user,
    )
    if not outcome.ok and outcome.reason_code != "ALREADY_AUTHORIZED":
        raise _error(outcome.reason_code, "Execution authorization denied")
    if outcome.authorization is None:
        raise HTTPException(status_code=500, detail="Authorization state error")
    return ExecutionAuthorizationResponse.model_validate(outcome.authorization)


@router.get("/{proposal_id}/authorization", response_model=list[ExecutionAuthorizationResponse])
async def list_authorizations(
    proposal_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List authorization records for a proposal (read-only)."""
    proposal = await exec_auth_service.get_owned_proposal(db, proposal_id, user.id)
    if proposal is None:
        raise HTTPException(
            status_code=404, detail="Action proposal not found or access denied"
        )
    rows = (
        await db.execute(
            select(ExecutionAuthorization)
            .where(ExecutionAuthorization.action_proposal_id == proposal.id)
            .order_by(ExecutionAuthorization.created_at.desc())
        )
    ).scalars().all()
    return [ExecutionAuthorizationResponse.model_validate(r) for r in rows]


@router.get("/authorization/{authorization_id}", response_model=ExecutionAuthorizationResponse)
async def get_authorization(
    authorization_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get one authorization record (read-only, ownership enforced)."""
    authorization = await exec_auth_service.get_owned_authorization(
        db, authorization_id, user.id
    )
    if authorization is None:
        raise HTTPException(
            status_code=404, detail="Authorization not found or access denied"
        )
    return ExecutionAuthorizationResponse.model_validate(authorization)


@router.post("/authorization/{authorization_id}/consume")
async def consume_authorization(
    authorization_id: UUID,
    body: ExecutionAuthorizationConsumeRequest,
    user: User = Depends(check_execution_auth_rate_limit),
    db: AsyncSession = Depends(get_db),
):
    """Atomically consume the one-time authorization. NON-EXECUTING.

    Reserved as the single audited consumption point for the future
    executor phase (V3.4+). Verifies: live state, contract integrity,
    kill switch, three-way digest agreement, approval validity, one-time
    token. Transitions AUTHORIZED → CONSUMED and approval → USED in ONE
    transaction. Returns the machine-readable contract only — it starts
    no job, runs no code, writes no repository, issues no credentials.
    """
    authorization = await exec_auth_service.get_owned_authorization(
        db, authorization_id, user.id
    )
    if authorization is None:
        raise HTTPException(
            status_code=404, detail="Authorization not found or access denied"
        )
    outcome = await exec_auth_service.consume_authorization(
        db, authorization=authorization, actor=user, presented_token=body.token,
    )
    if not outcome.ok:
        raise _error(outcome.reason_code, "Authorization consumption denied")
    authorization = outcome.authorization
    return {
        "ok": True,
        "authorization_id": str(authorization.id),
        "action_proposal_id": str(authorization.action_proposal_id),
        "approval_id": str(authorization.approval_id),
        "action_digest": authorization.action_digest,
        "authorization_state": authorization.authorization_state,
        "consumed_at": authorization.consumed_at.isoformat() if authorization.consumed_at else None,
        "contract": authorization.contract,
        "contract_digest": authorization.contract_digest,
        "note": "Authorization consumed. No execution exists in V3.3.",
    }


@router.post(
    "/authorization/{authorization_id}/revoke",
    response_model=ExecutionAuthorizationResponse,
)
async def revoke_authorization(
    authorization_id: UUID,
    body: ExecutionAuthorizationRevokeRequest,
    user: User = Depends(check_execution_auth_rate_limit),
    db: AsyncSession = Depends(get_db),
):
    """Revoke a live authorization (AUTHORIZED → REVOKED, no resurrection)."""
    authorization = await exec_auth_service.get_owned_authorization(
        db, authorization_id, user.id
    )
    if authorization is None:
        raise HTTPException(
            status_code=404, detail="Authorization not found or access denied"
        )
    outcome = await exec_auth_service.revoke_authorization(
        db, authorization=authorization, actor=user, reason=body.reason,
    )
    if not outcome.ok:
        raise _error(outcome.reason_code, "Revoke denied")
    return ExecutionAuthorizationResponse.model_validate(outcome.authorization)
