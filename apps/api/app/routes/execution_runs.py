"""CYVRIX V3.4 — Execution-run routes.

TWO access classes, both never bypassing V3.3 (§87/§88):

1. INTERNAL EXECUTOR (service identity): POST /api/executor/runs
   Authenticated with a dedicated service token (Authorization: Bearer),
   NOT a user session. The executor cannot self-authorize: admission
   validates the V3.3 authorization record, re-verifies digests, scope,
   kill switch, and consumes the authorization atomically. The request
   body carries nothing security-relevant.

2. USER READ-ONLY STATUS: GET /api/executor/runs/{run_id} and
   GET /api/actions/{proposal_id}/runs — ownership-enforced read-only
   views of bounded run metadata. No GET mutates anything.

There is deliberately NO user-facing "execute now" endpoint: users can
approve, authorize, and observe — only the internal executor service can
admit a run, and it must present the one-time approval token.
"""
import logging
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.config import get_settings
from app.database import get_db
from app.models import ActionProposal, ExecutionAuthorization, ExecutionRun, User
from app.rate_limit import check_rate_limit
from app.schemas import ExecutionAdmissionRequest, ExecutionRunResponse
from app.services import execution_service, execution_run_model as erm
from app.services.execution_authorization_service import get_owned_authorization

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["execution-runs"])
settings = get_settings()


def _error(reason_code: str, message: str) -> HTTPException:
    conflict = {
        erm.RC_EXECUTION_REPLAY, erm.RC_EXECUTION_IN_PROGRESS,
        erm.RC_KILL_SWITCH_ACTIVE, erm.RC_ACTION_DIGEST_MISMATCH,
        erm.RC_ACTION_SCOPE_VIOLATION, erm.RC_PROTECTED_PATH,
        erm.RC_AUTHORIZATION_EXPIRED, erm.RC_AUTHORIZATION_REVOKED,
        "AUTHORIZATION_CONFLICT",
    }
    unavailable = {
        erm.RC_SANDBOX_UNAVAILABLE, erm.RC_RUNTIME_UNSUPPORTED,
        erm.RC_SANDBOX_POLICY_UNSUPPORTED,
    }
    status = (
        409 if reason_code in conflict
        else 503 if reason_code in unavailable
        else 403
    )
    return HTTPException(
        status_code=status,
        detail={"reason_code": reason_code, "message": message},
    )


async def require_executor_service(
    authorization: str = Header(default=""),
) -> None:
    """Service identity for the internal executor boundary (§88).

    A dedicated token — not a user session, not a worker-claimed boolean.
    Disabled (fails closed) until EXECUTOR_SERVICE_TOKEN is configured.
    """
    expected = settings.executor_service_token
    if not expected:
        raise HTTPException(
            status_code=503,
            detail={"reason_code": "EXECUTOR_DISABLED",
                    "message": "executor service identity not configured"},
        )
    import hmac as hmac_mod
    presented = authorization.removeprefix("Bearer ").strip()
    if not presented or not hmac_mod.compare_digest(presented, expected):
        raise HTTPException(
            status_code=401,
            detail={"reason_code": "UNAUTHORIZED_CONSUMER",
                    "message": "executor service authentication failed"},
        )


@router.post("/executor/runs", response_model=ExecutionRunResponse, status_code=202)
async def admit_and_execute(
    body: ExecutionAdmissionRequest,
    _service: None = Depends(require_executor_service),
    db: AsyncSession = Depends(get_db),
):
    """Admit one authorized execution and run it through the sandbox.

    INTERNAL ONLY. Exactly-once: a replayed authorization is refused
    with EXECUTION_REPLAY; a concurrent one with EXECUTION_IN_PROGRESS.
    Returns bounded run metadata only.
    """
    allowed, _ = await check_rate_limit(
        key="executor:admission",
        max_requests=settings.execution_admission_rate_limit_per_hour,
        window_seconds=3600,
    )
    if not allowed:
        raise HTTPException(status_code=429, detail="Admission rate limit exceeded")

    authorization = (
        await db.execute(
            select(ExecutionAuthorization).where(
                ExecutionAuthorization.id == body.execution_authorization_id
            )
        )
    ).scalar_one_or_none()
    if authorization is None:
        raise HTTPException(
            status_code=404, detail="Authorization not found"
        )

    try:
        run = await execution_service.admit_execution(
            db, authorization=authorization, actor=None,
            presented_token=body.token,
        )
    except execution_service.ExecutionDenied as exc:
        raise _error(exc.reason_code, exc.detail or "execution denied")

    # admitted: run the sandbox pipeline. Failures inside the pipeline
    # are recorded on the run (FAILED/CLEANUP_FAILED), not raised.
    try:
        run = await execution_service.execute_authorized_run(
            db, run=run, authorization=authorization
        )
    except execution_service.ExecutionFailure as exc:
        raise _error(exc.reason_code, exc.detail or "execution failed")

    return ExecutionRunResponse.model_validate(run)


@router.get("/executor/runs/{run_id}", response_model=ExecutionRunResponse)
async def get_run_service(
    run_id: UUID,
    _service: None = Depends(require_executor_service),
    db: AsyncSession = Depends(get_db),
):
    """Service view of a run (read-only)."""
    run = (
        await db.execute(
            select(ExecutionRun).where(ExecutionRun.id == run_id)
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return ExecutionRunResponse.model_validate(run)


@router.get("/actions/{proposal_id}/runs", response_model=list[ExecutionRunResponse])
async def list_runs_for_proposal(
    proposal_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """User-visible run history for a proposal (read-only, ownership)."""
    from app.services.execution_authorization_service import get_owned_proposal

    proposal = await get_owned_proposal(db, proposal_id, user.id)
    if proposal is None:
        raise HTTPException(
            status_code=404, detail="Action proposal not found or access denied"
        )
    rows = (
        await db.execute(
            select(ExecutionRun)
            .where(ExecutionRun.action_proposal_id == proposal.id)
            .order_by(ExecutionRun.created_at.desc())
        )
    ).scalars().all()
    return [ExecutionRunResponse.model_validate(r) for r in rows]


@router.get("/executor/runs/user/{run_id}", response_model=ExecutionRunResponse)
async def get_run_user(
    run_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """User-visible run status (read-only, ownership-enforced, 404 cross-tenant)."""
    run = await execution_service.get_run_for_user(db, run_id, user.id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found or access denied")
    return ExecutionRunResponse.model_validate(run)
