"""CYVRIX V3.5 — Controlled Git/GitHub remediation routes.

Access classes (same pattern as V3.4 execution runs):

1. USER: POST /api/actions/runs/{run_id}/remediation — starts a
   remediation from a SERVER-VERIFIED run (ownership chain enforced).
   The request body carries nothing security-relevant. Idempotent by
   design: the same run always maps to the same remediation record.
   GET endpoints are read-only status views (bounded metadata only).

2. INTERNAL EXECUTOR (service identity): POST
   /api/executor/remediations/{remediation_id}/execute — runs the
   Git/GitHub pipeline. Same bearer-token gate as V3.4 admission;
   users can never invoke it.

There is deliberately NO user route that pushes or creates PRs directly.
"""
import logging
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.config import get_settings
from app.database import get_db
from app.models import GitRemediation, User
from app.rate_limit import check_rate_limit
from app.schemas import GitRemediationResponse, GitRemediationStartRequest
from app.services import git_remediation_service as remediation_svc

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["git-remediation"])
settings = get_settings()


def _error(reason_code: str, message: str) -> HTTPException:
    conflict = {
        "REMEDIATION_EXISTS", "REMEDIATION_REPLAY", "REMEDIATION_IN_PROGRESS",
        "REMEDIATION_CONFLICT", "ACTION_DIGEST_MISMATCH", "BASE_COMMIT_MISMATCH",
        "REMOTE_STATE_MISMATCH", "RUN_NOT_VERIFIED", "SCOPE_NOT_VERIFIED",
        "SECRET_DETECTED", "KILL_SWITCH_ACTIVE", "STAGE_EXCEEDED",
        "GITHUB_STATE_MISMATCH", "BRANCH_INVALID",
    }
    unavailable = {"GIT_UNAVAILABLE", "SANDBOX_UNAVAILABLE", "RUNTIME_UNSUPPORTED"}
    status = 409 if reason_code in conflict else (
        503 if reason_code in unavailable else 403)
    return HTTPException(status_code=status,
                         detail={"reason_code": reason_code, "message": message})


async def check_remediation_rate_limit(user: User = Depends(get_current_user)):
    allowed, _ = await check_rate_limit(
        key=f"remediation:{user.id}",
        max_requests=20,
        window_seconds=3600,
    )
    if not allowed:
        raise HTTPException(status_code=429,
                            detail="Too many remediation requests. Please try again later.")
    return user


@router.post("/actions/runs/{run_id}/remediation",
             response_model=GitRemediationResponse, status_code=201)
async def start_remediation(
    run_id: UUID,
    _body: GitRemediationStartRequest,
    user: User = Depends(check_remediation_rate_limit),
    db: AsyncSession = Depends(get_db),
):
    """Start controlled Git/GitHub remediation for a verified run.

    Server-side guarantees: ownership chain; kill switch; run must be
    RESULT_READY/COMPLETED with host-side scope verification; digest
    recomputed; exactly-once per run (UNIQUE) and one live pipeline per
    authorization; server-generated remediation branch; server-derived
    stage ceiling; frozen digest-bound contract + audit event.
    This endpoint executes NOTHING and issues NO credentials.
    """
    run = await remediation_svc.get_run_for_remediation(db, run_id, user.id)
    if run is None:
        raise HTTPException(status_code=404,
                            detail="Execution run not found or access denied")
    try:
        remediation = await remediation_svc.start_remediation(
            db, run=run, actor_id=user.id)
    except remediation_svc.RemediationDenied as exc:
        raise _error(exc.reason_code, exc.detail or "remediation denied")
    return GitRemediationResponse.model_validate(remediation)


@router.get("/actions/runs/{run_id}/remediation",
            response_model=list[GitRemediationResponse])
async def list_remediations_for_run(
    run_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remediation history for a run (read-only, ownership-enforced)."""
    run = await remediation_svc.get_run_for_remediation(db, run_id, user.id)
    if run is None:
        raise HTTPException(status_code=404,
                            detail="Execution run not found or access denied")
    rows = (
        await db.execute(
            select(GitRemediation)
            .where(GitRemediation.execution_run_id == run.id)
            .order_by(GitRemediation.created_at.desc())
        )
    ).scalars().all()
    return [GitRemediationResponse.model_validate(r) for r in rows]


@router.get("/remediations/{remediation_id}", response_model=GitRemediationResponse)
async def get_remediation(
    remediation_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get one remediation (read-only, ownership enforced, 404 cross-tenant)."""
    remediation = await remediation_svc.get_owned_remediation(db, remediation_id, user.id)
    if remediation is None:
        raise HTTPException(status_code=404,
                            detail="Remediation not found or access denied")
    return GitRemediationResponse.model_validate(remediation)


# ── Internal executor boundary (service identity) ────────────────────


async def require_executor_service(authorization: str = Header(default="")) -> None:
    """Same V3.4 service-identity gate: dedicated bearer token, fail-closed."""
    expected = settings.executor_service_token
    if not expected:
        raise HTTPException(status_code=503, detail={
            "reason_code": "EXECUTOR_DISABLED",
            "message": "executor service identity not configured"})
    import hmac as hmac_mod
    presented = authorization.removeprefix("Bearer ").strip()
    if not presented or not hmac_mod.compare_digest(presented, expected):
        raise HTTPException(status_code=401, detail={
            "reason_code": "UNAUTHORIZED_CONSUMER",
            "message": "executor service authentication failed"})


@router.post("/executor/remediations/{remediation_id}/execute",
             response_model=GitRemediationResponse)
async def execute_remediation_service(
    remediation_id: UUID,
    _service: None = Depends(require_executor_service),
    db: AsyncSession = Depends(get_db),
):
    """Run the Git/GitHub pipeline for a created remediation (INTERNAL).

    Idempotent: a live/terminal remediation is returned unchanged; only
    PENDING pipelines start. Every security check is server-side.
    """
    remediation = (
        await db.execute(
            select(GitRemediation).where(
                GitRemediation.id == remediation_id)
        )
    ).scalar_one_or_none()
    if remediation is None:
        raise HTTPException(status_code=404, detail="Remediation not found")
    result = await remediation_svc.execute_remediation(
        db, remediation=remediation, actor_id=None)
    return GitRemediationResponse.model_validate(result)
