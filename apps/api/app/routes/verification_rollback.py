"""CYVRIX V3.6 — Verification + rollback routes.

Access classes (same pattern as V3.4/V3.5):

1. USER:
   - POST /api/remediations/{id}/verification — creates the exactly-once
     verification record for a committed remediation. The request body
     carries NOTHING security-relevant; the plan is server-derived and
     frozen. This endpoint executes NOTHING.
   - GET  /api/remediations/{id}/verification — read-only status + checks
   - POST /api/remediations/{id}/rollback — creates the exactly-once
     rollback record for a pushed remediation. NO client SHA exists.
     This endpoint executes NOTHING.
   - GET  /api/remediations/{id}/rollback — read-only status

2. INTERNAL EXECUTOR (service identity):
   - POST /api/executor/verifications/{id}/execute — runs the checks
   - POST /api/executor/rollbacks/{id}/execute — runs the rollback

There is deliberately NO user route that runs checks, pushes a revert,
or accepts a rollback SHA. Authority fields (verified=true, result=PASS,
rollback_sha=...) are structurally impossible: every schema forbids
extra fields and every decision is recomputed server-side.
"""
import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.config import get_settings
from app.database import get_db
from app.models import GitRemediation, User, VerificationCheck, VerificationRun
from app.rate_limit import check_rate_limit
from app.schemas import (
    RollbackRunResponse, RollbackStartRequest, VerificationCheckResponse,
    VerificationRunResponse, VerificationStartRequest,
)
from app.services import rollback_service, verification_service
from app.services.rollback_service import RollbackDenied
from app.services.verification_service import VerificationDenied

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["verification-rollback"])
settings = get_settings()


def _verification_error(reason_code: str, message: str) -> HTTPException:
    conflict = {
        "VERIFICATION_REPLAY", "VERIFICATION_CONFLICT",
        "VERIFICATION_IN_PROGRESS", "VERIFICATION_NOT_POSSIBLE",
        "ROLLBACK_REPLAY", "ROLLBACK_CONFLICT", "ROLLBACK_NOT_ALLOWED",
        "ROLLBACK_NOT_NEEDED", "KILL_SWITCH_ACTIVE",
        "ACTION_DIGEST_MISMATCH", "ROLLBACK_TARGET_INVALID",
    }
    unavailable = {"GIT_UNAVAILABLE", "SANDBOX_UNAVAILABLE"}
    status = 409 if reason_code in conflict else (
        503 if reason_code in unavailable else 403)
    if reason_code in ("VERIFICATION_NOT_FOUND", "ROLLBACK_NOT_FOUND"):
        status = 404
    return HTTPException(status_code=status,
                         detail={"reason_code": reason_code, "message": message})


async def check_verification_rate_limit(user: User = Depends(get_current_user)):
    allowed, _ = await check_rate_limit(
        key=f"verification:{user.id}", max_requests=40, window_seconds=3600)
    if not allowed:
        raise HTTPException(status_code=429,
                            detail="Too many verification requests. Please try again later.")
    return user


async def check_rollback_rate_limit(user: User = Depends(get_current_user)):
    allowed, _ = await check_rate_limit(
        key=f"rollback:{user.id}", max_requests=20, window_seconds=3600)
    if not allowed:
        raise HTTPException(status_code=429,
                            detail="Too many rollback requests. Please try again later.")
    return user


async def _owned_remediation(db: AsyncSession, remediation_id: UUID,
                             user_id) -> GitRemediation:
    remediation = await verification_service._remediation_owned(
        db, remediation_id, user_id)
    if remediation is None:
        raise HTTPException(status_code=404,
                            detail="Remediation not found or access denied")
    return remediation


# ── USER: verification ───────────────────────────────────────────────


@router.post("/remediations/{remediation_id}/verification",
             response_model=VerificationRunResponse, status_code=201)
async def start_verification(
    remediation_id: UUID,
    _body: VerificationStartRequest,
    user: User = Depends(check_verification_rate_limit),
    db: AsyncSession = Depends(get_db),
):
    """Create the exactly-once verification for a committed remediation.

    Server-side guarantees: ownership chain; kill switch; committed SHA
    present; plan frozen from trusted rows with a persisted digest;
    exactly-once per remediation (verdict is final — re-verification is
    refused at the DB level). Executes NOTHING.
    """
    remediation = await _owned_remediation(db, remediation_id, user.id)
    try:
        verification = await verification_service.start_verification(
            db, remediation=remediation, actor_id=user.id)
    except VerificationDenied as exc:
        raise _verification_error(exc.reason_code,
                                  exc.detail or "verification denied")
    return VerificationRunResponse.model_validate(verification)


@router.get("/remediations/{remediation_id}/verification",
            response_model=list[VerificationRunResponse])
async def list_verifications(
    remediation_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Verification history for a remediation (read-only, owned)."""
    remediation = await _owned_remediation(db, remediation_id, user.id)
    rows = (
        await db.execute(
            select(VerificationRun)
            .where(VerificationRun.git_remediation_id == remediation.id)
            .order_by(VerificationRun.created_at.desc())
        )
    ).scalars().all()
    return [VerificationRunResponse.model_validate(r) for r in rows]


@router.get("/verifications/{verification_id}",
            response_model=VerificationRunResponse)
async def get_verification(
    verification_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get one verification (read-only, ownership enforced, 404 cross-tenant)."""
    row = await verification_service.get_owned_verification_row(
        db, verification_id, user.id)
    if row is None:
        raise HTTPException(status_code=404,
                            detail="Verification not found or access denied")
    return VerificationRunResponse.model_validate(row)


@router.get("/verifications/{verification_id}/checks",
            response_model=list[VerificationCheckResponse])
async def get_verification_checks(
    verification_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Per-check evidence (bounded; read-only; ownership enforced)."""
    row = await verification_service.get_owned_verification_row(
        db, verification_id, user.id)
    if row is None:
        raise HTTPException(status_code=404,
                            detail="Verification not found or access denied")
    checks = (
        await db.execute(
            select(VerificationCheck).where(
                VerificationCheck.verification_run_id == row.id)
            .order_by(VerificationCheck.check_type)
        )
    ).scalars().all()
    return [VerificationCheckResponse.model_validate(c) for c in checks]


# ── USER: rollback ───────────────────────────────────────────────────


@router.post("/remediations/{remediation_id}/rollback",
             response_model=RollbackRunResponse, status_code=201)
async def start_rollback(
    remediation_id: UUID,
    _body: RollbackStartRequest,
    user: User = Depends(check_rollback_rate_limit),
    db: AsyncSession = Depends(get_db),
):
    """Create the exactly-once rollback for a pushed remediation.

    The rollback TARGET is server-derived (frozen contract base SHA);
    the request body carries NOTHING security-relevant. Executes NOTHING.
    """
    remediation = await _owned_remediation(db, remediation_id, user.id)
    try:
        rollback = await rollback_service.start_rollback(
            db, remediation=remediation, actor_id=user.id)
    except RollbackDenied as exc:
        raise _verification_error(exc.reason_code,
                                  exc.detail or "rollback denied")
    return RollbackRunResponse.model_validate(rollback)


@router.get("/remediations/{remediation_id}/rollback",
            response_model=list[RollbackRunResponse])
async def list_rollbacks(
    remediation_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Rollback history for a remediation (read-only, owned)."""
    remediation = await _owned_remediation(db, remediation_id, user.id)
    rows = (
        await db.execute(
            select(rollback_service.RollbackRun)
            .where(rollback_service.RollbackRun.git_remediation_id
                   == remediation.id)
            .order_by(rollback_service.RollbackRun.created_at.desc())
        )
    ).scalars().all()
    return [RollbackRunResponse.model_validate(r) for r in rows]


@router.get("/rollbacks/{rollback_id}", response_model=RollbackRunResponse)
async def get_rollback(
    rollback_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get one rollback (read-only, ownership enforced, 404 cross-tenant)."""
    row = await rollback_service.get_owned_rollback_row(
        db, rollback_id, user.id)
    if row is None:
        raise HTTPException(status_code=404,
                            detail="Rollback not found or access denied")
    return RollbackRunResponse.model_validate(row)


# ── Internal executor boundary (service identity) ────────────────────

from app.routes.git_remediation import require_executor_service  # noqa: E402


@router.post("/executor/verifications/{verification_id}/execute",
             response_model=VerificationRunResponse)
async def execute_verification_service(
    verification_id: UUID,
    _service: None = Depends(require_executor_service),
    db: AsyncSession = Depends(get_db),
):
    """Run the deterministic checks for a created verification (INTERNAL).

    Idempotent: a live/terminal verification is returned unchanged; only
    PENDING verifications run. The verdict is computed entirely
    server-side from trusted evidence.
    """
    verification = (
        await db.execute(
            select(VerificationRun).where(
                VerificationRun.id == verification_id)
        )
    ).scalar_one_or_none()
    if verification is None:
        raise HTTPException(status_code=404, detail="Verification not found")
    result = await verification_service.execute_verification(
        db, verification=verification)
    return VerificationRunResponse.model_validate(result)


@router.post("/executor/rollbacks/{rollback_id}/execute",
             response_model=RollbackRunResponse)
async def execute_rollback_service(
    rollback_id: UUID,
    _service: None = Depends(require_executor_service),
    db: AsyncSession = Depends(get_db),
):
    """Run the controlled rollback pipeline for a created rollback
    (INTERNAL). Idempotent: a live/terminal rollback is returned
    unchanged; only PENDING rollbacks start."""
    rollback = (
        await db.execute(
            select(rollback_service.RollbackRun).where(
                rollback_service.RollbackRun.id == rollback_id)
        )
    ).scalar_one_or_none()
    if rollback is None:
        raise HTTPException(status_code=404, detail="Rollback not found")
    result = await rollback_service.execute_rollback(db, rollback=rollback)
    return RollbackRunResponse.model_validate(result)
