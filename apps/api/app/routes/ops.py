"""CYVRIX V3.7 — Operational control-plane routes (operator API).

Every endpoint here:
- requires an authenticated session (fail closed)
- requires an explicit capability via the role matrix (least privilege)
- requires fresh STEP-UP authentication for dangerous operations
  (emergency stop, resume, circuit reset — Phase 22)
- is rate-limited
- validates all state server-side; client input can never select
  authority (no force/skip/bypass flags exist anywhere in this API)
- emits operational audit events

Administrative control ≠ remediation authorization: nothing in this
router can approve, authorize, or execute a remediation. Operators
operate the platform; remediation security is V3.1–V3.6's exclusive job.
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.config import get_settings
from app.database import get_db
from app.models import (
    CircuitBreaker, GithubInstallation, OperationalEvent, Repository,
    RepositoryControl, User,
)
from app.rate_limit import check_rate_limit, get_client_ip
from app.services import approval_model
from app.services import ops_model as om
from app.services import ops_service, reconciliation_service

logger = logging.getLogger("cyvrix.ops_routes")
settings = get_settings()
router = APIRouter(prefix="/api/ops", tags=["operations"])


# ── Capability dependencies (fail closed) ────────────────────────────


def _user_role(user: User) -> str:
    """Resolve the user's role. Bootstrap: the configured operator email
    list grants OPERATOR capabilities ONLY when the DB role is not yet
    provisioned (missing column value). Never elevates a USER row."""
    role = getattr(user, "role", None)
    if om.is_valid_role(role) and role != om.Role.USER:
        return role
    if (not role or role == om.Role.USER) and ops_service.is_operator_bootstrap_email(
        getattr(user, "email", None)
    ):
        return om.Role.OPERATOR
    return om.Role.USER


def require_capability(capability: str):
    async def _dep(user: User = Depends(get_current_user)) -> User:
        role = _user_role(user)
        if not om.role_has_capability(role, capability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="OPERATOR_CAPABILITY_REQUIRED",
            )
        return user
    return _dep


def require_capability_with_step_up(capability: str):
    async def _dep(
        request: Request,
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> User:
        role = _user_role(user)
        if not om.role_has_capability(role, capability):
            raise HTTPException(status_code=403, detail="OPERATOR_CAPABILITY_REQUIRED")
        if capability in om.STEP_UP_REQUIRED_CAPABILITIES:
            fresh = await _step_up_fresh(user)
            if not fresh:
                raise HTTPException(status_code=403, detail="STEP_UP_REQUIRED")
        return user
    return _dep


async def _step_up_fresh(user: User) -> bool:
    """Fresh step-up (GitHub re-auth round-trip) is verified from Redis
    exactly like approvals do. Redis failure ⇒ fail closed."""
    try:
        from app.session import get_redis
        r = await get_redis()
        raw = await r.get(f"stepup:{user.id}")
        if not raw or not approval_model.validate_step_up_marker(raw):
            return False
        marker_at = datetime.fromtimestamp(int(raw), tz=timezone.utc)
        return approval_model.is_step_up_fresh(marker_at, datetime.now(timezone.utc))
    except Exception:
        return False


# ── Rate limit helper ────────────────────────────────────────────────


async def _rate_limited(request: Request, user: User, bucket: str, limit: int) -> None:
    allowed, _ = await check_rate_limit(
        f"ops:{bucket}:{user.id}", limit, 3600
    )
    if not allowed:
        raise HTTPException(status_code=429, detail="RATE_LIMITED")


# ── Schemas (no authority fields exist — by design) ──────────────────


class OpsStateOut(BaseModel):
    operational_state: str
    kill_switch_disabled: bool
    detail: Optional[str] = None


class CapabilitiesOut(BaseModel):
    """Server-derived identity view for the console (V3.9).

    Read-only presentation of the SAME role/capability resolution the
    capability dependencies enforce. It grants nothing: every route
    re-derives the role server-side, so a tampered response can only
    change what the browser displays, never what the server permits.
    """
    role: str
    capabilities: list[str]
    step_up_required: list[str]


class OpsTransitionIn(BaseModel):
    target: str = Field(min_length=4, max_length=20)


class RepoControlIn(BaseModel):
    control_state: str = Field(min_length=5, max_length=10)
    reason: Optional[str] = Field(default=None, max_length=200)


class RepoControlOut(BaseModel):
    repository_id: str
    control_state: str
    reason: Optional[str] = None


class BreakerOut(BaseModel):
    id: str
    repository_id: str
    scope: str
    action_type: str
    breaker_state: str
    consecutive_failures: int
    max_consecutive_failures: int


class ReconciliationOut(BaseModel):
    id: str
    trigger: str
    status: str
    stats: Optional[dict] = None
    findings: Optional[list] = None


# ── Identity: caller capabilities (authenticated only) ───────────────


@router.get("/capabilities", response_model=CapabilitiesOut)
async def get_capabilities(
    user: User = Depends(get_current_user),
):
    """Return the caller's server-derived role and capability set.

    Authenticated but NOT capability-gated (a caller must be able to
    discover its own authority). No tenant data is exposed. The console
    uses this only to shape the UI; the server remains authoritative.
    """
    role = _user_role(user)
    caps = sorted(om.ROLE_CAPABILITIES.get(role, frozenset()))
    return CapabilitiesOut(
        role=role,
        capabilities=caps,
        step_up_required=sorted(om.STEP_UP_REQUIRED_CAPABILITIES),
    )


# ── Read: system status (VIEW_OPERATIONS) ────────────────────────────


@router.get("/status", response_model=OpsStateOut)
async def get_status(
    request: Request,
    user: User = Depends(require_capability(om.CAP_VIEW_OPERATIONS)),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limited(request, user, "status", settings.ops_rate_limit_per_hour)
    state, fail = await ops_service.read_operational_state(db)
    from app.services.execution_authorization_service import read_kill_switch
    disabled, ks_reason = await read_kill_switch(db)
    return OpsStateOut(
        operational_state=state or "UNKNOWN",
        kill_switch_disabled=disabled,
        detail=fail or ks_reason,
    )


# ── Transitions: pause / drain / emergency stop / resume ─────────────


@router.post("/state", response_model=OpsStateOut)
async def post_state(
    body: OpsTransitionIn,
    request: Request,
    user: User = Depends(
        require_capability_with_step_up(om.CAP_PAUSE_SYSTEM)
    ),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limited(request, user, "state", settings.ops_rate_limit_per_hour)
    target = body.target.strip().upper()
    if target not in om.ALL_OPS_STATES:
        raise HTTPException(status_code=422, detail="INVALID_TARGET_STATE")

    # Step-up enforcement per target (emergency stop + resume are the
    # dangerous ones; pause/drain are ordinary operator actions).
    if target in (om.OpsState.EMERGENCY_STOP, om.OpsState.NORMAL):
        if not await _step_up_fresh(user):
            raise HTTPException(status_code=403, detail="STEP_UP_REQUIRED")

    # Emergency stop requires the stronger capability.
    if target == om.OpsState.EMERGENCY_STOP and not om.role_has_capability(
        _user_role(user), om.CAP_EMERGENCY_STOP
    ):
        raise HTTPException(status_code=403, detail="EMERGENCY_STOP_CAPABILITY_REQUIRED")

    # Resume (PAUSED → NORMAL) is the reconciled-resume path: the caller
    # must have run reconciliation that found no unresolved state.
    if target == om.OpsState.NORMAL:
        current, _ = await ops_service.read_operational_state(db)
        if current == om.OpsState.EMERGENCY_STOP:
            raise HTTPException(
                status_code=409,
                detail="RESUME_FROM_EMERGENCY_STOP_REQUIRES_PAUSE_FIRST",
            )
        ok_resume, resume_reason = await _resume_gate(db)
        if not ok_resume:
            raise HTTPException(status_code=409, detail=resume_reason or "RECONCILIATION_REQUIRED")

    ok, fail = await ops_service.set_operational_state(db, target=target, actor=user)
    if not ok:
        raise HTTPException(status_code=409, detail=fail or "TRANSITION_REFUSED")
    state, fail2 = await ops_service.read_operational_state(db)
    return OpsStateOut(operational_state=state or "UNKNOWN", kill_switch_disabled=False, detail=fail2)


async def _resume_gate(db: AsyncSession) -> tuple[bool, Optional[str]]:
    """Resume (→ NORMAL) requires a recent COMPLETED reconciliation pass
    with zero UNKNOWN/INCONSISTENT findings and no stuck executions.
    Fail closed: no recent reconciliation ⇒ refuse resume."""
    # reconciliation_runs is the authoritative reconciliation record (the
    # operational_events feed is diagnostics, not a decision input).
    from app.models import ReconciliationRun
    last = (
        await db.execute(
            select(ReconciliationRun)
            .where(ReconciliationRun.status == "COMPLETED")
            .order_by(ReconciliationRun.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if last is None:
        return False, "RECONCILIATION_REQUIRED_BEFORE_RESUME"
    age = datetime.now(timezone.utc) - (
        last.created_at if last.created_at.tzinfo else last.created_at.replace(tzinfo=timezone.utc)
    )
    if age.total_seconds() > 900:  # reconciliation older than 15 min
        return False, "RECONCILIATION_STALE_RUN_AGAIN"
    findings = last.findings or []
    blocking = [
        f for f in findings
        if isinstance(f, dict) and f.get("classification") in ("UNKNOWN", "INCONSISTENT", "STUCK")
    ]
    if blocking:
        return False, "RECONCILIATION_FINDINGS_UNRESOLVED"
    return True, None


# ── Repository controls ──────────────────────────────────────────────


@router.get("/repositories/{repository_id}/control", response_model=RepoControlOut)
async def get_repo_control(
    repository_id,
    request: Request,
    user: User = Depends(require_capability(om.CAP_VIEW_OPERATIONS)),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limited(request, user, "repo-read", settings.ops_rate_limit_per_hour)
    repo = await _owned_repository(db, user, repository_id)
    control = await ops_service.get_repository_control(db, repository_id=repo.id)
    return RepoControlOut(
        repository_id=str(repo.id),
        control_state=control.control_state if control else om.RepoControlState.ENABLED,
        reason=control.reason if control else None,
    )


@router.post("/repositories/{repository_id}/control", response_model=RepoControlOut)
async def set_repo_control(
    repository_id,
    body: RepoControlIn,
    request: Request,
    user: User = Depends(require_capability(om.CAP_SET_REPO_CONTROL)),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limited(request, user, "repo-write", settings.ops_rate_limit_per_hour)
    repo = await _owned_repository(db, user, repository_id)
    target = body.control_state.strip().upper()
    if not om.is_valid_repo_control(target):
        raise HTTPException(status_code=422, detail="INVALID_CONTROL_STATE")
    ok, fail = await ops_service.set_repository_control(
        db, repository_id=repo.id, target=target, actor=user, reason=body.reason
    )
    if not ok:
        raise HTTPException(status_code=409, detail=fail or "REFUSED")
    return RepoControlOut(repository_id=str(repo.id), control_state=target, reason=body.reason)


async def _owned_repository(db: AsyncSession, user: User, repository_id) -> Repository:
    """Tenant-safe repository resolution: user → installation → repo.
    An operator can only touch repositories inside installations they own.
    (Cross-tenant operational control is impossible by construction.)"""
    try:
        rid = __import__("uuid").UUID(str(repository_id))
    except ValueError:
        raise HTTPException(status_code=404, detail="REPOSITORY_NOT_FOUND")
    repo = (
        await db.execute(
            select(Repository)
            .join(GithubInstallation, Repository.installation_id == GithubInstallation.id)
            .where(Repository.id == rid, GithubInstallation.user_id == user.id)
        )
    ).scalar_one_or_none()
    if repo is None:
        raise HTTPException(status_code=404, detail="REPOSITORY_NOT_FOUND")
    return repo


# ── Circuit breakers ─────────────────────────────────────────────────


@router.get("/breakers", response_model=list[BreakerOut])
async def list_breakers(
    request: Request,
    user: User = Depends(require_capability(om.CAP_VIEW_OPERATIONS)),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limited(request, user, "breakers", settings.ops_rate_limit_per_hour)
    rows = (
        await db.execute(
            select(CircuitBreaker)
            .join(GithubInstallation, CircuitBreaker.repository_id == Repository.id)
            .join(Repository, Repository.id == CircuitBreaker.repository_id)
            .where(GithubInstallation.user_id == user.id)
        )
        .scalars()
        .all()
    )
    return [
        BreakerOut(
            id=str(r.id),
            repository_id=str(r.repository_id),
            scope=r.scope,
            action_type=r.action_type,
            breaker_state=r.breaker_state,
            consecutive_failures=r.consecutive_failures,
            max_consecutive_failures=r.max_consecutive_failures,
        )
        for r in rows
    ]


@router.post("/breakers/{breaker_id}/reset", response_model=BreakerOut)
async def reset_breaker(
    breaker_id,
    request: Request,
    user: User = Depends(require_capability_with_step_up(om.CAP_RESET_CIRCUIT)),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limited(request, user, "breaker-reset", settings.ops_rate_limit_per_hour)
    try:
        bid = __import__("uuid").UUID(str(breaker_id))
    except ValueError:
        raise HTTPException(status_code=404, detail="BREAKER_NOT_FOUND")
    breaker = (
        await db.execute(
            select(CircuitBreaker)
            .join(Repository, Repository.id == CircuitBreaker.repository_id)
            .join(GithubInstallation, Repository.installation_id == GithubInstallation.id)
            .where(CircuitBreaker.id == bid, GithubInstallation.user_id == user.id)
        )
    ).scalars().first()
    if breaker is None:
        raise HTTPException(status_code=404, detail="BREAKER_NOT_FOUND")
    ok, fail = await ops_service.reset_circuit(
        db, repository_id=breaker.repository_id, scope=breaker.scope,
        action_type=breaker.action_type, actor=user,
    )
    if not ok:
        raise HTTPException(status_code=409, detail=fail or "REFUSED")
    return BreakerOut(
        id=str(breaker.id),
        repository_id=str(breaker.repository_id),
        scope=breaker.scope,
        action_type=breaker.action_type,
        breaker_state=breaker.breaker_state,
        consecutive_failures=breaker.consecutive_failures,
        max_consecutive_failures=breaker.max_consecutive_failures,
    )


# ── Reconciliation ───────────────────────────────────────────────────


@router.post("/reconciliation/run", response_model=ReconciliationOut)
async def run_reconciliation_route(
    request: Request,
    user: User = Depends(require_capability(om.CAP_RUN_RECONCILIATION)),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limited(request, user, "reconciliation", settings.ops_reconciliation_rate_limit_per_hour)
    rec = await reconciliation_service.run_reconciliation(db, trigger="OPERATOR", actor=user)
    return ReconciliationOut(
        id=str(rec.id), trigger=rec.trigger, status=rec.status,
        stats=rec.stats, findings=rec.findings,
    )


# ── V4.2 Phase 27: worker drain (deployment control) ─────────────────


@router.post("/workers/{worker_id}/drain")
async def drain_worker(
    request: Request,
    worker_id: str,
    user: User = Depends(require_capability(om.CAP_PAUSE_SYSTEM)),
):
    """Request a graceful worker drain.

    A draining worker stops claiming new jobs, finishes its current job
    (RQ warm shutdown), and exits cleanly — used during rolling deploys.
    The marker lives in Redis so ANY api instance can drain ANY worker.
    Deployment control never touches authorization state: it cannot
    create, approve, authorize, or execute anything (Phase 42: this is
    INFRASTRUCTURE lifecycle, not remediation rollback).

    worker_id must match the worker's own identity (hostname-derived);
    unknown ids are accepted but harmless — the marker simply expires.
    """
    await _rate_limited(request, user, "worker-drain", settings.ops_rate_limit_per_hour)
    if not worker_id or len(worker_id) > 128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in worker_id):
        raise HTTPException(status_code=422, detail="WORKER_ID_INVALID")
    from app.session import get_redis
    from app.worker_runtime import request_drain

    r = await get_redis()
    ok = await request_drain(r, worker_id=worker_id)
    if not ok:
        raise HTTPException(status_code=503, detail="DRAIN_REQUEST_UNAVAILABLE")
    return {"worker_id": worker_id, "drain_requested": True}


@router.get("/workers")
async def list_workers(
    request: Request,
    user: User = Depends(require_capability(om.CAP_VIEW_OPERATIONS)),
):
    """Live worker fleet view (heartbeat-derived; expired workers vanish)."""
    await _rate_limited(request, user, "workers-read", settings.ops_rate_limit_per_hour)
    from app.session import get_redis
    from app.worker_runtime import fleet_snapshot

    r = await get_redis()
    fleet = await fleet_snapshot(r)
    workers = []
    for worker_id, info in (fleet.get("workers") or {}).items():
        workers.append(
            {
                "worker_id": worker_id,
                "state": info.get("state"),
                "queues": info.get("queues"),
                "current_job": info.get("current_job") or None,
                "last_heartbeat": info.get("last_heartbeat"),
            }
        )
    return {"workers": workers}


@router.get("/reconciliation/last", response_model=Optional[ReconciliationOut])
async def last_reconciliation(
    request: Request,
    user: User = Depends(require_capability(om.CAP_VIEW_OPERATIONS)),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limited(request, user, "reconciliation-read", settings.ops_rate_limit_per_hour)
    from app.models import ReconciliationRun
    rec = (
        await db.execute(
            select(ReconciliationRun).order_by(ReconciliationRun.created_at.desc()).limit(1)
        )
    ).scalar_one_or_none()
    if rec is None:
        return None
    return ReconciliationOut(
        id=str(rec.id), trigger=rec.trigger, status=rec.status,
        stats=rec.stats, findings=rec.findings,
    )


# ── Operational events (diagnostics feed) ────────────────────────────


@router.get("/metrics")
async def get_metrics(
    request: Request,
    user: User = Depends(require_capability(om.CAP_VIEW_DIAGNOSTICS)),
):
    """V4.1 metrics snapshot (Prometheus text format).

    An OPERATOR surface: capability-gated, session-authenticated, never
    on the public API. The payload is content-free by construction —
    bounded, allowlisted label values only; no organization names,
    repository names, branches, or user content can appear.
    """
    await _rate_limited(request, user, "metrics", settings.ops_rate_limit_per_hour)
    from app.metrics import render_prometheus, set_gauge

    # V4.2 Phase 20/21: live platform gauges — worker fleet liveness and
    # queue depths are read from Redis at scrape time. Content-free by
    # construction: COUNTS only (no per-worker labels — that would mint
    # an unbounded series per worker lifecycle). If Redis is unavailable
    # the gauges keep their last known values; the scrape never fails on
    # a dependency blip.
    try:
        from app.session import get_redis
        from app.worker_runtime import fleet_snapshot

        r = await get_redis()
        fleet = await fleet_snapshot(r)
        live = 0
        draining = 0
        for info in (fleet.get("workers") or {}).values():
            state = (info.get("state") or "").upper()
            if state == "DRAINING":
                draining += 1
            elif state in ("RUNNING", "BUSY"):
                live += 1
        set_gauge("cyvrix_workers_live", live)
        set_gauge("cyvrix_workers_draining", draining)
        set_gauge("cyvrix_queue_depth_scans", max(0, int(await r.llen("rq:queue:scans"))))
        set_gauge("cyvrix_queue_depth_container_scans", max(0, int(await r.llen("rq:queue:container_scans"))))
        set_gauge("cyvrix_queue_depth_log_analysis", max(0, int(await r.llen("rq:queue:log_analysis"))))
    except Exception:
        # Redis blipped: gauges hold last values, scrape still serves.
        pass

    from fastapi.responses import PlainTextResponse

    return PlainTextResponse(
        render_prometheus(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@router.get("/events")
async def list_events(
    request: Request,
    limit: int = 50,
    user: User = Depends(require_capability(om.CAP_VIEW_DIAGNOSTICS)),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limited(request, user, "events", settings.ops_rate_limit_per_hour)
    limit = max(1, min(int(limit), 200))
    rows = (
        await db.execute(
            select(OperationalEvent).order_by(OperationalEvent.created_at.desc()).limit(limit)
        )
    ).scalars().all()
    return [
        {
            "id": str(r.id),
            "event_type": r.event_type,
            "repository_id": str(r.repository_id) if r.repository_id else None,
            "reason_code": r.reason_code,
            "detail": r.detail,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
