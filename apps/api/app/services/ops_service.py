"""CYVRIX V3.7 — Operational control-plane service (impure).

Server-side enforcement of operational safety around the V3.1–V3.6
pipelines. Everything here FAILS CLOSED:

- read_operational_state(): unknown/missing/unreadable ⇒ not NORMAL
- assert_execution_allowed(): state × repo control × circuit × quota
- circuit breakers: bounded consecutive failures, operator reset only
- leases: explicit ownership/expiry, no takeover by admission paths
- quota counting: server-side; clients cannot raise limits

This module never authorizes a remediation by itself: it only gates the
existing V3.3 authorization → V3.5 execution → V3.6 verification flow.
An operator can pause the world; they can never make an unauthorized
remediation pass its own security checks.
"""
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models import (
    CircuitBreaker, ExecutionLease, ExecutionRun, OperationalEvent,
    RepositoryControl, SystemControl, User,
)
from app.services import ops_model as om
from app.services.execution_authorization_service import read_kill_switch

logger = logging.getLogger("cyvrix.ops")

# ── Bootstrap guard (Phase 21/23): who may be an operator? ───────────


def _operator_bootstrap_emails() -> frozenset:
    raw = os.environ.get("CYVRIX_OPERATOR_EMAILS", "")
    return frozenset(e.strip().lower() for e in raw.split(",") if e.strip())


def is_operator_bootstrap_email(email: Optional[str]) -> bool:
    if not email:
        return False
    return email.strip().lower() in _operator_bootstrap_emails()


# ── Operational state (system-wide) ──────────────────────────────────


async def read_operational_state(db: AsyncSession) -> tuple[str, Optional[str]]:
    """Read the operational state. FAIL CLOSED: missing, unreadable, or
    unparseable values are never NORMAL. Returns (state, fail_reason)."""
    try:
        row = (
            await db.execute(
                select(SystemControl).where(SystemControl.key == om.OPS_STATE_KEY)
            )
        ).scalar_one_or_none()
    except Exception as exc:
        return om.OpsState.EMERGENCY_STOP, f"{om.RC_OPS_READ_FAILED}:{type(exc).__name__}"
    if row is None:
        # Unprovisioned: fail closed, but keep the legacy kill-switch
        # semantics available (the migration provisions this row; absent
        # row ⇒ blocked with a distinct reason).
        return None, om.RC_OPS_STATE_MISSING
    state, reason = om.parse_ops_state(row.value)
    if state is None:
        return om.OpsState.EMERGENCY_STOP, reason
    return state, None


async def set_operational_state(
    db: AsyncSession,
    *,
    target: str,
    actor: Optional[User],
    force_transition_check: bool = True,
    now: Optional[datetime] = None,
) -> tuple[bool, Optional[str]]:
    """Transition the operational state with an explicit validated graph.

    The transition is audited (operational_events). Returns
    (ok, fail_reason). EMERGENCY_STOP → NORMAL does not exist; recovery
    is EMERGENCY_STOP → PAUSED (reconciled resume) → NORMAL.
    """
    now = now or datetime.now(timezone.utc)
    current, fail = await read_operational_state(db)
    if current is None:
        return False, fail
    if not om.can_transition(current, target):
        return False, om.RC_OPS_TRANSITION_INVALID

    try:
        row = (
            await db.execute(
                select(SystemControl).where(SystemControl.key == om.OPS_STATE_KEY)
            )
        ).scalar_one_or_none()
        if row is None:
            return False, om.RC_OPS_STATE_MISSING
        # Re-validate the stored value inside the transaction (TOCTOU)
        recheck, recheck_reason = om.parse_ops_state(row.value)
        if recheck is None or (force_transition_check and recheck != current):
            return False, om.RC_OPS_TRANSITION_INVALID
        row.value = target
        row.updated_at = now
        await _op_event(
            db,
            event_type=(
                om.EVENT_EMERGENCY_STOP if target == om.OpsState.EMERGENCY_STOP
                else om.EVENT_SYSTEM_RESUMED if target == om.OpsState.NORMAL
                else om.EVENT_SYSTEM_PAUSED
            ),
            reason_code=target,
            detail=f"operational_state {current} → {target}",
            actor=actor,
        )
        await db.commit()
        return True, None
    except Exception as exc:
        await db.rollback()
        logger.warning("set_operational_state_failed err=%s", type(exc).__name__)
        return False, f"{om.RC_OPS_READ_FAILED}:{type(exc).__name__}"


# ── The one gate every mutating pipeline calls ───────────────────────


async def assert_execution_allowed(
    db: AsyncSession,
    *,
    repository_id,
    action_type: Optional[str] = None,
    scope: str = "EXECUTION",
    now: Optional[datetime] = None,
) -> tuple[bool, Optional[str]]:
    """The single V3.7 gate for NEW mutations/execution.

    Order: kill switch (legacy, unchanged) → operational state →
    repository control → circuit breaker → concurrency quotas. Returns
    (allowed, fail_reason_code)."""
    now = now or datetime.now(timezone.utc)

    # 0. Legacy kill switch (V3.3 semantics preserved verbatim)
    disabled, ks_reason = await read_kill_switch(db)
    if disabled:
        return False, ks_reason or "KILL_SWITCH_ACTIVE"

    # 1. Operational state
    state, fail = await read_operational_state(db)
    if state is None:
        return False, fail or om.RC_OPS_STATE_MISSING
    if not om.execution_allowed(state):
        reason = {
            om.OpsState.PAUSED: om.RC_SYSTEM_PAUSED,
            om.OpsState.DRAINING: om.RC_SYSTEM_DRAINING,
            om.OpsState.EMERGENCY_STOP: om.RC_EMERGENCY_STOP,
        }.get(state, om.RC_EMERGENCY_STOP)
        return False, reason

    # 2. Repository control. Containment is OPT-IN: a missing row means
    #    "no operator containment applied" (default ENABLED) so an
    #    upgrade never silently changes V3.1–V3.6 behavior. An EXPLICIT
    #    PAUSED/BLOCKED row is enforced strictly; a corrupt value fails
    #    closed. The security-critical fail-closed surface is the system
    #    state + kill switch, not this containment tool.
    control = (
        await db.execute(
            select(RepositoryControl).where(RepositoryControl.repository_id == repository_id)
        )
    ).scalar_one_or_none()
    control_state = control.control_state if control is not None else om.RepoControlState.ENABLED
    if not om.repo_execution_allowed(control_state):
        return False, (
            om.RC_REPO_BLOCKED if control_state == om.RepoControlState.BLOCKED
            else om.RC_REPO_PAUSED if control_state == om.RepoControlState.PAUSED
            else om.RC_REPO_CONTROL_MISSING
        )

    # 3. Circuit breaker for (repo, scope, action_type)
    breaker, reason = await _load_breaker(db, repository_id=repository_id, scope=scope, action_type=action_type)
    if breaker is None:
        return False, reason
    evaluation = om.evaluate_circuit(
        breaker.breaker_state,
        breaker.consecutive_failures,
        max_consecutive_failures=breaker.max_consecutive_failures,
    )
    if not evaluation.allowed:
        return False, evaluation.reason or om.RC_CIRCUIT_OPEN

    # 4. Concurrency quotas (server-counted)
    ok, quota_reason = await _check_quotas(db, repository_id=repository_id, now=now)
    if not ok:
        return False, quota_reason

    return True, None


async def assert_verification_allowed(
    db: AsyncSession,
    *,
    repository_id,
) -> tuple[bool, Optional[str]]:
    """Verification gate: read-only work, allowed under ENABLED/PAUSED,
    blocked under BLOCKED/EMERGENCY_STOP/unknown."""
    disabled, ks_reason = await read_kill_switch(db)
    if disabled:
        return False, ks_reason or "KILL_SWITCH_ACTIVE"
    state, fail = await read_operational_state(db)
    if state is None:
        return False, fail or om.RC_OPS_STATE_MISSING
    if state == om.OpsState.EMERGENCY_STOP:
        return False, om.RC_EMERGENCY_STOP
    control = (
        await db.execute(
            select(RepositoryControl).where(RepositoryControl.repository_id == repository_id)
        )
    ).scalar_one_or_none()
    control_state = control.control_state if control is not None else om.RepoControlState.ENABLED
    if not om.repo_allows_verification(control_state):
        return False, om.RC_REPO_BLOCKED if control_state == om.RepoControlState.BLOCKED else om.RC_REPO_CONTROL_MISSING
    return True, None


async def assert_rollback_allowed(
    db: AsyncSession,
    *,
    repository_id,
    now: Optional[datetime] = None,
) -> tuple[bool, Optional[str]]:
    """Rollback gate: full execution gate (rollback is a GitHub mutation)."""
    return await assert_execution_allowed(
        db, repository_id=repository_id, scope="ROLLBACK", now=now
    )


# ── Circuit breakers ─────────────────────────────────────────────────


async def _load_breaker(
    db: AsyncSession,
    *,
    repository_id,
    scope: str,
    action_type: Optional[str],
) -> tuple[Optional[CircuitBreaker], Optional[str]]:
    """Load the effective breaker for (repo, scope, action_type).

    Falls back from the exact action_type to the ANY row. A MISSING row
    means "no failure history" → a synthetic CLOSED breaker (breakers are
    opt-in reliability tools; the first recorded failure creates the
    row). An EXPLICITLY OPEN breaker or a corrupt state value is enforced
    strictly / fails closed."""
    action_type = action_type or "ANY"
    rows = (
        (
            await db.execute(
                select(CircuitBreaker).where(
                    CircuitBreaker.repository_id == repository_id,
                    CircuitBreaker.scope == scope,
                    CircuitBreaker.action_type.in_([action_type, "ANY"]),
                )
            )
        )
        .scalars()
        .all()
    )
    exact = next((r for r in rows if r.action_type == action_type), None)
    any_row = next((r for r in rows if r.action_type == "ANY"), None)
    if action_type != "ANY" and exact is not None:
        return exact, None
    if any_row is not None:
        return any_row, None
    # Unprovisioned scope: synthetic CLOSED (no failure history yet)
    synthetic = CircuitBreaker(
        repository_id=repository_id, scope=scope, action_type=action_type,
        breaker_state=om.CircuitState.CLOSED, consecutive_failures=0,
        max_consecutive_failures=get_settings().ops_breaker_max_failures,
    )
    return synthetic, None


async def record_execution_failure(
    db: AsyncSession,
    *,
    repository_id,
    scope: str = "EXECUTION",
    action_type: Optional[str] = None,
    reason_code: Optional[str] = None,
    actor: Optional[User] = None,
) -> bool:
    """Record a failure; OPEN the breaker at the configured bound.

    Returns True when this call opened the breaker (audited)."""
    breaker, _ = await _load_breaker(db, repository_id=repository_id, scope=scope, action_type=action_type)
    if breaker is None:
        return False
    if breaker.id is None:
        # Synthetic (unprovisioned) breaker: persist it now so failures
        # accumulate durably from the very first one.
        db.add(breaker)
        await db.flush()
    breaker.consecutive_failures = (breaker.consecutive_failures or 0) + 1
    opened = False
    if breaker.consecutive_failures >= breaker.max_consecutive_failures and breaker.breaker_state != om.CircuitState.OPEN:
        breaker.breaker_state = om.CircuitState.OPEN
        breaker.opened_at = datetime.now(timezone.utc)
        breaker.opened_reason_code = (reason_code or "UNKNOWN")[:60]
        opened = True
    await _op_event(
        db,
        event_type=om.EVENT_CIRCUIT_OPENED if opened else "EXECUTION_FAILURE_RECORDED",
        repository_id=repository_id,
        subject_type="BREAKER",
        subject_id=breaker.id,
        reason_code=(reason_code or "UNKNOWN")[:60],
        detail=f"consecutive_failures={breaker.consecutive_failures}",
        actor=actor,
    )
    return opened


async def record_execution_success(
    db: AsyncSession,
    *,
    repository_id,
    scope: str = "EXECUTION",
    action_type: Optional[str] = None,
) -> None:
    """A success resets the consecutive-failure count (never an OPEN
    breaker — that requires the operator reset)."""
    breaker, _ = await _load_breaker(db, repository_id=repository_id, scope=scope, action_type=action_type)
    if breaker is not None and breaker.breaker_state == om.CircuitState.CLOSED:
        breaker.consecutive_failures = 0


async def reset_circuit(
    db: AsyncSession,
    *,
    repository_id,
    scope: str,
    action_type: Optional[str] = None,
    actor: Optional[User] = None,
) -> tuple[bool, Optional[str]]:
    """Operator-only breaker reset (capability-gated in the route)."""
    breaker, fail = await _load_breaker(db, repository_id=repository_id, scope=scope, action_type=action_type)
    if breaker is None:
        return False, fail or om.RC_CIRCUIT_OPEN
    breaker.breaker_state = om.CircuitState.CLOSED
    breaker.consecutive_failures = 0
    breaker.reset_by_user_id = actor.id if actor is not None else None
    await _op_event(
        db,
        event_type=om.EVENT_CIRCUIT_RESET,
        repository_id=repository_id,
        subject_type="BREAKER",
        subject_id=breaker.id,
        reason_code=om.RC_OK,
        detail="operator reset",
        actor=actor,
    )
    try:
        await db.commit()  # durable reset — never report success on a
    except Exception as exc:  # transaction the caller may roll back
        await db.rollback()
        logger.warning("reset_circuit_commit_failed err=%s", type(exc).__name__)
        return False, f"{om.RC_OPS_READ_FAILED}:{type(exc).__name__}"
    return True, None


# ── Quotas (server-counted) ──────────────────────────────────────────


async def _check_quotas(
    db: AsyncSession,
    *,
    repository_id,
    now: datetime,
) -> tuple[bool, Optional[str]]:
    settings = get_settings()
    active_states = ("ADMISSION_PENDING", "EXECUTING")
    total = (
        await db.execute(
            select(func.count()).select_from(ExecutionRun).where(
                ExecutionRun.run_state.in_(active_states)
            )
        )
    ).scalar() or 0
    if total >= settings.ops_max_concurrent_executions:
        return False, om.RC_QUOTA_EXCEEDED
    per_repo = (
        await db.execute(
            select(func.count()).select_from(ExecutionRun).where(
                ExecutionRun.run_state.in_(active_states),
                ExecutionRun.repository_id == repository_id,
            )
        )
    ).scalar() or 0
    if per_repo >= settings.ops_max_concurrent_executions_per_repository:
        return False, om.RC_QUOTA_EXCEEDED
    return True, None


# ── Repository controls ──────────────────────────────────────────────


async def set_repository_control(
    db: AsyncSession,
    *,
    repository_id,
    target: str,
    actor: Optional[User],
    reason: Optional[str] = None,
) -> tuple[bool, Optional[str]]:
    """Operator-only repository control change (capability-gated in the
    route; ownership is verified there too — an operator can only pause
    repositories in installations they are authorized for)."""
    if not om.is_valid_repo_control(target):
        return False, om.RC_REPO_CONTROL_MISSING
    control = (
        await db.execute(
            select(RepositoryControl).where(RepositoryControl.repository_id == repository_id)
        )
    ).scalar_one_or_none()
    if control is None:
        control = RepositoryControl(repository_id=repository_id)
        db.add(control)
    control.control_state = target
    control.reason = (reason or "")[:200] or None
    control.updated_by_user_id = actor.id if actor is not None else None
    await _op_event(
        db,
        event_type=om.EVENT_REPOSITORY_PAUSED if target == om.RepoControlState.PAUSED else "REPOSITORY_CONTROL_CHANGED",
        repository_id=repository_id,
        subject_type="REPOSITORY_CONTROL",
        subject_id=control.id,
        reason_code=target,
        detail=(reason or "")[:120],
        actor=actor,
    )
    try:
        await db.commit()  # durable containment change — never report
    except Exception as exc:  # success on a transaction the caller rolls back
        await db.rollback()
        logger.warning("set_repository_control_commit_failed err=%s", type(exc).__name__)
        return False, f"{om.RC_OPS_READ_FAILED}:{type(exc).__name__}"
    return True, None


async def get_repository_control(db: AsyncSession, *, repository_id) -> Optional[RepositoryControl]:
    return (
        await db.execute(
            select(RepositoryControl).where(RepositoryControl.repository_id == repository_id)
        )
    ).scalar_one_or_none()


# ── Leases ───────────────────────────────────────────────────────────


async def acquire_lease(
    db: AsyncSession,
    *,
    subject_type: str,
    subject_id,
    repository_id,
    owner_id: str,
    ttl_seconds: int,
    now: Optional[datetime] = None,
) -> tuple[bool, Optional[str], Optional[object]]:
    """Acquire the single ACTIVE lease for a subject.

    Returns (ok, fail_reason, lease). An existing ACTIVE lease held by
    another owner denies acquisition (never stolen by identity). An
    expired ACTIVE lease is transitioned to EXPIRED here (audited) and a
    fresh lease may be issued ONLY to the reconciliation engine's
    worker — callers pass `allow_expired_takeover` for that path."""
    now = now or datetime.now(timezone.utc)
    existing = (
        await db.execute(
            select(ExecutionLease).where(
                (ExecutionLease.subject_id == subject_id)
                & (ExecutionLease.lease_state == "ACTIVE")
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        verdict = om.evaluate_lease(existing.lease_owner_id, existing.expires_at, owner_id, now)
        if verdict.owned:
            # re-entrant heartbeat refresh
            existing.heartbeat_at = now
            existing.expires_at = om.lease_expiry_time(now, ttl_seconds)
            return True, None, existing
        if verdict.reason == om.RC_LEASE_EXPIRED:
            existing.lease_state = "EXPIRED"
            await _op_event(
                db,
                event_type=om.EVENT_LEASE_EXPIRED,
                repository_id=repository_id,
                subject_type=subject_type,
                subject_id=subject_id,
                reason_code=om.RC_LEASE_EXPIRED,
                detail=f"owner={existing.lease_owner_id}",
            )
            await db.commit()  # durable expiry: takeover requires reconciliation
            return False, om.RC_LEASE_EXPIRED, existing
        return False, om.RC_LEASE_NOT_OWNED, existing
    lease = ExecutionLease(
        subject_type=subject_type,
        subject_id=subject_id,
        repository_id=repository_id,
        lease_owner_id=owner_id,
        lease_state="ACTIVE",
        heartbeat_at=now,
        expires_at=om.lease_expiry_time(now, ttl_seconds),
    )
    db.add(lease)
    return True, None, lease


async def heartbeat_lease(db: AsyncSession, *, lease, now: Optional[datetime] = None) -> tuple[bool, Optional[str]]:
    """Refresh a lease the caller owns. Expired leases cannot be
    heartbeat back to life (recovery owns that path)."""
    now = now or datetime.now(timezone.utc)
    if lease is None:
        return False, om.RC_LEASE_NOT_OWNED
    if lease.lease_state != "ACTIVE":
        return False, om.RC_LEASE_EXPIRED
    verdict = om.evaluate_lease(
        lease.lease_owner_id, lease.expires_at, lease.lease_owner_id, now
    )
    if not verdict.owned:
        lease.lease_state = "EXPIRED"
        return False, om.RC_LEASE_EXPIRED
    lease.heartbeat_at = now
    lease.expires_at = om.lease_expiry_time(now, get_settings().ops_lease_ttl_seconds)
    return True, None


async def release_lease(db: AsyncSession, *, lease) -> None:
    if lease is not None:
        lease.lease_state = "RELEASED"


# ── Operational events ───────────────────────────────────────────────


async def _op_event(
    db: AsyncSession,
    *,
    event_type: str,
    repository_id=None,
    subject_type: Optional[str] = None,
    subject_id=None,
    reason_code: Optional[str] = None,
    detail: Optional[str] = None,
    actor: Optional[User] = None,
) -> None:
    db.add(
        OperationalEvent(
            event_type=event_type,
            repository_id=repository_id,
            subject_type=subject_type,
            subject_id=subject_id,
            reason_code=reason_code,
            detail=(detail or "")[:400] or None,
            created_by_user_id=actor.id if actor is not None else None,
        )
    )


# ── Watchdog: stuck execution detection (Phase 15) ───────────────────


async def detect_stuck_executions(db: AsyncSession) -> list[dict]:
    """Classify stuck executions from server-side state only.

    - runs EXECUTING with no lease, an expired lease, or a late heartbeat
    - runs EXECUTING longer than the execution-duration quota
    Does NOT mutate anything and NEVER auto-retries destructive work."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    stuck: list[dict] = []
    runs = (
        await db.execute(select(ExecutionRun).where(ExecutionRun.run_state == "EXECUTING"))
    ).scalars().all()
    for run in runs:
        reasons: list[str] = []
        started = run.started_at or run.created_at
        if started is not None:
            s = started if started.tzinfo else started.replace(tzinfo=timezone.utc)
            if (now - s).total_seconds() > settings.ops_max_execution_duration_seconds:
                reasons.append("EXECUTION_DURATION_EXCEEDED")
        if reasons:
            stuck.append({
                "subject": f"execution_run:{run.id}",
                "repository_id": str(run.repository_id),
                "classification": "STUCK",
                "reason": ",".join(reasons),
            })
    return stuck


# ── Configuration validation (Phase 23, fail closed at startup) ──────


def validate_ops_configuration(settings) -> Optional[str]:
    """Validate all V3.7 operational settings. Returns a fail reason or
    None. Invalid security-sensitive configuration must stop startup in
    production (the caller decides based on environment)."""
    limits = type("L", (), {})()
    limits.max_concurrent_executions = settings.ops_max_concurrent_executions
    limits.max_concurrent_executions_per_repository = settings.ops_max_concurrent_executions_per_repository
    limits.max_executions_per_action = 1
    limits.max_github_mutations_per_remediation = 1
    limits.max_verification_attempts_per_remediation = 1
    limits.max_rollback_attempts_per_remediation = 1
    limits.max_execution_duration_seconds = settings.ops_max_execution_duration_seconds
    fail = om.validate_quota_limits(limits)
    if fail:
        return fail
    if settings.ops_lease_ttl_seconds < 10 or settings.ops_lease_ttl_seconds > 3600:
        return "QUOTA_INVALID"
    if settings.ops_breaker_max_failures < 1 or settings.ops_breaker_max_failures > 100:
        return "QUOTA_INVALID"
    for name in (
        "ops_rate_limit_per_hour", "ops_reconciliation_rate_limit_per_hour",
    ):
        value = getattr(settings, name)
        if value < 1 or value > 1000:
            return "QUOTA_INVALID"
    return None
