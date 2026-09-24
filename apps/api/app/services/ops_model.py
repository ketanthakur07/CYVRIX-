"""CYVRIX V3.7 — Operational controls domain model.

Pure, side-effect-free primitives for the operational control plane:
- Operational state (system-wide execution control): NORMAL | PAUSED |
  DRAINING | EMERGENCY_STOP with the exact transition graph
- Repository controls: ENABLED | PAUSED | BLOCKED (tenant-owned)
- Circuit breaker model: bounded consecutive failures → OPEN (operator
  reset only); unknown/unprovisioned breaker state fails closed
- Execution leases: ownership/expiry/heartbeat semantics (pure helpers
  only — the DB rows live in execution_leases)
- Quota evaluation: pure limit checks (counting happens in ops_service)
- Cancellation semantics: explicit per-state decision table

Security properties (docs/v3-operational-controls.md):
- No I/O of any kind: no DB, no network, no filesystem, no subprocess
- Unknown states always fail closed (an unparseable value is treated as
  EMERGENCY_STOP-equivalent, never as "allowed")
- The transition graph is total: any transition not listed is refused
- Emergency stop is a one-way door: EMERGENCY_STOP → NORMAL does not
  exist; recovery requires an explicit reconciled resume (PAUSED) that
  the operator performs AFTER reconciliation reports consistent state
- Quotas can only be lowered by configuration, never raised by clients;
  client input can never select or mutate any control here
- This module must NEVER import services that perform side effects
"""

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

# ── Versions ─────────────────────────────────────────────────────────

OPS_MODEL_VERSION = "1"

# ── Reason codes (stable, machine-readable) ──────────────────────────

RC_OK = "OK"
RC_OPS_STATE_MISSING = "OPS_STATE_MISSING"
RC_OPS_STATE_UNPARSEABLE = "OPS_STATE_UNPARSEABLE"
RC_OPS_READ_FAILED = "OPS_READ_FAILED"
RC_OPS_TRANSITION_INVALID = "OPS_TRANSITION_INVALID"
RC_SYSTEM_PAUSED = "SYSTEM_PAUSED"
RC_SYSTEM_DRAINING = "SYSTEM_DRAINING"
RC_EMERGENCY_STOP = "EMERGENCY_STOP"
RC_REPO_NOT_FOUND = "REPO_NOT_FOUND"
RC_REPO_PAUSED = "REPOSITORY_PAUSED"
RC_REPO_BLOCKED = "REPOSITORY_BLOCKED"
RC_REPO_CONTROL_MISSING = "REPO_CONTROL_MISSING"
RC_CIRCUIT_OPEN = "CIRCUIT_OPEN"
RC_QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
RC_QUOTA_INVALID = "QUOTA_INVALID"
RC_LEASE_NOT_OWNED = "LEASE_NOT_OWNED"
RC_LEASE_EXPIRED = "LEASE_EXPIRED"
RC_CANCEL_NOT_REQUESTED = "CANCEL_NOT_REQUESTED"
RC_CANCEL_REQUESTED = "CANCEL_REQUESTED"
RC_CANCEL_NOT_CANCELLABLE = "CANCEL_NOT_CANCELLABLE"
RC_RATE_LIMITED = "RATE_LIMITED"
RC_FORBIDDEN = "FORBIDDEN"
RC_STEP_UP_REQUIRED = "STEP_UP_REQUIRED"

# ── Operational states ───────────────────────────────────────────────


class OpsState:
    NORMAL = "NORMAL"
    PAUSED = "PAUSED"
    DRAINING = "DRAINING"
    EMERGENCY_STOP = "EMERGENCY_STOP"


ALL_OPS_STATES = (
    OpsState.NORMAL,
    OpsState.PAUSED,
    OpsState.DRAINING,
    OpsState.EMERGENCY_STOP,
)

# Semantics (docs/v3-operational-controls.md §states):
# - NORMAL:         all pipelines may start new work
# - PAUSED:         no NEW mutations/execution; in-flight work continues;
#                   reconciliation and read-only ops are allowed
# - DRAINING:       like PAUSED, plus in-flight pipelines are asked to
#                   stop at their NEXT stage boundary (cooperative only)
# - EMERGENCY_STOP: everything PAUSED blocks, plus: no new GitHub
#                   credential issuance, no rollback initiation, no
#                   resume without operator reconciliation; in-flight
#                   processes are NOT magically killed (documented truth)

# The exact transition graph. Anything not listed here is refused.
ALLOWED_TRANSITIONS: dict[str, frozenset] = {
    OpsState.NORMAL: frozenset({OpsState.PAUSED, OpsState.DRAINING, OpsState.EMERGENCY_STOP}),
    OpsState.PAUSED: frozenset({OpsState.NORMAL, OpsState.EMERGENCY_STOP}),
    OpsState.DRAINING: frozenset({OpsState.PAUSED, OpsState.EMERGENCY_STOP}),
    OpsState.EMERGENCY_STOP: frozenset({OpsState.PAUSED}),  # via reconciled resume only
}


def is_valid_ops_state(value: object) -> bool:
    return isinstance(value, str) and value in ALL_OPS_STATES


def can_transition(current: str, target: str) -> bool:
    """True only for transitions present in the graph. Unknown states
    (either side) always return False — fail closed."""
    if not is_valid_ops_state(current) or not is_valid_ops_state(target):
        return False
    return target in ALLOWED_TRANSITIONS.get(current, frozenset())


def execution_allowed(state: str) -> bool:
    """May a NEW execution/mutation start under this state?

    Unknown/invalid states are fail-closed (False)."""
    return state == OpsState.NORMAL


def credential_issuance_allowed(state: str) -> bool:
    """May a NEW GitHub credential be issued under this state?

    EMERGENCY_STOP forbids issuance outright. PAUSED/DRAINING also
    forbid it (no new external mutations while paused). Unknown → False."""
    return state == OpsState.NORMAL


def rollback_initiation_allowed(state: str) -> bool:
    """May a NEW rollback be initiated under this state?

    Rollback is a GitHub mutation, so PAUSED/DRAINING/EMERGENCY_STOP all
    block NEW rollbacks. (An already-running rollback is reconciled, not
    abandoned.) Unknown → False."""
    return state == OpsState.NORMAL


# ── The system_controls key + parsing ────────────────────────────────

OPS_STATE_KEY = "operational_state"


def parse_ops_state(raw: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Parse a stored operational_state value.

    Returns (state, fail_reason). Fail-closed rules:
    - None / empty / whitespace            → (None, RC_OPS_STATE_MISSING)
    - any unknown or malformed string      → (None, RC_OPS_STATE_UNPARSEABLE)
    Callers MUST treat (None, reason) as EMERGENCY_STOP-equivalent.
    """
    if raw is None:
        return None, RC_OPS_STATE_MISSING
    value = raw.strip()
    if not value:
        return None, RC_OPS_STATE_MISSING
    if not is_valid_ops_state(value):
        return None, RC_OPS_STATE_UNPARSEABLE
    return value, None


# ── Repository controls ──────────────────────────────────────────────


class RepoControlState:
    ENABLED = "ENABLED"
    PAUSED = "PAUSED"
    BLOCKED = "BLOCKED"


ALL_REPO_CONTROL_STATES = (
    RepoControlState.ENABLED,
    RepoControlState.PAUSED,
    RepoControlState.BLOCKED,
)


def is_valid_repo_control(value: object) -> bool:
    return isinstance(value, str) and value in ALL_REPO_CONTROL_STATES


def repo_execution_allowed(control_value: Optional[str]) -> bool:
    """May execution start for this repository? Unknown/missing → False."""
    if not is_valid_repo_control(control_value):
        return False
    return control_value == RepoControlState.ENABLED


def repo_allows_verification(control_value: Optional[str]) -> bool:
    """Verification is read-only regarding the repository; it is allowed
    under ENABLED and PAUSED (containment without losing evidence), but
    not BLOCKED or an unknown value."""
    return is_valid_repo_control(control_value) and control_value in (
        RepoControlState.ENABLED,
        RepoControlState.PAUSED,
    )


# ── Circuit breaker ──────────────────────────────────────────────────


class CircuitState:
    CLOSED = "CLOSED"
    OPEN = "OPEN"


MAX_CONSECUTIVE_FAILURES_DEFAULT = 3


@dataclass(frozen=True)
class CircuitEvaluation:
    allowed: bool
    state: str
    reason: Optional[str]
    consecutive_failures: int


def evaluate_circuit(
    state_value: Optional[str],
    consecutive_failures: int,
    *,
    max_consecutive_failures: int = MAX_CONSECUTIVE_FAILURES_DEFAULT,
) -> CircuitEvaluation:
    """Pure breaker decision.

    - Unknown state value → fail closed (OPEN-equivalent).
    - OPEN → never allowed (operator reset is the only exit).
    - CLOSED with failures ≥ limit → the caller must OPEN it; this call
      denies execution for the transition (fail closed at the boundary).
    """
    if not isinstance(consecutive_failures, int) or consecutive_failures < 0:
        return CircuitEvaluation(False, CircuitState.OPEN, RC_CIRCUIT_OPEN, 0)
    if state_value == CircuitState.OPEN:
        return CircuitEvaluation(False, CircuitState.OPEN, RC_CIRCUIT_OPEN, consecutive_failures)
    if state_value != CircuitState.CLOSED:
        # Unprovisioned/unknown → fail closed
        return CircuitEvaluation(False, CircuitState.OPEN, RC_CIRCUIT_OPEN, consecutive_failures)
    if consecutive_failures >= max_consecutive_failures:
        return CircuitEvaluation(False, CircuitState.OPEN, RC_CIRCUIT_OPEN, consecutive_failures)
    return CircuitEvaluation(True, CircuitState.CLOSED, None, consecutive_failures)


# ── Leases ───────────────────────────────────────────────────────────


class LeaseState:
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    RELEASED = "RELEASED"


@dataclass(frozen=True)
class LeaseVerdict:
    owned: bool
    reason: Optional[str]  # RC_OK | RC_LEASE_NOT_OWNED | RC_LEASE_EXPIRED


def evaluate_lease(
    lease_owner_id: Optional[str],
    lease_expires_at: Optional[datetime],
    worker_id: str,
    now: datetime,
) -> LeaseVerdict:
    """Pure lease-ownership decision.

    Priority: expiry is evaluated FIRST so an expired lease is always
    reported LEASE_EXPIRED (reconciliation signal) regardless of which
    worker asks — takeover still requires the reconciliation engine.

    - missing lease data  → fail closed (NOT_OWNED)
    - expired             → LEASE_EXPIRED (any asker)
    - owner mismatch      → NOT_OWNED (never stealable by identity)
    - owner + not expired → owned
    """
    if not lease_owner_id or lease_expires_at is None:
        return LeaseVerdict(False, RC_LEASE_NOT_OWNED)
    exp = lease_expires_at if lease_expires_at.tzinfo else lease_expires_at.replace(tzinfo=timezone.utc)
    n = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    if n >= exp:
        return LeaseVerdict(False, RC_LEASE_EXPIRED)
    if lease_owner_id != worker_id:
        return LeaseVerdict(False, RC_LEASE_NOT_OWNED)
    return LeaseVerdict(True, None)


def lease_expiry_time(started_at: datetime, ttl_seconds: int) -> datetime:
    s = started_at if started_at.tzinfo else started_at.replace(tzinfo=timezone.utc)
    return s + timedelta(seconds=max(1, int(ttl_seconds)))


def heartbeat_is_late(
    last_heartbeat_at: Optional[datetime],
    now: datetime,
    ttl_seconds: int,
) -> bool:
    if last_heartbeat_at is None:
        return True
    hb = last_heartbeat_at if last_heartbeat_at.tzinfo else last_heartbeat_at.replace(tzinfo=timezone.utc)
    n = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    return (n - hb).total_seconds() > ttl_seconds


# ── Quotas (pure limit checks) ───────────────────────────────────────


@dataclass(frozen=True)
class QuotaLimits:
    max_concurrent_executions: int = 5
    max_concurrent_executions_per_repository: int = 2
    max_executions_per_action: int = 1
    max_github_mutations_per_remediation: int = 1
    max_verification_attempts_per_remediation: int = 1
    max_rollback_attempts_per_remediation: int = 1
    max_execution_duration_seconds: int = 900


DEFAULT_QUOTA_LIMITS = QuotaLimits()


def validate_quota_limits(
    limits: QuotaLimits,
) -> Optional[str]:
    """Configuration validation. Returns a fail reason or None.

    Rejects negative, zero, or absurd values; no infinite settings exist
    by design (there is no representation for 'unlimited')."""
    checks = (
        (limits.max_concurrent_executions, 1, 10_000),
        (limits.max_concurrent_executions_per_repository, 1, 1_000),
        (limits.max_executions_per_action, 1, 100),
        (limits.max_github_mutations_per_remediation, 1, 100),
        (limits.max_verification_attempts_per_remediation, 1, 100),
        (limits.max_rollback_attempts_per_remediation, 1, 100),
        (limits.max_execution_duration_seconds, 1, 86_400),
    )
    for value, low, high in checks:
        if not isinstance(value, int) or value < low or value > high:
            return RC_QUOTA_INVALID
    return None


def quota_allows(count: int, limit: int) -> bool:
    """Pure quota comparison. Negative counts fail closed."""
    if not isinstance(count, int) or count < 0:
        return False
    return count < limit


# ── Cancellation semantics ───────────────────────────────────────────
#
# Per-state decision table (Phase 13): what does CANCEL_REQUESTED mean?
#
# remediation_state    cancellation
# -------------------  ------------------------------------------------
# PENDING/VERIFYING    IMMEDIATE_SAFE: no external effect yet; the
#                      pipeline checks the flag at each stage boundary
#                      and stops without side effects.
# COMMITTING/COMMITTED COOPERATIVE: stop before PUSH; a local commit
#                      remains local (no remote mutation to reconcile).
# PUSHING              NOT_IMMEDIATE: the push may be in flight; the
#                      pipeline cannot abort a network call already
#                      sent. Cancellation is REQUESTED; the outcome is
#                      determined by reconciliation (PUSHED/NOT_PUSHED).
# PUSHED/PR_CREATING   REQUIRES_RECONCILIATION: the branch already
#                      exists remotely; cancellation stops PR creation
#                      but the pushed branch must be reconciled/reported.
# PR_CREATED           IMPOSSIBLE for the mutation itself (already
#                      external + verified). Only an operator-visible
#                      note is recorded; rollback is the counter-action.
# terminal states      NOT_CANCELLABLE.

CANCEL_IMMEDIATE_SAFE = "IMMEDIATE_SAFE"
CANCEL_COOPERATIVE = "COOPERATIVE"
CANCEL_NOT_IMMEDIATE = "NOT_IMMEDIATE"
CANCEL_REQUIRES_RECONCILIATION = "REQUIRES_RECONCILIATION"
CANCEL_IMPOSSIBLE = "IMPOSSIBLE"
CANCEL_NOT_CANCELLABLE = "NOT_CANCELLABLE"


def cancellation_semantics(remediation_state: Optional[str]) -> str:
    """Map a remediation state to its honest cancellation semantics."""
    if not isinstance(remediation_state, str) or not remediation_state:
        return CANCEL_NOT_CANCELLABLE
    if remediation_state in ("PENDING", "VERIFYING"):
        return CANCEL_IMMEDIATE_SAFE
    if remediation_state in ("COMMITTING", "COMMITTED"):
        return CANCEL_COOPERATIVE
    if remediation_state == "PUSHING":
        return CANCEL_NOT_IMMEDIATE
    if remediation_state in ("PUSHED", "PR_CREATING"):
        return CANCEL_REQUIRES_RECONCILIATION
    return CANCEL_NOT_CANCELLABLE


# ── Failure classification (Phase 17) ────────────────────────────────
#
# TRANSIENT:        safe to retry later with backoff, via reconciliation
# NON_TRANSIENT:    never retried automatically (security denials etc.)

TRANSIENT = "TRANSIENT"
NON_TRANSIENT = "NON_TRANSIENT"

_NON_TRANSIENT_CODES = frozenset({
    # Security denials are never retried
    "KILL_SWITCH_ACTIVE", "EMERGENCY_STOP", "SYSTEM_PAUSED", "SYSTEM_DRAINING",
    "REPOSITORY_BLOCKED", "REPOSITORY_PAUSED", "CIRCUIT_OPEN",
    "ACTION_DIGEST_MISMATCH", "APPROVAL_DIGEST_MISMATCH",
    "CONTRACT_DIGEST_MISMATCH", "PLAN_DIGEST_MISMATCH",
    "BASE_COMMIT_MISMATCH", "REMOTE_STATE_MISMATCH", "REMOTE_MISMATCH",
    "ACTION_SCOPE_VIOLATION", "SCOPE_MISMATCH", "SCOPE_NOT_VERIFIED",
    "SECRET_DETECTED", "SANDBOX_ESCAPE_ATTEMPT", "NETWORK_VIOLATION",
    "FILESYSTEM_VIOLATION", "PROTECTED_PATH", "UNEXPECTED_FILE_CHANGE",
    "UNEXPECTED_BINARY", "UNEXPECTED_SYMLINK", "UNEXPECTED_PERMISSION",
    "FORCE_PUSH_PROHIBITED", "DEFAULT_BRANCH_PROHIBITED",
    "AUTHORIZATION_REPLAY", "TOKEN_REPLAY", "TOKEN_INVALID",
    "APPROVAL_EXPIRED", "APPROVAL_REVOKED", "APPROVAL_CONSUMED",
    "AUTHORIZATION_EXPIRED", "AUTHORIZATION_REVOKED",
    "POLICY_DENIED", "VERIFICATION_REPLAY", "ROLLBACK_REPLAY",
    "EXECUTION_REPLAY", "GITHUB_STATE_MISMATCH",
    # Repository identity problems are not transient
    "REPOSITORY_MISMATCH", "RUN_NOT_FOUND", "AUTHORIZATION_NOT_FOUND",
})


def classify_failure(reason_code: Optional[str]) -> str:
    """Classify a failure for retry policy. Unknown codes are treated as
    TRANSIENT only if clearly infra-shaped; anything ambiguous is
    NON_TRANSIENT (fail closed for retries)."""
    if not isinstance(reason_code, str) or not reason_code:
        return NON_TRANSIENT
    if reason_code in _NON_TRANSIENT_CODES:
        return NON_TRANSIENT
    # Explicit allowlist of known-transient infra codes
    if reason_code in {
        "GITHUB_TIMEOUT", "GITHUB_UNAVAILABLE", "GITHUB_RATE_LIMITED",
        "REDIS_UNAVAILABLE", "DATABASE_UNAVAILABLE", "GIT_UNAVAILABLE",
        "SANDBOX_UNAVAILABLE", "TIMEOUT", "CONNECTION_RESET",
    }:
        return TRANSIENT
    # Everything else: do NOT retry automatically (fail closed)
    return NON_TRANSIENT


# ── Backoff / jitter (pure computation) ──────────────────────────────

_MAX_BACKOFF_SECONDS = 3600


def backoff_seconds(
    attempt: int,
    *,
    base_seconds: float = 2.0,
    factor: float = 2.0,
    max_seconds: int = _MAX_BACKOFF_SECONDS,
) -> float:
    """Exponential backoff with hard cap (never unbounded). Jitter is
    applied by the scheduler (impure), not here."""
    if not isinstance(attempt, int) or attempt < 1:
        return float(base_seconds)
    delay = float(base_seconds) * (factor ** (attempt - 1))
    return float(min(delay, float(max_seconds), float(_MAX_BACKOFF_SECONDS)))


# ── Operator capabilities (Phase 21, least privilege) ────────────────


class Role:
    USER = "USER"
    OPERATOR = "OPERATOR"
    ADMIN = "ADMIN"


CAP_VIEW_OPERATIONS = "VIEW_OPERATIONS"
CAP_VIEW_AUDIT = "VIEW_AUDIT"
CAP_VERIFY_AUDIT = "VERIFY_AUDIT"
CAP_EXPORT_AUDIT = "EXPORT_AUDIT"
CAP_PAUSE_SYSTEM = "PAUSE_SYSTEM"
CAP_RESUME_SYSTEM = "RESUME_SYSTEM"
CAP_EMERGENCY_STOP = "EMERGENCY_STOP"
CAP_CANCEL_JOB = "CANCEL_JOB"
CAP_RETRY_JOB = "RETRY_JOB"
CAP_RESET_CIRCUIT = "RESET_CIRCUIT"
CAP_VIEW_DIAGNOSTICS = "VIEW_DIAGNOSTICS"
CAP_SET_REPO_CONTROL = "SET_REPO_CONTROL"
CAP_RUN_RECONCILIATION = "RUN_RECONCILIATION"

# Capability matrix. ADMIN implies every OPERATOR capability; OPERATOR
# implies every VIEW capability. There is deliberately no capability
# that bypasses remediation authorization — operators operate the
# platform, they do not authorize remediations.
ROLE_CAPABILITIES: dict[str, frozenset] = {
    Role.USER: frozenset(),
    Role.OPERATOR: frozenset({
        CAP_VIEW_OPERATIONS, CAP_PAUSE_SYSTEM, CAP_RESUME_SYSTEM,
        CAP_EMERGENCY_STOP, CAP_CANCEL_JOB, CAP_RETRY_JOB,
        CAP_RESET_CIRCUIT, CAP_VIEW_DIAGNOSTICS, CAP_SET_REPO_CONTROL,
        CAP_RUN_RECONCILIATION,
    }),
    Role.ADMIN: frozenset({
        CAP_VIEW_OPERATIONS, CAP_PAUSE_SYSTEM, CAP_RESUME_SYSTEM,
        CAP_EMERGENCY_STOP, CAP_CANCEL_JOB, CAP_RETRY_JOB,
        CAP_RESET_CIRCUIT, CAP_VIEW_DIAGNOSTICS, CAP_SET_REPO_CONTROL,
        CAP_RUN_RECONCILIATION,
        # V3.8 audit capabilities: read/verify/export only — there is
        # deliberately NO EDIT_AUDIT/DELETE_AUDIT capability anywhere.
        CAP_VIEW_AUDIT, CAP_VERIFY_AUDIT, CAP_EXPORT_AUDIT,
    }),
}


def role_has_capability(role_value: Optional[str], capability: str) -> bool:
    if not is_valid_role(role_value):
        return False
    return capability in ROLE_CAPABILITIES.get(role_value, frozenset())


_ROLE_PATTERN = re.compile(r"^[A-Z]{4,16}$")


def is_valid_role(value: object) -> bool:
    return isinstance(value, str) and value in (Role.USER, Role.OPERATOR, Role.ADMIN)


# Dangerous operations requiring step-up (Phase 22)
STEP_UP_REQUIRED_CAPABILITIES = frozenset({
    CAP_EMERGENCY_STOP,
    CAP_RESUME_SYSTEM,
    CAP_RESET_CIRCUIT,
})

# ── Audit event names (Phase 47) ─────────────────────────────────────

EVENT_SYSTEM_PAUSED = "SYSTEM_PAUSED"
EVENT_SYSTEM_RESUMED = "SYSTEM_RESUMED"
EVENT_EMERGENCY_STOP = "EMERGENCY_STOP"
EVENT_REPOSITORY_PAUSED = "REPOSITORY_PAUSED"
EVENT_CIRCUIT_OPENED = "CIRCUIT_OPENED"
EVENT_CIRCUIT_RESET = "CIRCUIT_RESET"
EVENT_EXECUTION_CANCEL_REQUESTED = "EXECUTION_CANCEL_REQUESTED"
EVENT_EXECUTION_CANCELLED = "EXECUTION_CANCELLED"
EVENT_JOB_RETRY_REQUESTED = "JOB_RETRY_REQUESTED"
EVENT_JOB_RETRY_EXHAUSTED = "JOB_RETRY_EXHAUSTED"
EVENT_LEASE_EXPIRED = "LEASE_EXPIRED"
EVENT_JOB_RECONCILED = "JOB_RECONCILED"
EVENT_ORPHAN_CLEANUP = "ORPHAN_CLEANUP"
EVENT_QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
EVENT_RATE_LIMITED = "RATE_LIMITED"
EVENT_SECURITY_INCIDENT_MODE = "SECURITY_INCIDENT_MODE"
EVENT_ADMIN_CONFIGURATION_CHANGED = "ADMIN_CONFIGURATION_CHANGED"
