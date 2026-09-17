"""CYVRIX V3.4 — Execution run domain model.

Pure, side-effect-free primitives for the sandboxed execution engine:
- Execution-run states and the canonical state machine (§6)
- The single V3.4 execution profile + frozen resource limits (§26/§38)
- Action-type → profile binding (§39; server-derived, unknown = deny)
- Bounded execution results and the result/diff digest (§48/§93/§94)
- Stable security error taxonomy (§104)

Security properties:
- No I/O of any kind: no DB, no network, no filesystem, no subprocess
- Unknown states / operations / profiles always fail closed
- Results are bounded and contain no secrets, no workspace content,
  no executable material — metadata only
- This module must NEVER import services that perform side effects
"""
import hashlib
from dataclasses import dataclass, field
from typing import Optional

from app.services.action_digest import generic_canonical_bytes

# ── Reason codes (§104 — stable, machine-readable) ───────────────────

RC_SANDBOX_UNAVAILABLE = "SANDBOX_UNAVAILABLE"
RC_SANDBOX_POLICY_UNSUPPORTED = "SANDBOX_POLICY_UNSUPPORTED"
RC_AUTHORIZATION_INVALID = "AUTHORIZATION_INVALID"
RC_AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
RC_AUTHORIZATION_REVOKED = "AUTHORIZATION_REVOKED"
RC_AUTHORIZATION_NOT_FOUND = "AUTHORIZATION_NOT_FOUND"
RC_CONTRACT_DIGEST_MISMATCH = "CONTRACT_DIGEST_MISMATCH"
RC_ACTION_DIGEST_MISMATCH = "ACTION_DIGEST_MISMATCH"
RC_ACTION_SCOPE_VIOLATION = "ACTION_SCOPE_VIOLATION"
RC_PROTECTED_PATH = "PROTECTED_PATH"
RC_RESOURCE_LIMIT = "RESOURCE_LIMIT"
RC_EXECUTION_TIMEOUT = "EXECUTION_TIMEOUT"
RC_EXECUTION_CANCELLED = "EXECUTION_CANCELLED"
RC_SANDBOX_ESCAPE_ATTEMPT = "SANDBOX_ESCAPE_ATTEMPT"
RC_NETWORK_VIOLATION = "NETWORK_VIOLATION"
RC_FILESYSTEM_VIOLATION = "FILESYSTEM_VIOLATION"
RC_CLEANUP_FAILED = "CLEANUP_FAILED"
RC_EXECUTION_IN_PROGRESS = "EXECUTION_IN_PROGRESS"
RC_EXECUTION_REPLAY = "EXECUTION_REPLAY"
RC_KILL_SWITCH_ACTIVE = "KILL_SWITCH_ACTIVE"
RC_RUNTIME_UNSUPPORTED = "RUNTIME_UNSUPPORTED"
RC_KILL_SWITCH_UNPROVISIONED = "KILL_SWITCH_UNPROVISIONED"
RC_OPERATION_UNSUPPORTED = "OPERATION_UNSUPPORTED"
RC_OPERATION_FAILED = "OPERATION_FAILED"
RC_UNEXPECTED_FILE_CHANGE = "UNEXPECTED_FILE_CHANGE"
RC_CROSS_TENANT = "CROSS_TENANT"
RC_OK = "OK"

# HTTP mapping (consistent with V3.3 §33): 404 cross-tenant hiding;
# 409 stale/conflict (in progress, replay, contract mismatch, kill
# switch); 403 unauthorized; 503 sandbox/runtime unavailability. Expected
# security denials never map to 500.

# ── Execution-run states (§6) ────────────────────────────────────────


class ExecutionRunState:
    """Explicit run states. Values are persisted verbatim.

    Lifecycle:
        ADMISSION_PENDING → EXECUTING → RESULT_READY → COMPLETED
                                     ↘ FAILED (any stage)
        RESULT_READY → CLEANUP_FAILED (success whose teardown failed —
                       never reported as clean success, §61)
    DENIED is not a state: denials create no run record. VERIFIED does
    not exist (V3.6); COMPLETED means "sandbox executed the approved
    structured operations and teardown succeeded" and nothing more.
    """

    ADMISSION_PENDING = "ADMISSION_PENDING"
    EXECUTING = "EXECUTING"
    RESULT_READY = "RESULT_READY"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CLEANUP_FAILED = "CLEANUP_FAILED"


ALL_RUN_STATES = frozenset({
    ExecutionRunState.ADMISSION_PENDING,
    ExecutionRunState.EXECUTING,
    ExecutionRunState.RESULT_READY,
    ExecutionRunState.COMPLETED,
    ExecutionRunState.FAILED,
    ExecutionRunState.CLEANUP_FAILED,
})

ALLOWED_RUN_TRANSITIONS: dict[str, frozenset[str]] = {
    ExecutionRunState.ADMISSION_PENDING: frozenset({
        ExecutionRunState.EXECUTING,
        ExecutionRunState.FAILED,
    }),
    ExecutionRunState.EXECUTING: frozenset({
        ExecutionRunState.RESULT_READY,
        ExecutionRunState.FAILED,
    }),
    ExecutionRunState.RESULT_READY: frozenset({
        ExecutionRunState.COMPLETED,
        ExecutionRunState.FAILED,
        ExecutionRunState.CLEANUP_FAILED,
    }),
    ExecutionRunState.COMPLETED: frozenset(),
    ExecutionRunState.FAILED: frozenset(),
    ExecutionRunState.CLEANUP_FAILED: frozenset(),
}


class ExecutionRunStateError(ValueError):
    """An execution-run state transition violates the state machine."""


def can_transition_run(current: str, new: str) -> bool:
    if current not in ALL_RUN_STATES or new not in ALL_RUN_STATES:
        return False
    return new in ALLOWED_RUN_TRANSITIONS.get(current, frozenset())


def assert_transition_run(current: str, new: str) -> None:
    if not can_transition_run(current, new):
        raise ExecutionRunStateError(
            f"execution run state transition {current} -> {new} is not permitted"
        )


def is_terminal_run(state: str) -> bool:
    if state not in ALL_RUN_STATES:
        return True  # unknown → terminal (fail closed)
    return len(ALLOWED_RUN_TRANSITIONS[state]) == 0


# Cleanup status is tracked separately from the run state so a FAILED run
# still records whether its sandbox teardown succeeded (§33/§103).
CLEANUP_NOT_STARTED = "NOT_STARTED"
CLEANUP_COMPLETED = "COMPLETED"
CLEANUP_FAILED = "FAILED"

# ── Execution profile (§38/§39 — one minimal profile in V3.4) ────────

PROFILE_STRUCTURED_TEXT = "PROFILE_STRUCTURED_TEXT"

# Frozen resource limits (§26). No soft/unlimited defaults.
RESOURCE_LIMITS = {
    "execution_timeout_seconds": 60,
    "memory_mb": 256,
    "cpu_period_us": 100_000,
    "cpu_quota_us": 50_000,      # 0.5 CPU
    "pids_limit": 32,            # fork-bomb bound
    "output_limit_bytes": 65_536,
    "workspace_disk_mb": 64,
}

# Every V3.1 action type maps to exactly this profile. Unknown action
# types map to nothing → deny. The client can never choose a profile.
ACTION_TYPE_TO_PROFILE: dict[str, str] = {
    "DEPENDENCY_UPGRADE": PROFILE_STRUCTURED_TEXT,
    "DOCKERFILE_UPDATE": PROFILE_STRUCTURED_TEXT,
    "CONFIGURATION_UPDATE": PROFILE_STRUCTURED_TEXT,
    "DOCUMENTED_SECURITY_FIX": PROFILE_STRUCTURED_TEXT,
}


def profile_for_action_type(action_type: object) -> Optional[str]:
    """Server-derived profile binding. Unknown → None (deny)."""
    if not isinstance(action_type, str):
        return None
    return ACTION_TYPE_TO_PROFILE.get(action_type)


# ── Bounded execution results (§48/§93) ──────────────────────────────


@dataclass(frozen=True)
class OperationOutcome:
    """Per-operation result. No file content, no secrets, bounded."""

    index: int
    op_type: str
    file_path: str
    applied: bool
    detail: str = ""  # bounded, non-secret reason/detail


@dataclass(frozen=True)
class ExecutorResult:
    """Structured result produced by the in-sandbox executor.

    The HOST owns the final status (§53): the sandbox returns raw
    bounded data, the host-side service decides COMPLETED/FAILED.
    """

    ok: bool
    reason_code: str
    operations: tuple = field(default=())      # tuple[OperationOutcome]
    files_read_count: int = 0
    stdout_bytes: int = 0                      # metadata, not content
    truncated: bool = False
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "reason_code": self.reason_code,
            "operations": [
                {
                    "index": o.index,
                    "op_type": o.op_type,
                    "file_path": o.file_path,
                    "applied": o.applied,
                    "detail": o.detail[:500],
                }
                for o in self.operations
            ],
            "files_read_count": self.files_read_count,
            "stdout_bytes": self.stdout_bytes,
            "truncated": self.truncated,
            "detail": self.detail[:1000],
        }

    @staticmethod
    def from_dict(d: dict) -> "ExecutorResult":
        ops = tuple(
            OperationOutcome(
                index=int(o.get("index", -1)),
                op_type=str(o.get("op_type", "")),
                file_path=str(o.get("file_path", "")),
                applied=bool(o.get("applied", False)),
                detail=str(o.get("detail", "")),
            )
            for o in (d.get("operations") or ())
        )
        return ExecutorResult(
            ok=bool(d.get("ok", False)),
            reason_code=str(d.get("reason_code", "")),
            operations=ops,
            files_read_count=int(d.get("files_read_count", 0)),
            stdout_bytes=int(d.get("stdout_bytes", 0)),
            truncated=bool(d.get("truncated", False)),
            detail=str(d.get("detail", "")),
        )


# ── Result / diff digest (§94 — distinct from the action digest) ─────


def compute_diff_digest(change_set: dict) -> str:
    """Deterministic SHA-256 over the resulting change set.

    change_set: {path: {"before_sha256": str|None, "after_sha256": str|None}}
    Canonical JSON → digest. Pure. Later phases (V3.6/V3.7) consume this
    to verify and roll back; it is NOT the action digest.
    """
    canonical = {
        "change_set_version": "1",
        "files": {
            str(path): {
                "before_sha256": change.get("before_sha256"),
                "after_sha256": change.get("after_sha256"),
            }
            for path, change in sorted(change_set.items(), key=lambda kv: str(kv[0]))
        },
    }
    return hashlib.sha256(generic_canonical_bytes(canonical)).hexdigest()
