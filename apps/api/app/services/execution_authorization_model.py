"""CYVRIX V3.3 — Execution authorization domain model.

Pure, side-effect-free primitives for the execution-authorization contract:
- Authorization states and the canonical state machine
- The immutable ExecutionAuthorizationContract + its canonical digest
- Reason-code constants (stable, machine-readable taxonomy)

Security properties (docs/v3-execution-authorization.md, ADR-009):
- No I/O of any kind: no DB, no network, no filesystem, no subprocess
- The contract is FROZEN (immutable) and digestable; any change to the
  action, repository, branch, commit, scope, policy, or expiration
  produces a different contract digest
- Unknown states / transitions always fail closed
- This module must NEVER import services that perform side effects
"""
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from app.services.action_digest import generic_canonical_bytes

# ── Contract version ─────────────────────────────────────────────────

CONTRACT_VERSION = "1"

# ── Reason codes (stable, machine-readable — §32) ────────────────────

RC_AUTHORIZATION_NOT_FOUND = "AUTHORIZATION_NOT_FOUND"
RC_ACTION_NOT_FOUND = "ACTION_NOT_FOUND"
RC_APPROVAL_NOT_FOUND = "APPROVAL_NOT_FOUND"
RC_APPROVAL_INVALID = "APPROVAL_INVALID"
RC_APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
RC_APPROVAL_REVOKED = "APPROVAL_REVOKED"
RC_APPROVAL_CONSUMED = "APPROVAL_CONSUMED"
RC_ACTION_EXPIRED = "ACTION_EXPIRED"
RC_ACTION_STALE = "ACTION_STALE"
RC_ACTION_DIGEST_MISMATCH = "ACTION_DIGEST_MISMATCH"
RC_APPROVAL_DIGEST_MISMATCH = "APPROVAL_DIGEST_MISMATCH"
RC_POLICY_DENIED = "POLICY_DENIED"
RC_POLICY_VERSION_STALE = "POLICY_VERSION_STALE"
RC_RISK_CHANGED = "RISK_CHANGED"
RC_RECOMMENDATION_CHANGED = "RECOMMENDATION_CHANGED"
RC_AUTHORIZATION_REPLAY = "AUTHORIZATION_REPLAY"
RC_KILL_SWITCH_ACTIVE = "KILL_SWITCH_ACTIVE"
RC_UNAUTHORIZED_CONSUMER = "UNAUTHORIZED_CONSUMER"
RC_CONTRACT_INVALID = "CONTRACT_INVALID"
RC_CONTRACT_DIGEST_MISMATCH = "CONTRACT_DIGEST_MISMATCH"
RC_NOT_AUTHORIZED = "NOT_AUTHORIZED"
RC_TOKEN_INVALID = "TOKEN_INVALID"
RC_TOKEN_REPLAY = "TOKEN_REPLAY"

# HTTP mapping (§33): 401 unauthenticated; 403 unauthorized; 404
# cross-tenant hiding; 409 stale/digest/replay/policy conflict;
# 422 malformed. Expected security denials never map to 500.

# ── Authorization states ─────────────────────────────────────────────


class AuthorizationState:
    """Explicit authorization states. Values are persisted verbatim.

    DENIED is deliberately NOT a state: a denial creates no record and
    leaves nothing to resurrect — it is an outcome with an audit event.
    """

    AUTHORIZED = "AUTHORIZED"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


ALL_AUTHORIZATION_STATES = frozenset({
    AuthorizationState.AUTHORIZED,
    AuthorizationState.CONSUMED,
    AuthorizationState.EXPIRED,
    AuthorizationState.REVOKED,
})

# Canonical lifecycle (docs/v3-execution-authorization.md §3):
#   AUTHORIZED → CONSUMED
#   AUTHORIZED → EXPIRED
#   AUTHORIZED → REVOKED
# No resurrection: CONSUMED/EXPIRED/REVOKED are terminal and immutable.
ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    AuthorizationState.AUTHORIZED: frozenset({
        AuthorizationState.CONSUMED,
        AuthorizationState.EXPIRED,
        AuthorizationState.REVOKED,
    }),
    AuthorizationState.CONSUMED: frozenset(),
    AuthorizationState.EXPIRED: frozenset(),
    AuthorizationState.REVOKED: frozenset(),
}


class AuthorizationStateError(ValueError):
    """An authorization state transition violates the state machine."""


def can_transition(current: str, new: str) -> bool:
    """Check a state-machine transition. Unknown states are never allowed."""
    if current not in ALL_AUTHORIZATION_STATES or new not in ALL_AUTHORIZATION_STATES:
        return False
    return new in ALLOWED_TRANSITIONS.get(current, frozenset())


def assert_transition(current: str, new: str) -> None:
    """Raise AuthorizationStateError for forbidden transitions."""
    if not can_transition(current, new):
        raise AuthorizationStateError(
            f"authorization state transition {current} -> {new} is not permitted"
        )


def is_terminal(state: str) -> bool:
    """A terminal state allows no outgoing transitions."""
    if state not in ALL_AUTHORIZATION_STATES:
        return True  # unknown → treat as terminal (fail closed)
    return len(ALLOWED_TRANSITIONS[state]) == 0


# ── Execution authorization contract (§27/§28) ───────────────────────

# Fields that constitute the complete machine-readable authorization the
# future executor may rely on. Nothing else enters the contract: no shell
# commands, no executable paths, no credentials, no arbitrary URLs, no
# plaintext secrets, no scripts (§26). The future executor reconstructs
# allowed operations from the authoritative proposal, not from this
# contract — the contract authorizes, it never describes HOW to execute.
CONTRACT_FIELDS = (
    "contract_version",
    "authorization_id",
    "action_proposal_id",
    "approval_id",
    "action_digest",
    "repository_id",
    "base_commit_sha",
    "target_branch",
    "policy_version",
    "policy_decision",
    "allowed_files",
    "allowed_operations",
    "authorized_at",
    "expires_at",
)


@dataclass(frozen=True)
class ExecutionAuthorizationContract:
    """Immutable, typed, bounded, deterministic, digestable, non-executable.

    Binds one-time consumption to exactly: this action, this repository,
    this commit, this branch, this scope, this policy, this expiry.
    """

    contract_version: str
    authorization_id: str
    action_proposal_id: str
    approval_id: str
    action_digest: str
    repository_id: str
    base_commit_sha: str
    target_branch: str
    policy_version: str
    policy_decision: str
    allowed_files: tuple = field(default=())
    allowed_operations: tuple = field(default=())
    authorized_at: str = ""
    expires_at: str = ""

    def to_dict(self) -> dict:
        """Canonical dict (lists sorted where order is semantically
        irrelevant — files yes, operations keep their order)."""
        return {
            "contract_version": self.contract_version,
            "authorization_id": self.authorization_id,
            "action_proposal_id": self.action_proposal_id,
            "approval_id": self.approval_id,
            "action_digest": self.action_digest,
            "repository_id": self.repository_id,
            "base_commit_sha": self.base_commit_sha,
            "target_branch": self.target_branch,
            "policy_version": self.policy_version,
            "policy_decision": self.policy_decision,
            "allowed_files": sorted(self.allowed_files),
            "allowed_operations": list(self.allowed_operations),
            "authorized_at": self.authorized_at,
            "expires_at": self.expires_at,
        }


def compute_contract_digest(contract: ExecutionAuthorizationContract) -> str:
    """SHA-256 over the canonical contract serialization.

    Detects any change to action / repository / branch / commit / scope /
    policy / expiration. Pure function: same contract → same digest.
    """
    return hashlib.sha256(generic_canonical_bytes(contract.to_dict())).hexdigest()


def verify_contract_digest(contract: ExecutionAuthorizationContract, expected: str) -> bool:
    """Constant-time-enough comparison (digest equality); mismatch denies."""
    if not expected:
        return False
    return compute_contract_digest(contract) == expected


# ── Time helpers (server UTC only — §41) ─────────────────────────────


def _as_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def is_expired(expires_at: Optional[datetime], now: datetime) -> bool:
    """True when now is at or past expires_at. Missing expiry = expired
    (fail closed: no unbounded authorization). Boundary semantics: the
    instant expires_at itself is already expired (now >= expires_at)."""
    exp = _as_utc(expires_at)
    if exp is None:
        return True
    n = _as_utc(now)
    return n >= exp


def authorization_window_expired(approval_expires_at: Optional[datetime], now: datetime) -> bool:
    """The authorization window is exactly the approval window. There is
    no independent authorization TTL to keep the two from drifting."""
    return is_expired(approval_expires_at, now)
