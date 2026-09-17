"""CYVRIX V3.2 — Approval domain model.

Pure, side-effect-free primitives for the human approval workflow:
- Approval states and the canonical state machine
- Approver eligibility (risk-level dependent, second-principal rule)
- One-time authorization token generation, hashing, and verification
- Approval reason validation

Security properties (docs/v3-approval-model.md, security-model §6):
- No I/O of any kind: no DB, no network, no filesystem, no subprocess
- Token material is cryptographically random; only a keyed hash is stored
- Unknown states / transitions always fail closed
- This module must NEVER import services that perform side effects
"""
import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone

# ── Constants (docs/v3-security-model.md §6/§8) ─────────────────────

APPROVAL_TTL_MINUTES = 60          # approved authorizations live 1 hour
MAX_REASON_LENGTH = 2000
STEP_UP_SESSION_MAX_AGE_MINUTES = 15   # a step-up round-trip is valid 15 min

# Risk levels that require a second principal (security-model §6)
SECOND_PRINCIPAL_RISK_LEVELS = frozenset({"HIGH", "CRITICAL"})

_STEP_UP_AGE = re.compile(r"^[0-9]{1,10}$")

_TOKEN_PREFIX = "cyv1"
_TOKEN_SECRET_INFO = b"cyvrix.approval.token.v1"


class ApprovalStateError(ValueError):
    """An approval state transition violates the state machine."""


# ── Approval states ──────────────────────────────────────────────────


class ApprovalState:
    """Explicit approval states. Values are persisted verbatim."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    USED = "USED"


ALL_APPROVAL_STATES = frozenset({
    ApprovalState.PENDING,
    ApprovalState.APPROVED,
    ApprovalState.REJECTED,
    ApprovalState.EXPIRED,
    ApprovalState.REVOKED,
    ApprovalState.USED,
})

# Canonical lifecycle (docs/v3-approval-model.md §2):
#   PENDING → APPROVED → USED
#   PENDING → REJECTED
#   PENDING → EXPIRED
#   APPROVED → REVOKED
#   APPROVED → EXPIRED   (expiry reconciliation: consumed-nothing, timed out)
# Terminal states and forbidden transitions are derived from this map.
# A NEW approval row is the only path back to approval after a terminal
# state (REJECTED/EXPIRED/REVOKED/USED are never mutated in place).
ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    ApprovalState.PENDING: frozenset({ApprovalState.APPROVED, ApprovalState.REJECTED}),
    ApprovalState.APPROVED: frozenset({ApprovalState.REVOKED, ApprovalState.EXPIRED}),
    # USED and REJECTED are terminal: nothing may resurrect them.
    ApprovalState.USED: frozenset(),
    ApprovalState.REJECTED: frozenset(),
    ApprovalState.REVOKED: frozenset(),
    ApprovalState.EXPIRED: frozenset(),
}

# States from which a token can still be consumed
CONSUMABLE_STATES = frozenset({ApprovalState.APPROVED})

# States from which the approval still decides a live decision
DECIDABLE_STATES = frozenset({ApprovalState.PENDING})


def can_transition(current: str, new: str) -> bool:
    """Check a state-machine transition. Unknown states are never allowed."""
    if current not in ALL_APPROVAL_STATES or new not in ALL_APPROVAL_STATES:
        return False
    return new in ALLOWED_TRANSITIONS.get(current, frozenset())


def assert_transition(current: str, new: str) -> None:
    """Raise ApprovalStateError for forbidden transitions."""
    if not can_transition(current, new):
        raise ApprovalStateError(
            f"approval state transition {current} -> {new} is not permitted"
        )


def is_terminal(state: str) -> bool:
    """A terminal state allows no outgoing transitions."""
    if state not in ALL_APPROVAL_STATES:
        return True  # unknown → treat as terminal (fail closed)
    return len(ALLOWED_TRANSITIONS[state]) == 0


# ── Approval expiry ──────────────────────────────────────────────────


def approval_expiry(approved_at: datetime) -> datetime:
    """Server-derived approval expiry: approved_at + APPROVAL_TTL_MINUTES.

    Clients cannot set or extend expirations.
    """
    approved = approved_at if approved_at.tzinfo else approved_at.replace(tzinfo=timezone.utc)
    return approved + timedelta(minutes=APPROVAL_TTL_MINUTES)


def is_approval_expired(expires_at: datetime, now: datetime) -> bool:
    """True when now is at or past expires_at. UTC-normalized."""
    if expires_at is None:
        return True
    exp = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=timezone.utc)
    n = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    return n >= exp


# ── Approver eligibility ─────────────────────────────────────────────


def is_step_up_fresh(step_up_at: datetime, now: datetime) -> bool:
    """True when a step-up authentication round-trip is recent enough.

    Allows up to 60 seconds of backwards clock skew (a marker written
    microseconds after the caller's `now` snapshot, or NTP correction).
    Markers stamped more than 60 seconds in the future are treated as
    forged and rejected.
    """
    if step_up_at is None:
        return False
    su = step_up_at if step_up_at.tzinfo else step_up_at.replace(tzinfo=timezone.utc)
    n = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    age_seconds = (n - su).total_seconds()
    return -60 <= age_seconds <= STEP_UP_SESSION_MAX_AGE_MINUTES * 60


def check_approver_eligibility(
    *,
    risk_level: str,
    approver_id: str,
    proposer_id: str,
    second_approver_user_id: "str | None",
    step_up_at: "datetime | None",
    now: datetime,
    second_step_up_at: "datetime | None" = None,
) -> tuple[bool, str]:
    """Evaluate approver eligibility per docs/v3-security-model.md §6.

    Returns (eligible, reason_code).

    Rules:
    - LOW risk:  self-approval allowed with a fresh step-up authentication
    - MEDIUM:    self-approval allowed with a fresh step-up authentication
    - HIGH/CRITICAL: second principal required (approver must differ from
      the proposal creator); BOTH principals need fresh step-up.
    """
    rl = (risk_level or "").upper()

    if rl in SECOND_PRINCIPAL_RISK_LEVELS:
        # Second-principal rule
        if approver_id == proposer_id:
            return False, "SECOND_APPROVER_REQUIRED"
        if not is_step_up_fresh(step_up_at, now):
            return False, "STEP_UP_REQUIRED"
        if not is_step_up_fresh(second_step_up_at, now):
            return False, "STEP_UP_REQUIRED"
        return True, "OK"

    if rl in {"LOW", "MEDIUM"}:
        if not is_step_up_fresh(step_up_at, now):
            return False, "STEP_UP_REQUIRED"
        return True, "OK"

    # Unknown / malformed risk levels fail closed
    return False, "UNKNOWN_RISK_LEVEL"


# ── One-time authorization tokens ────────────────────────────────────


def generate_token() -> str:
    """Generate a one-time authorization token (returned once, in full).

    256 bits of entropy, URL-safe. Plaintext is shown to the approver
    exactly once at issuance and is never persisted.
    """
    raw = secrets.token_urlsafe(32)
    return f"{_TOKEN_PREFIX}_{raw}"


def _signing_key() -> bytes:
    """Derive the keyed-hash key. Uses SECRET_KEY via HKDF-like extraction
    so that rotating the app secret invalidates outstanding tokens."""
    import hashlib as _h

    from app.config import get_settings

    ikm = get_settings().secret_key.encode("utf-8")
    return _h.sha256(_TOKEN_SECRET_INFO + b"\x00" + ikm).digest()


def hash_token(token: str) -> str:
    """Keyed hash (HMAC-SHA256) of a token for storage. Not reversible
    without the app secret; prevents rainbow/preimage attacks against a
    stolen hash DB dump."""
    key = _signing_key()
    return hmac.new(key, token.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_token_hash(token: str, token_hash: str) -> bool:
    """Constant-time comparison of a presented token against a stored hash."""
    if not token or not token_hash:
        return False
    return hmac.compare_digest(hash_token(token), token_hash)


def validate_step_up_marker(value: object) -> bool:
    """Validate a Redis step-up marker value (epoch-seconds string)."""
    return isinstance(value, str) and bool(_STEP_UP_AGE.match(value)) and 0 < int(value) <= 4_102_444_800


# ── Approval reason ──────────────────────────────────────────────────


def validate_reason(raw: object) -> str:
    """Validate and bound the human reason. Human metadata only — never
    authorization logic. Returns "" for None."""
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raise ApprovalStateError("reason must be a string")
    if len(raw) > MAX_REASON_LENGTH:
        raise ApprovalStateError(f"reason exceeds {MAX_REASON_LENGTH} characters")
    if any(ord(c) < 32 and c not in ("\t", "\n", "\r") for c in raw):
        raise ApprovalStateError("reason contains control characters")
    return raw
