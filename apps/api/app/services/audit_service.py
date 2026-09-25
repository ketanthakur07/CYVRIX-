"""V3.8 — Tamper-evident audit chains.

SECURITY MODEL (docs/v3-audit-integrity.md is normative):

- TAMPER-EVIDENT, not physically immutable. A database row plus an
  application-computed hash makes unauthorized modification *detectable*
  within the defined trust model; it does not make it impossible.
- CHAIN MODEL: one hash chain per tenant installation (audit_chains;
  1:1 with the tenant boundary used across V3.1–V3.7). No global lock:
  concurrency is per-chain, tenant isolation follows installation.
- DIGEST CONSTRUCTION (v1):
      event_digest = SHA-256(
          b"cyvrix-audit-v1" || 0x1f || chain_id.bytes || 0x1f ||
          prev_digest.encode("ascii") || 0x1f ||
          canonical_json(event_payload).encode("utf-8")
      )
  prev_digest is the hex digest of the predecessor event, or
  GENESIS_PREV_DIGEST ("0" * 64) for sequence 1 — never NULL. An event
  whose predecessor link is wrong cannot validate.
- ORDERING: (chain_id, seq) with server-side sequencing inside the
  caller's transaction. Timestamps are metadata, never ordering
  authority. Canonical timestamps are UTC ISO-8601 with microseconds.
- CRITICALITY: SECURITY-CRITICAL events commit atomically with the
  security state change they witness (fail closed); OPERATIONAL events
  are best-effort (failure logged, product continues).
- SECRETS: centralized redaction runs BEFORE canonicalization; nothing
  secret ever enters the hash input (hashing is not redaction).
- TRUNCATION: a plain hash chain cannot detect tail truncation by
  itself; signed checkpoints (HMAC key outside the database) and the
  standalone export verifier close that gap. Residual trust is
  documented, never overstated.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession as SAAsyncSession

from app.config import get_settings
from app.models import AuditChain, AuditChainEvent, AuditCheckpoint

logger = logging.getLogger(__name__)

# ── Genesis ───────────────────────────────────────────────────────────

GENESIS_PREV_DIGEST = "0" * 64  # deterministic, recognizable genesis link
CHAIN_DOMAIN = b"cyvrix-audit-v1"
EVENT_SCHEMA_VERSION = 1

# ── Actor identity (server-derived only) ─────────────────────────────


class ActorType:
    USER = "USER"
    ADMIN = "ADMIN"
    WORKER = "WORKER"
    EXECUTOR = "EXECUTOR"
    SYSTEM = "SYSTEM"
    RECONCILER = "RECONCILER"
    GITHUB_INTEGRATION = "GITHUB_INTEGRATION"


VALID_ACTOR_TYPES = frozenset({
    ActorType.USER, ActorType.ADMIN, ActorType.WORKER, ActorType.EXECUTOR,
    ActorType.SYSTEM, ActorType.RECONCILER, ActorType.GITHUB_INTEGRATION,
})


class Criticality:
    SECURITY_CRITICAL = "SECURITY_CRITICAL"  # atomic with the state change
    OPERATIONAL = "OPERATIONAL"              # best-effort, never blocks
    DIAGNOSTIC = "DIAGNOSTIC"                # best-effort, may be dropped


# ── Closed-world event type registry (Phase 17) ──────────────────────
# Every appendable event type MUST be listed here with its criticality.
# Unknown types are rejected (fail closed). Extending the registry is a
# code change, never a client input.

EVENT_CRITICALITY: dict[str, str] = {
    # V3.1 action lifecycle
    "ACTION_PROPOSED": Criticality.SECURITY_CRITICAL,
    # V3.2 approvals
    "ACTION_APPROVED": Criticality.SECURITY_CRITICAL,
    "ACTION_REJECTED": Criticality.SECURITY_CRITICAL,
    "APPROVAL_GRANTED": Criticality.SECURITY_CRITICAL,
    "APPROVAL_DENIED": Criticality.SECURITY_CRITICAL,
    "APPROVAL_REVOKED": Criticality.SECURITY_CRITICAL,
    # V3.3 authorization
    "AUTHORIZATION_CREATED": Criticality.SECURITY_CRITICAL,
    "AUTHORIZATION_DENIED": Criticality.SECURITY_CRITICAL,
    "AUTHORIZATION_CONSUMED": Criticality.SECURITY_CRITICAL,
    "AUTHORIZATION_REVOKED": Criticality.SECURITY_CRITICAL,
    # V3.4 execution
    "EXECUTION_STARTED": Criticality.SECURITY_CRITICAL,
    "EXECUTION_COMPLETED": Criticality.SECURITY_CRITICAL,
    "EXECUTION_FAILED": Criticality.SECURITY_CRITICAL,
    # V3.5 git/github
    "GIT_COMMIT_CREATED": Criticality.SECURITY_CRITICAL,
    "GITHUB_PUSH_STARTED": Criticality.OPERATIONAL,
    "GITHUB_PUSH_SUCCEEDED": Criticality.SECURITY_CRITICAL,
    "GITHUB_PUSH_FAILED": Criticality.SECURITY_CRITICAL,
    "PR_CREATED": Criticality.OPERATIONAL,
    # V3.6 verification/rollback
    "VERIFICATION_STARTED": Criticality.OPERATIONAL,
    "VERIFICATION_PASSED": Criticality.SECURITY_CRITICAL,
    "VERIFICATION_FAILED": Criticality.SECURITY_CRITICAL,
    "ROLLBACK_STARTED": Criticality.OPERATIONAL,
    "ROLLBACK_SUCCEEDED": Criticality.SECURITY_CRITICAL,
    "ROLLBACK_FAILED": Criticality.SECURITY_CRITICAL,
    # V3.7 operational controls
    "SYSTEM_PAUSED": Criticality.SECURITY_CRITICAL,
    "SYSTEM_RESUMED": Criticality.SECURITY_CRITICAL,
    "EMERGENCY_STOP": Criticality.SECURITY_CRITICAL,
    "JOB_RECONCILED": Criticality.OPERATIONAL,
    "CIRCUIT_OPENED": Criticality.OPERATIONAL,
    "CIRCUIT_RESET": Criticality.SECURITY_CRITICAL,
    "CREDENTIAL_DENIED": Criticality.SECURITY_CRITICAL,
    "GITHUB_CREDENTIAL_ISSUED": Criticality.SECURITY_CRITICAL,
    # V3.7 operational control events (emitted via ops_service._op_event)
    "REPOSITORY_PAUSED": Criticality.SECURITY_CRITICAL,
    "REPOSITORY_CONTROL_CHANGED": Criticality.SECURITY_CRITICAL,
    "EXECUTION_CANCEL_REQUESTED": Criticality.SECURITY_CRITICAL,
    "EXECUTION_CANCELLED": Criticality.SECURITY_CRITICAL,
    "JOB_RETRY_REQUESTED": Criticality.OPERATIONAL,
    "JOB_RETRY_EXHAUSTED": Criticality.OPERATIONAL,
    "LEASE_EXPIRED": Criticality.OPERATIONAL,
    "ORPHAN_CLEANUP": Criticality.OPERATIONAL,
    "EXECUTION_FAILURE_RECORDED": Criticality.OPERATIONAL,
    "QUOTA_EXCEEDED": Criticality.OPERATIONAL,
    "RATE_LIMITED": Criticality.OPERATIONAL,
    "SECURITY_INCIDENT_MODE": Criticality.SECURITY_CRITICAL,
    "ADMIN_CONFIGURATION_CHANGED": Criticality.SECURITY_CRITICAL,
    # ── V4.1 external boundary (closed world; do not add casually) ──────
    # API-key lifecycle. SECURITY-CRITICAL: a credential gain/loss must
    # commit atomically with its audit event.
    "API_KEY_CREATED": Criticality.SECURITY_CRITICAL,
    "API_KEY_ROTATED": Criticality.SECURITY_CRITICAL,
    "API_KEY_REVOKED": Criticality.SECURITY_CRITICAL,
    "API_KEY_EXPIRED": Criticality.SECURITY_CRITICAL,
    # Inbound webhook lifecycle. Rejections are SECURITY-CRITICAL (an
    # attacker-visible refusal must be on the record); acceptance is
    # OPERATIONAL (the scan request itself re-audits).
    "WEBHOOK_RECEIVED": Criticality.OPERATIONAL,
    "WEBHOOK_ACCEPTED": Criticality.OPERATIONAL,
    "WEBHOOK_REJECTED": Criticality.SECURITY_CRITICAL,
    "WEBHOOK_REPLAY_REJECTED": Criticality.SECURITY_CRITICAL,
    # CI event lifecycle.
    "CI_EVENT_RECEIVED": Criticality.OPERATIONAL,
    "CI_EVENT_REJECTED": Criticality.SECURITY_CRITICAL,
    # Analysis request submitted through the public API.
    "SCAN_REQUESTED": Criticality.OPERATIONAL,
    # Idempotency conflict (a caller probing key reuse).
    "IDEMPOTENCY_CONFLICT": Criticality.OPERATIONAL,
    # Quota enforcement.
    "QUOTA_LIMIT_REACHED": Criticality.OPERATIONAL,
}

# Legacy V1–V3.6 audit_events types that the existing producers emit.
# V3.8 chains these through emit_security_event; the mapping to the
# closed-world registry is explicit (no silent renaming).
LEGACY_EVENT_TYPE_MAP: dict[str, str] = {
    "ACTION_PROPOSAL_CREATED": "ACTION_PROPOSED",
    "APPROVAL_DIGEST_MISMATCH": "AUTHORIZATION_DENIED",
    "APPROVAL_POLICY_DENIED": "APPROVAL_DENIED",
    "APPROVAL_REJECTED": "ACTION_REJECTED",
    "APPROVAL_UNAUTHORIZED": "AUTHORIZATION_DENIED",
    "EXECUTION_ADMITTED": "EXECUTION_STARTED",
    "EXECUTION_AUTHORIZATION_CONSUMED": "AUTHORIZATION_CONSUMED",
    "EXECUTION_AUTHORIZATION_DENIED": "AUTHORIZATION_DENIED",
    "EXECUTION_AUTHORIZATION_REVOKED": "AUTHORIZATION_REVOKED",
    "EXECUTION_AUTHORIZED": "AUTHORIZATION_CREATED",
    "EXECUTION_DENIED": "AUTHORIZATION_DENIED",
    "EXECUTION_DIGEST_MISMATCH": "AUTHORIZATION_DENIED",
    "EXECUTION_POLICY_DENIED": "AUTHORIZATION_DENIED",
    "EXECUTION_STUCK_DETECTED": "EXECUTION_FAILED",
    "GIT_REMEDIATION_CREATED": "GIT_COMMIT_CREATED",
    "GIT_REMEDIATION_FAILED": "GITHUB_PUSH_FAILED",
    "REMEDIATION_VERIFIED": "VERIFICATION_PASSED",
    "ROLLBACK_REQUESTED": "ROLLBACK_STARTED",
    "SANDBOX_CLEANUP_FAILED": "ROLLBACK_FAILED",
    "SCOPE_VIOLATION": "AUTHORIZATION_DENIED",
    "VERIFICATION_BLOCKED": "VERIFICATION_FAILED",
    "VERIFICATION_CONFLICT": "VERIFICATION_FAILED",
    "VERIFICATION_INCONCLUSIVE": "VERIFICATION_FAILED",
    "ROLLBACK_CONFLICT": "ROLLBACK_FAILED",
    "ROLLBACK_STATE_MISMATCH": "ROLLBACK_FAILED",
    "ROLLBACK_PUSH": "GITHUB_PUSH_SUCCEEDED",
}


class AuditEventError(Exception):
    """Unknown/unregistered event type or invalid actor — fail closed."""


def _norm_uuid(value):
    """Server-side normalization for UUID-typed event fields.

    Callers may pass uuid.UUID, dashed strings, or raw hex strings;
    every accepted form is converted to a real UUID object so the ORM
    bind processors are deterministic across dialects (SQLite's
    processor requires a dashed form). Returns None for None; raises
    ValueError for malformed values (fail closed before any state is
    touched)."""
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return value
    s = str(value).replace("-", "")
    if len(s) == 64:  # hex-encoded 32 bytes: take the first 16
        s = s[:32]
    return uuid.UUID(hex=s)


# ── Secret redaction (Phase 15/38) — BEFORE canonicalization ─────────

_SECRET_KEY_PATTERN = re.compile(
    r"(token|secret|password|passwd|private_key|authorization|cookie|"
    r"credential|api_key|apikey|session|bearer)",
    re.IGNORECASE,
)

_REDACTED = "[REDACTED]"


def redact_payload(value: Any, _depth: int = 0) -> Any:
    """Recursively redact secret-bearing keys and oversized blobs.

    Key names decide: any key matching the secret pattern is replaced by
    a marker regardless of value. Applied centrally so no producer can
    forget. Depth-bounded to keep canonicalization deterministic.
    """
    if _depth > 6:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and _SECRET_KEY_PATTERN.search(k):
                out[k] = _REDACTED
            else:
                out[k] = redact_payload(v, _depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [redact_payload(v, _depth + 1) for v in value[:20]]
    if isinstance(value, str):
        # Defensive: never let token-shaped strings into the chain even
        # under an unflagged key (ghp_/gho_/github_pat_ prefix patterns).
        if re.search(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}", value):
            return _REDACTED
        return value[:2000]
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        # No floating-point ambiguity: floats are canonicalized as repr
        # strings only when finite; otherwise stringified.
        return repr(value)
    return str(value)[:2000]


# ── Canonicalization (Phase 3) — ONE deterministic serializer ─────────

def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8, explicit
    null, float-free (floats pre-stringified by redact_payload), stable
    Unicode (ensure_ascii=False, fixed encoding at the hash boundary)."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False, default=_canonical_default,
    )


def _canonical_default(o: Any) -> Any:
    if isinstance(o, datetime):
        return canonical_timestamp(o)
    if isinstance(o, (set, frozenset)):
        return sorted(str(x) for x in o)
    if hasattr(o, "hex"):  # UUID
        return str(o)
    return str(o)


def canonical_timestamp(dt) -> str:
    """UTC ISO-8601 with microseconds — the ONLY timestamp representation
    used in canonical payloads (no locale, no DST, no local time).
    None canonicalizes deterministically to "" so a nulled timestamp is
    DETECTED as a digest mismatch by the verifier, never a crash."""
    if dt is None:
        return ""
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical_event_payload(event: AuditChainEvent) -> dict[str, Any]:
    """The canonical, hashable representation of an event's trusted
    fields. Field set is closed: adding fields is a schema-version bump,
    never a silent change to v1 hashing."""
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_type": event.event_type,
        "event_version": int(event.event_version),
        "actor_type": event.actor_type,
        "actor_id": event.actor_id,
        "actor_user_id": str(event.actor_user_id) if event.actor_user_id else None,
        "repository_id": str(event.repository_id) if event.repository_id else None,
        "action_id": str(event.action_id) if event.action_id else None,
        "authorization_id": str(event.authorization_id) if event.authorization_id else None,
        "execution_run_id": str(event.execution_run_id) if event.execution_run_id else None,
        "verification_id": str(event.verification_id) if event.verification_id else None,
        "rollback_id": str(event.rollback_id) if event.rollback_id else None,
        "reason_code": event.reason_code,
        "result": event.result,
        "payload": event.payload if event.payload is not None else {},
        "occurred_at": canonical_timestamp(event.occurred_at),
        "recorded_at": canonical_timestamp(event.recorded_at),
        "seq": int(event.seq),
    }


def _uuid16(value) -> bytes:
    """Deterministic 16-byte form of a chain id across dialects
    (Postgres returns uuid.UUID; SQLite returns a 32-char hex str with
    no dashes — normalize through uuid.UUID either way)."""
    if isinstance(value, uuid.UUID):
        return value.bytes
    s = str(value).replace("-", "")
    if len(s) == 64:  # hex-encoded 32 bytes: take the first 16
        s = s[:32]
    return uuid.UUID(hex=s).bytes


def compute_event_digest(
    *, chain_id, prev_digest: str, canonical_payload: dict[str, Any]
) -> str:
    """event_digest = H(domain || chain || prev || canonical_payload).
    The predecessor link is INSIDE the hash: an event is not
    independently valid if its predecessor link is wrong."""
    h = hashlib.sha256()
    h.update(CHAIN_DOMAIN)
    h.update(b"\x1f")
    h.update(_uuid16(chain_id))
    h.update(b"\x1f")
    h.update(prev_digest.encode("ascii"))
    h.update(b"\x1f")
    h.update(canonical_json(canonical_payload).encode("utf-8"))
    return h.hexdigest()


# ── Checkpoint MAC (Phase 21/22/24) — key outside the database ────────

def checkpoint_mac(payload_digest: str, key: str, key_version: int) -> str:
    return hmac.new(
        f"cyvrix-audit-checkpoint-v1:{key_version}".encode("ascii"),
        payload_digest.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def checkpoint_material(chain_id, through_sequence: int, head_digest: str,
                        event_count: int) -> str:
    """Canonical checkpoint payload — the exact MAC input."""
    return canonical_json({
        "chain_id": str(chain_id),
        "through_sequence": int(through_sequence),
        "head_digest": head_digest,
        "event_count": int(event_count),
        "schema_version": EVENT_SCHEMA_VERSION,
    })


# ── Append (Phase 9/10/11) ────────────────────────────────────────────

async def get_or_create_chain(db: AsyncSession, *, installation_id) -> AuditChain:
    """Resolve the tenant chain (concurrency-safe).

    installation_id MUST be the server-side installation row PK (UUID)
    — resolved by the caller from repository ownership; the GitHub
    installation NUMBER is data, never identity.

    Race discipline: two concurrent first-events for one tenant both
    pass the SELECT; the loser of the INSERT hits the UNIQUE
    (installation_id) constraint and re-selects the winner's chain
    inside the same transaction. The chain row is created exactly once,
    but no event ordering is sacrificed and no global lock is taken."""
    iid = _norm_uuid(installation_id)
    chain = (
        await db.execute(
            select(AuditChain).where(AuditChain.installation_id == iid)
        )
    ).scalar_one_or_none()
    if chain is not None:
        return chain
    # SAVEPOINT-scoped insert: when a concurrent creator wins, the UNIQUE
    # backstop aborts only the savepoint — NEVER the caller's transaction,
    # which may already hold flushed security state (e.g. an API key row
    # awaiting its fail-closed audit witness). A full rollback here would
    # silently destroy that state while the caller still reports success.
    try:
        async with db.begin_nested():
            db.add(AuditChain(installation_id=iid))
            await db.flush()
    except Exception:
        # Concurrent creator won (UNIQUE installation_id). Re-read the
        # winner inside this transaction and continue.
        pass
    return (
        await db.execute(
            select(AuditChain).where(AuditChain.installation_id == iid)
        )
    ).scalar_one()


async def get_or_create_organization_chain(
    db: AsyncSession, *, organization_id
) -> AuditChain:
    """V4.1 — resolve the per-ORGANIZATION chain (concurrency-safe).

    An organization may hold ZERO installations (a key-only tenant), yet
    its key lifecycle and public-API events must still be hash-chained.
    This chain is installation_id = NULL, organization_id = org PK. Same
    race discipline as the installation chain: the UNIQUE(organization_id)
    index decides the winner.
    """
    oid = _norm_uuid(organization_id)
    chain = (
        await db.execute(
            select(AuditChain).where(AuditChain.organization_id == oid)
        )
    ).scalar_one_or_none()
    if chain is not None:
        return chain
    # SAVEPOINT-scoped insert — same discipline as get_or_create_chain:
    # a lost creation race must never roll back the caller's transaction.
    try:
        async with db.begin_nested():
            db.add(AuditChain(organization_id=oid))
            await db.flush()
    except Exception:
        pass
    return (
        await db.execute(
            select(AuditChain).where(AuditChain.organization_id == oid)
        )
    ).scalar_one()


async def emit_security_event(
    db: AsyncSession,
    *,
    installation_id=None,
    organization_id=None,
    event_type: str,
    actor_type: str = ActorType.SYSTEM,
    actor_id: Optional[str] = None,
    actor_user_id=None,
    repository_id=None,
    action_id=None,
    authorization_id=None,
    execution_run_id=None,
    verification_id=None,
    rollback_id=None,
    reason_code: Optional[str] = None,
    result: Optional[str] = None,
    payload: Optional[dict] = None,
    occurred_at: Optional[datetime] = None,
    event_version: int = EVENT_SCHEMA_VERSION,
) -> tuple[bool, Optional[str]]:
    """Append one hash-linked event to the tenant's chain INSIDE the
    caller's transaction (SECURITY-CRITICAL semantics: the event commits
    atomically with the state change it witnesses — the caller owns the
    commit; this function never commits).

    Concurrency discipline (Phase 9): concurrent appends serialize on a
    row-level lock of the chain row, acquired BEFORE the head is read;
    the UNIQUE (chain_id, seq) / (chain_id, prev_digest) constraints are
    the backstop. On a lost sequencing race the append is retried (≤3)
    and then fails closed — a duplicate-sequence event is never committeed.

    Returns (ok, error_code). Fail-closed behavior for unknown event
    types/actors (programming errors) raises AuditEventError before any
    state is touched. Registry mapping for legacy V1–V3.6 event names is
    explicit and validated against the closed-world registry.
    """
    registered = LEGACY_EVENT_TYPE_MAP.get(event_type, event_type)
    criticality = EVENT_CRITICALITY.get(registered)
    if criticality is None:
        raise AuditEventError(f"unregistered audit event type: {event_type}")
    if actor_type not in VALID_ACTOR_TYPES:
        raise AuditEventError(f"invalid actor type: {actor_type}")

    last_error: Optional[Exception] = None
    for _attempt in range(3):
        try:
            # SAVEPOINT per attempt: a lost sequencing race aborts only the
            # append attempt, never the caller's transaction — which may
            # already hold flushed security state (e.g. an API key row
            # awaiting this fail-closed witness). A full rollback here
            # would discard that state while the caller still reports
            # success, minting a credential that was never persisted.
            async with db.begin_nested():
                return await _emit_event_locked(
                    db,
                    installation_id=installation_id,
                    organization_id=organization_id,
                    registered=registered,
                    actor_type=actor_type,
                    actor_id=actor_id,
                    actor_user_id=actor_user_id,
                    repository_id=repository_id,
                    action_id=action_id,
                    authorization_id=authorization_id,
                    execution_run_id=execution_run_id,
                    verification_id=verification_id,
                    rollback_id=rollback_id,
                    reason_code=reason_code,
                    result=result,
                    payload=payload,
                    occurred_at=occurred_at,
                    event_version=event_version,
                )
        except Exception as exc:
            last_error = exc
            if not _is_sequencing_race(exc):
                raise
            # A lost sequencing race is retried from a clean savepoint:
            # the unique (chain_id, seq/prev_digest) backstop only fires
            # once the competing append has committed, so a fresh
            # savepoint is required for the retry to observe the new head.
    raise last_error if last_error else AuditEventError("audit append failed")


def _is_sequencing_race(exc: Exception) -> bool:
    """True when the failure is the UNIQUE backstop catching a lost
    append race (never a data problem we should swallow)."""
    name = type(exc).__name__
    if name in ("UniqueViolationError", "IntegrityError"):
        text_ = str(getattr(exc, "orig", exc)).lower() + str(exc).lower()
        return any(marker in text_ for marker in (
            "uq_audit_chain_events_seq", "uq_audit_chain_events_prev",
            "uq_audit_checkpoints_seq", "audit_chains_installation_id_key",
            "audit_chains_organization_id_key",
        ))
    return False


async def _emit_event_locked(
    db: AsyncSession,
    *,
    installation_id,
    organization_id,
    registered: str,
    actor_type: str,
    actor_id: Optional[str],
    actor_user_id,
    repository_id,
    action_id,
    authorization_id,
    execution_run_id,
    verification_id,
    rollback_id,
    reason_code: Optional[str],
    result: Optional[str],
    payload: Optional[dict],
    occurred_at: Optional[datetime],
    event_version: int,
) -> tuple[bool, Optional[str]]:
    """Single append attempt. The chain row lock is taken before the
    head is read, so concurrent appends to one chain serialize on the
    row (no global lock across tenants).

    V4.1: exactly one chain owner must be supplied — an installation
    (tenant boundary with repositories) or an organization (key-only
    boundary for API-key lifecycle and public-API events). Supplying
    neither is a programming error and fails closed."""
    if installation_id is not None:
        chain = await get_or_create_chain(db, installation_id=installation_id)
    elif organization_id is not None:
        chain = await get_or_create_organization_chain(db, organization_id=organization_id)
    else:
        raise AuditEventError(
            "audit event requires installation_id or organization_id"
        )
    await db.execute(
        select(AuditChain.id).where(AuditChain.id == chain.id).with_for_update()
    )
    await db.refresh(chain)  # re-read head AFTER the lock

    now = datetime.now(timezone.utc)
    seq = int(chain.last_sequence or 0) + 1
    prev = chain.last_event_digest or GENESIS_PREV_DIGEST

    event = AuditChainEvent(
        chain_id=chain.id,
        seq=seq,
        event_type=registered,
        event_version=event_version,
        actor_type=actor_type,
        actor_id=(actor_id or (str(actor_user_id) if actor_user_id else None)),
        actor_user_id=_norm_uuid(actor_user_id),
        repository_id=_norm_uuid(repository_id),
        action_id=_norm_uuid(action_id),
        authorization_id=_norm_uuid(authorization_id),
        execution_run_id=_norm_uuid(execution_run_id),
        verification_id=_norm_uuid(verification_id),
        rollback_id=_norm_uuid(rollback_id),
        reason_code=reason_code,
        result=result,
        payload=redact_payload(payload or {}),
        occurred_at=occurred_at or now,
        recorded_at=now,
        prev_digest=prev,
    )
    event.event_digest = compute_event_digest(
        chain_id=chain.id, prev_digest=prev,
        canonical_payload=canonical_event_payload(event),
    )
    db.add(event)

    # Head bookkeeping (advisory; verifier recomputes from events).
    chain.last_sequence = seq
    chain.last_event_digest = event.event_digest
    chain.updated_at = now

    # Advisory tail checkpoint when configured (best-effort within the
    # same transaction; verification never depends on its existence).
    key = get_settings().audit_checkpoint_key
    if key:
        count = int(seq)
        material = checkpoint_material(chain.id, seq, event.event_digest, count)
        db.add(AuditCheckpoint(
            chain_id=chain.id,
            through_sequence=seq,
            head_digest=event.event_digest,
            event_count=count,
            payload_digest=material,
            mac=checkpoint_mac(material, key, 1),
            mac_key_version=1,
        ))
    return True, None


# ── Legacy audit_events bridge (Phase 10: same-transaction chaining) ──


def _correlation_from_metadata(metadata: dict) -> dict:
    """Extract V3.8 correlation ids from legacy metadata keys (explicit
    allowlist — never pass untrusted metadata through blindly)."""
    keys = {
        "action_digest", "proposal_id", "policy_version", "execution_run_id",
        "execution_authorization_id", "git_remediation_id", "approval_id",
        "authorization_id", "verification_id", "rollback_id", "pr_url",
        "branch", "commit_sha", "recommendation_id", "finding_id",
    }
    return {k: metadata[k] for k in keys if k in metadata and metadata[k] is not None}


async def emit_from_legacy_audit(
    db: AsyncSession,
    *,
    repository_id,
    event_type: str,
    metadata: dict,
    actor_user_id=None,
    finding_id=None,
    result: Optional[str] = None,
    commit_with: bool = False,
) -> None:
    """Mirror a legacy AuditEvent(...) call into the V3.8 chain inside the
    SAME transaction as the producer's state change (SECURITY-CRITICAL
    atomicity preserved). Best-effort: the legacy row is the record of
    truth for pre-V3.8 compatibility; chain failure is logged loudly and
    surfaced via the integrity signal, never used to weaken a decision
    and never masked silently."""
    try:
        from app.models import Repository
        installation_id = (
            await db.execute(
                select(Repository.installation_id).where(Repository.id == repository_id)
            )
        ).scalar_one_or_none()
        if installation_id is None:
            logger.warning("audit_chain_no_tenant repo=%s event=%s",
                           str(repository_id)[:8], event_type)
            return
        correlation = _correlation_from_metadata(metadata or {})
        actor_id = metadata.get("actor") if metadata else None
        # The mirror is BEST-EFFORT and must never poison the producer's
        # transaction. A SAVEPOINT contains any failure — including the
        # producer's own pending constraint violation surfaced by the
        # autoflush this append triggers (e.g. a concurrent exactly-once
        # insert losing its unique index) — so the producer can still
        # commit, or classify its own conflict, instead of dying with
        # PendingRollbackError.
        async with db.begin_nested():
            await emit_security_event(
                db,
                installation_id=installation_id,
                event_type=event_type,
                actor_type=ActorType.USER if actor_user_id is not None else ActorType.SYSTEM,
                actor_id=actor_id,
                actor_user_id=actor_user_id,
                repository_id=repository_id,
                action_id=correlation.get("proposal_id"),
                authorization_id=correlation.get(
                    "execution_authorization_id",
                    correlation.get("authorization_id")),
                execution_run_id=correlation.get("execution_run_id"),
                verification_id=correlation.get("verification_id"),
                rollback_id=correlation.get("rollback_id"),
                reason_code=metadata.get("reason_code") if metadata else None,
                result=result,
                payload={
                    "legacy_event_type": event_type,
                    "finding_id": str(finding_id) if finding_id else None,
                    **correlation,
                },
            )
    except AuditEventError as exc:
        logger.error("audit_chain_registry_miss event=%s err=%s", event_type, exc)
    except Exception as exc:  # never mask the security decision itself
        # Include the DB-level cause so an integrity incident is diagnosable
        # (constraint names only — audit payloads/credentials never appear).
        logger.warning(
            "audit_chain_mirror_failed event=%s err=%s detail=%s",
            event_type, type(exc).__name__,
            str(getattr(exc, "orig", exc))[:200],
        )


# ── Verifier (Phase 19/20) ────────────────────────────────────────────


@dataclass
class VerifyIssue:
    code: str
    seq: Optional[int] = None
    detail: Optional[str] = None


@dataclass
class VerifyResult:
    status: str  # VALID | INVALID | INCOMPLETE | UNSUPPORTED_VERSION | EMPTY
    checked_events: int = 0
    issues: list[VerifyIssue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == "VALID"


def verify_chain_rows(rows: list, checkpoints: list = (),
                      checkpoint_key: Optional[str] = None) -> VerifyResult:
    """Pure verifier over ordered chain rows (works on DB rows AND on
    export rows, Phase 27/28). Detects: payload tampering, digest
    mismatch, predecessor breaks, sequence gaps/duplicates/reordering,
    genesis defects, unsupported schema versions, checkpoint MAC
    mismatch/truncation beyond a trusted checkpoint."""
    issues: list[VerifyIssue] = []
    if not rows:
        return VerifyResult(status="EMPTY", checked_events=0, issues=issues)

    expected_seq = rows[0].seq
    prev = rows[0].prev_digest
    max_verified_seq = 0
    last_verified_digest = GENESIS_PREV_DIGEST

    for row in rows:
        if row.event_version is None or int(row.event_version) > EVENT_SCHEMA_VERSION:
            issues.append(VerifyIssue(
                code="UNSUPPORTED_VERSION", seq=row.seq,
                detail=f"event_version={row.event_version}"))
            return VerifyResult(status="UNSUPPORTED_VERSION",
                                checked_events=len(rows), issues=issues)
        if row.seq != expected_seq:
            code = ("SEQ_GAP" if isinstance(row.seq, int) and row.seq > expected_seq
                    else "SEQ_DUPLICATE_OR_REORDER")
            issues.append(VerifyIssue(
                code=code, seq=row.seq,
                detail=f"expected_seq={expected_seq}"))
        if row.prev_digest != prev:
            issues.append(VerifyIssue(
                code="PREDECESSOR_BREAK", seq=row.seq,
                detail=f"prev={str(row.prev_digest)[:16]} expected={str(prev)[:16]}"))
        recomputed = compute_event_digest(
            chain_id=row.chain_id, prev_digest=row.prev_digest,
            canonical_payload=canonical_event_payload(row),
        )
        if recomputed != row.event_digest:
            issues.append(VerifyIssue(
                code="DIGEST_MISMATCH", seq=row.seq,
                detail=f"stored={str(row.event_digest)[:16]} computed={recomputed[:16]}"))
        prev = row.event_digest
        expected_seq = row.seq + 1
        max_verified_seq = max(max_verified_seq, int(row.seq))
        last_verified_digest = row.event_digest

    # Checkpoint verification (truncation anchor).
    # A MAC-valid checkpoint is an INDEPENDENT claim that the chain once
    # reached (through_sequence, head_digest). Two detections fall out:
    #   - CHECKPOINT_HEAD_MISMATCH: checkpoint at/below the verified head
    #     disagrees with the recomputed chain
    #   - TRUNCATED_TAIL: a MAC-valid checkpoint claims events BEYOND the
    #     presented head — the tail was deleted/withheld (T13)
    if checkpoints and checkpoint_key:
        verified_below = []
        for cp in checkpoints:
            material = checkpoint_material(
                cp.chain_id, cp.through_sequence, cp.head_digest, cp.event_count)
            expected_mac = checkpoint_mac(material, checkpoint_key, cp.mac_key_version or 1)
            if not hmac.compare_digest(expected_mac, cp.mac or ""):
                issues.append(VerifyIssue(
                    code="CHECKPOINT_MAC_MISMATCH",
                    seq=int(cp.through_sequence),
                    detail=f"through={cp.through_sequence}"))
                continue
            if int(cp.through_sequence) <= max_verified_seq:
                verified_below.append(cp)
            else:
                issues.append(VerifyIssue(
                    code="TRUNCATED_TAIL",
                    seq=int(cp.through_sequence),
                    detail=(f"checkpoint expects seq>={max_verified_seq + 1} "
                            f"through={cp.through_sequence} but chain ends at {max_verified_seq}")))
        if verified_below:
            latest = max(verified_below, key=lambda c: int(c.through_sequence))
            if latest.head_digest != last_verified_digest:
                issues.append(VerifyIssue(
                    code="CHECKPOINT_HEAD_MISMATCH",
                    seq=int(latest.through_sequence),
                    detail=f"cp_head={str(latest.head_digest)[:16]} chain_tail={str(last_verified_digest)[:16]}"))

    status = "VALID" if not issues else "INVALID"
    return VerifyResult(status=status, checked_events=len(rows), issues=issues)


async def verify_chain(
    db: SAAsyncSession, *, chain_id, from_seq: Optional[int] = None,
    to_seq: Optional[int] = None,
) -> VerifyResult:
    """Verify a stored chain (or a range). Statuses: VALID | INVALID |
    EMPTY | UNSUPPORTED_VERSION — never collapsed into one bucket."""
    q = (
        select(AuditChainEvent)
        .where(AuditChainEvent.chain_id == chain_id)
        .order_by(AuditChainEvent.seq.asc())
    )
    if from_seq is not None:
        q = q.where(AuditChainEvent.seq >= from_seq)
    if to_seq is not None:
        q = q.where(AuditChainEvent.seq <= to_seq)
    rows = list((await db.execute(q)).scalars().all())
    cps = list((await db.execute(
        select(AuditCheckpoint)
        .where(AuditCheckpoint.chain_id == chain_id)
        .order_by(AuditCheckpoint.through_sequence.asc())
    )).scalars().all())
    key = get_settings().audit_checkpoint_key
    result = verify_chain_rows(rows, cps, key if key else None)
    # V3.8 §16 — integrity failures must alert without a caller having to
    # inspect the verdict. Structured and content-free on purpose: only
    # the chain id prefix, checked count, and machine-readable issue codes
    # are logged — never event payloads ("alerts carry no event contents").
    if result.status == "INVALID":
        codes = sorted({i.code for i in result.issues})
        if any(c.startswith("CHECKPOINT_") for c in codes):
            logger.error(
                "audit_chain_checkpoint_mismatch chain=%s checked=%d codes=%s",
                str(chain_id)[:8], result.checked_events, ",".join(codes))
        logger.error(
            "audit_chain_verification_failed chain=%s checked=%d codes=%s",
            str(chain_id)[:8], result.checked_events, ",".join(codes))
    elif result.status == "UNSUPPORTED_VERSION":
        logger.error(
            "audit_chain_unsupported_version chain=%s checked=%d",
            str(chain_id)[:8], result.checked_events)
    return result


# ── Export (Phase 27/28) — deterministic NDJSON, independently verifiable

EXPORT_FORMAT_VERSION = 1


def export_chain_ndjson(
    rows: list, checkpoints: list = (), chain: Optional[AuditChain] = None
) -> str:
    """Canonical NDJSON export: one event per line, header first,
    checkpoints after. Bytes of the text are the verification input."""
    lines: list[str] = []
    header = {
        "type": "cyvrix_audit_export",
        "format_version": EXPORT_FORMAT_VERSION,
        "schema_version": EVENT_SCHEMA_VERSION,
        "chain_id": str(chain.id) if chain else str(rows[0].chain_id) if rows else None,
        "genesis_prev_digest": GENESIS_PREV_DIGEST,
        "digest_domain": CHAIN_DOMAIN.decode("ascii"),
    }
    lines.append(canonical_json(header))
    for row in rows:
        lines.append(canonical_json({
            "chain_id": str(row.chain_id),
            "seq": int(row.seq),
            "event_type": row.event_type,
            "event_version": int(row.event_version),
            "actor_type": row.actor_type,
            "actor_id": row.actor_id,
            "actor_user_id": str(row.actor_user_id) if row.actor_user_id else None,
            "repository_id": str(row.repository_id) if row.repository_id else None,
            "action_id": str(row.action_id) if row.action_id else None,
            "authorization_id": str(row.authorization_id) if row.authorization_id else None,
            "execution_run_id": str(row.execution_run_id) if row.execution_run_id else None,
            "verification_id": str(row.verification_id) if row.verification_id else None,
            "rollback_id": str(row.rollback_id) if row.rollback_id else None,
            "reason_code": row.reason_code,
            "result": row.result,
            "payload": row.payload if row.payload is not None else {},
            "occurred_at": canonical_timestamp(row.occurred_at),
            "recorded_at": canonical_timestamp(row.recorded_at),
            "prev_digest": row.prev_digest,
            "event_digest": row.event_digest,
        }))
    for cp in checkpoints:
        lines.append(canonical_json({
            "type": "checkpoint",
            "chain_id": str(cp.chain_id),
            "through_sequence": int(cp.through_sequence),
            "head_digest": cp.head_digest,
            "event_count": int(cp.event_count),
            "payload_digest": cp.payload_digest,
            "mac": cp.mac,
            "mac_key_version": int(cp.mac_key_version or 1),
            "created_at": canonical_timestamp(cp.created_at),
        }))
    return "\n".join(lines) + "\n"


@dataclass
class _ExportRow:
    """Mimics the AuditChainEvent attribute surface for the pure
    verifier over exported JSON records (no DB needed)."""

    def __init__(self, rec: dict):
        self.chain_id = rec["chain_id"]
        self.seq = int(rec["seq"])
        self.event_type = rec["event_type"]
        self.event_version = int(rec.get("event_version", 1))
        self.actor_type = rec["actor_type"]
        self.actor_id = rec.get("actor_id")
        self.actor_user_id = rec.get("actor_user_id")
        self.repository_id = rec.get("repository_id")
        self.action_id = rec.get("action_id")
        self.authorization_id = rec.get("authorization_id")
        self.execution_run_id = rec.get("execution_run_id")
        self.verification_id = rec.get("verification_id")
        self.rollback_id = rec.get("rollback_id")
        self.reason_code = rec.get("reason_code")
        self.result = rec.get("result")
        self.payload = rec.get("payload") or {}
        self.occurred_at = _parse_export_ts(rec.get("occurred_at"))
        self.recorded_at = _parse_export_ts(rec.get("recorded_at"))
        self.prev_digest = rec["prev_digest"]
        self.event_digest = rec["event_digest"]


@dataclass
class _ExportCheckpoint:
    def __init__(self, rec: dict):
        self.chain_id = rec["chain_id"]
        self.through_sequence = int(rec["through_sequence"])
        self.head_digest = rec["head_digest"]
        self.event_count = int(rec["event_count"])
        self.payload_digest = rec["payload_digest"]
        self.mac = rec["mac"]
        self.mac_key_version = int(rec.get("mac_key_version", 1))
        self.created_at = _parse_export_ts(rec.get("created_at"))


def _parse_export_ts(value: Optional[str]) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def verify_export_ndjson(text: str, *, checkpoint_key: Optional[str] = None) -> VerifyResult:
    """Standalone verification of an exported audit chain. Needs NO
    database — only the export text (and, for checkpoint MACs, the
    verification key). Detects payload tampering, digest mismatch,
    predecessor breaks, sequence tampering, reordering, insertion,
    duplication, and checkpoint MAC/anchor mismatch."""
    lines = [ln for ln in text.strip().splitlines() if ln.strip()]
    if not lines:
        return VerifyResult(status="EMPTY", checked_events=0)
    header = json.loads(lines[0])
    if header.get("type") != "cyvrix_audit_export":
        return VerifyResult(status="INVALID", checked_events=0, issues=[
            VerifyIssue(code="EXPORT_HEADER_MISSING")])
    if int(header.get("format_version", 0)) > EXPORT_FORMAT_VERSION:
        return VerifyResult(status="UNSUPPORTED_VERSION", checked_events=0)

    event_rows: list[_ExportRow] = []
    checkpoint_rows: list[_ExportCheckpoint] = []
    for ln in lines[1:]:
        rec = json.loads(ln)
        if rec.get("type") == "checkpoint":
            checkpoint_rows.append(_ExportCheckpoint(rec))
        else:
            event_rows.append(_ExportRow(rec))
    return verify_chain_rows(event_rows, checkpoint_rows, checkpoint_key)
