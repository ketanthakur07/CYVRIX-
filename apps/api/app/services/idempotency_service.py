"""CYVRIX V4.1 — idempotency / replay protection.

ONE primitive, two callers that are structurally identical:

    public API mutation ── Idempotency-Key ──┐
                                             ├──► (tenant, namespace, key)
    GitHub webhook delivery ── delivery id ──┘        → outcome + digest

Semantics (docs/v4-api-security.md §Idempotency):

    same key + same request      → the ORIGINAL result is replayed; the
                                   side effect happens exactly once
    same key + different request → CONFLICT (409). The stored outcome is
                                   NOT returned for a request that was
                                   never made
    different key                → a distinct operation

The three properties that make this safe rather than decorative:

1. **The record commits with the effect.** The reservation row is inserted
   inside the caller's transaction, so "the effect happened" and "we
   recorded that we did it" cannot diverge. A crash between them rolls
   back both.

2. **Concurrency is decided by the database.** The unique constraint on
   `(organization_id, scope, key_value)` means a concurrent duplicate
   cannot insert a second record. Postgres makes the loser WAIT on the
   index until the winner commits or aborts, then raises a unique
   violation — so the loser sees a *committed* outcome, never a torn one.

3. **Authorization is never cached.** `reserve()` is called only AFTER
   authentication, organization resolution and scope checks have already
   passed. A replayed response is returned to a caller who was authorized
   for this organization on THIS request; the record is tenant-scoped, so
   a key value presented by organization A can never match organization
   B's record, and can never be used to skip a capability recheck.

A client key is OPTIONAL. Without one, a mutation is simply a new
operation — documented plainly rather than implied to be safe.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ApiIdempotencyKey, utcnow
from app.services.organization_service import _as_uuid

logger = logging.getLogger("cyvrix.idempotency")

# Bounded retention. Replay protection must not grow without limit.
DEFAULT_IDEMPOTENCY_TTL_HOURS = 24
WEBHOOK_REPLAY_TTL_HOURS = 24 * 7

# Client keys are opaque, but bounded and charset-limited: they are stored
# and echoed in errors, so they must not be a smuggling channel.
MIN_KEY_LENGTH = 8
MAX_KEY_LENGTH = 200
_SAFE_KEY_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.:"
)

OUTCOME_ACQUIRED = "ACQUIRED"
OUTCOME_REPLAY = "REPLAY"
OUTCOME_CONFLICT = "CONFLICT"
OUTCOME_IN_PROGRESS = "IN_PROGRESS"


class IdempotencyError(Exception):
    """A refusal raised by the idempotency layer (fail closed)."""

    def __init__(self, reason_code: str, detail: Optional[str] = None) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.detail = detail


class Reservation:
    """Result of attempting to claim an idempotency key."""

    __slots__ = ("outcome", "record", "status_code", "body")

    def __init__(
        self,
        outcome: str,
        record: Optional[ApiIdempotencyKey] = None,
        status_code: Optional[int] = None,
        body: Optional[dict] = None,
    ) -> None:
        self.outcome = outcome
        self.record = record
        self.status_code = status_code
        self.body = body

    @property
    def owned(self) -> bool:
        return self.outcome == OUTCOME_ACQUIRED


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    """Postgres may hand back a naive datetime; compare in UTC safely."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def validate_client_key(value: Optional[str]) -> Optional[str]:
    """Normalise a client-supplied idempotency key, or refuse it.

    Returns the trimmed key, or None when the caller supplied nothing.
    Raises when a key was supplied but is unusable — silently ignoring a
    malformed key would make a caller believe it had retry protection it
    does not have.
    """
    if value is None:
        return None
    stripped = value.strip()
    if stripped == "":
        return None
    if len(stripped) < MIN_KEY_LENGTH or len(stripped) > MAX_KEY_LENGTH:
        raise IdempotencyError("IDEMPOTENCY_KEY_INVALID")
    if not set(stripped) <= _SAFE_KEY_CHARS:
        raise IdempotencyError("IDEMPOTENCY_KEY_INVALID")
    return stripped


def canonical_request_digest(payload: Any) -> str:
    """Deterministic digest of a request body.

    Key order and whitespace must not change the digest, or the same
    logical request would look like a different one and be refused as a
    conflict. Values that are not JSON-serialisable are stringified
    deterministically rather than raising.
    """
    try:
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), default=str
        )
    except (TypeError, ValueError):
        canonical = json.dumps(str(payload), separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def reserve(
    db: AsyncSession,
    *,
    organization_id,
    scope: str,
    key_value: str,
    request_digest: str,
    api_key_prefix: Optional[str] = None,
    ttl_hours: int = DEFAULT_IDEMPOTENCY_TTL_HOURS,
) -> Reservation:
    """Claim `key_value` for `scope` within one organization.

    On OUTCOME_ACQUIRED the caller MUST call `complete()` after performing
    the effect, inside the same transaction, so the record and the effect
    commit together.
    """
    org_uuid = _as_uuid(organization_id)
    expires_at = utcnow() + timedelta(hours=ttl_hours)

    record = ApiIdempotencyKey(
        organization_id=org_uuid,
        scope=scope,
        key_value=key_value,
        request_digest=request_digest,
        state="IN_PROGRESS",
        actor_api_key_prefix=api_key_prefix,
        expires_at=expires_at,
    )

    try:
        # A savepoint contains the unique violation so the surrounding
        # transaction (and the caller's other pending work) survives.
        async with db.begin_nested():
            db.add(record)
            await db.flush()
        return Reservation(OUTCOME_ACQUIRED, record=record)
    except IntegrityError:
        pass

    existing = (
        await db.execute(
            select(ApiIdempotencyKey).where(
                ApiIdempotencyKey.organization_id == org_uuid,
                ApiIdempotencyKey.scope == scope,
                ApiIdempotencyKey.key_value == key_value,
            )
        )
    ).scalar_one_or_none()

    if existing is None:
        # The competing transaction rolled back after blocking us. The key
        # is free again; the caller may retry rather than be told its
        # request conflicted with nothing.
        raise IdempotencyError("IDEMPOTENCY_RETRY")

    if _aware(existing.expires_at) is not None and _aware(existing.expires_at) < utcnow():
        # Take over an expired record atomically: only one taker wins.
        claimed = await db.execute(
            update(ApiIdempotencyKey)
            # The ORM would otherwise try to evaluate this criteria in
            # Python against the identity-map object, where a naive
            # (SQLite) vs aware (Postgres) `expires_at` raises TypeError.
            # The database owns the comparison; we re-read the row after.
            .execution_options(synchronize_session=False)
            .where(
                ApiIdempotencyKey.id == existing.id,
                ApiIdempotencyKey.expires_at < utcnow(),
            )
            .values(
                request_digest=request_digest,
                state="IN_PROGRESS",
                response_status=None,
                response_body=None,
                completed_at=None,
                actor_api_key_prefix=api_key_prefix,
                expires_at=expires_at,
            )
        )
        if claimed.rowcount == 1:
            await db.refresh(existing)
            return Reservation(OUTCOME_ACQUIRED, record=existing)
        await db.refresh(existing)

    if existing.request_digest != request_digest:
        # Same key, different request: never answer with the other
        # request's result.
        return Reservation(OUTCOME_CONFLICT)

    if existing.state != "COMPLETED":
        # A concurrent request holds the key and has not finished. We do
        # NOT return a partial result.
        return Reservation(OUTCOME_IN_PROGRESS)

    return Reservation(
        OUTCOME_REPLAY,
        status_code=existing.response_status,
        body=existing.response_body,
    )


async def complete(
    db: AsyncSession,
    reservation: Reservation,
    *,
    status_code: int,
    body: Optional[dict],
) -> None:
    """Record the outcome so a later retry replays it instead of redoing it."""
    record = reservation.record
    if record is None:
        return
    record.state = "COMPLETED"
    record.response_status = status_code
    record.response_body = body
    record.completed_at = utcnow()
    await db.flush()


async def purge_expired(db: AsyncSession, *, limit: int = 500) -> int:
    """Delete expired records (bounded retention). Returns rows removed."""
    expired_ids = (
        await db.execute(
            select(ApiIdempotencyKey.id)
            .where(ApiIdempotencyKey.expires_at < utcnow())
            .limit(limit)
        )
    ).scalars().all()
    if not expired_ids:
        return 0
    await db.execute(
        delete(ApiIdempotencyKey).where(ApiIdempotencyKey.id.in_(expired_ids))
    )
    return len(expired_ids)
