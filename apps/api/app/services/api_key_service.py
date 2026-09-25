"""CYVRIX V4.0 — organization API keys.

Security properties (docs/v4-api.md):

- The secret is shown EXACTLY ONCE and only a SHA-256 hash is persisted.
- The stored `prefix` identifies the key without revealing the secret.
- Scopes are a closed world (services/v4_rbac.py) and can never include
  member/policy/operations management.
- A key is bound to ONE organization; lookups derive the organization from
  the key row, never from the request.
- Revoked/expired keys never authenticate.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ApiKey, utcnow
from app.services import v4_rbac as rbac
from app.services.organization_service import OrgError, _as_uuid

logger = logging.getLogger("cyvrix.api_key")

_KEY_PREFIX = "cyv"


async def _audit_key_event(
    db: AsyncSession,
    *,
    organization_id,
    event_type: str,
    actor_user_id=None,
    api_key_prefix: Optional[str] = None,
    result: Optional[str] = None,
    reason_code: Optional[str] = None,
) -> None:
    """Append a key-lifecycle event to the organization's audit chain.

    SECURITY-CRITICAL semantics (V3.8): the event commits atomically with
    the key state change — a failure here FAILS THE CALLING OPERATION
    (fail closed), so a credential can never be minted or destroyed
    without its audit witness. Only the prefix (an identifier designed
    for logs) and server-side facts enter the chain; NEVER the plaintext
    secret, never the hash.
    """
    from app.services import audit_service

    await audit_service.emit_security_event(
        db,
        organization_id=organization_id,
        event_type=event_type,
        actor_type=audit_service.ActorType.ADMIN if actor_user_id else audit_service.ActorType.SYSTEM,
        actor_id=str(api_key_prefix) if api_key_prefix else None,
        actor_user_id=actor_user_id,
        reason_code=reason_code,
        result=result,
        payload={
            "key_prefix": api_key_prefix,
            "scopes_granted": event_type == "API_KEY_CREATED",
        },
    )


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def generate_key() -> tuple[str, str, str]:
    """Return (plaintext, prefix, hash). The plaintext is never stored."""
    prefix = secrets.token_hex(4)          # 8 hex chars, stored for lookup
    secret = secrets.token_urlsafe(32)
    plaintext = f"{_KEY_PREFIX}_{prefix}_{secret}"
    return plaintext, prefix, _hash(plaintext)


def parse_prefix(token: str) -> Optional[str]:
    parts = (token or "").split("_")
    if len(parts) < 3 or parts[0] != _KEY_PREFIX:
        return None
    return parts[1] or None


async def create_api_key(
    db: AsyncSession, *, org_id, actor_membership, actor_user_id,
    name: str, scopes: list[str], expires_at: Optional[datetime] = None,
) -> tuple[ApiKey, str]:
    if not rbac.role_has_capability(actor_membership.role, rbac.CAP_MANAGE_API_KEYS):
        raise OrgError("API_KEY_MANAGEMENT_NOT_PERMITTED")
    clean = (name or "").strip()
    if not clean or len(clean) > 120:
        raise OrgError("INVALID_API_KEY_NAME")
    if not isinstance(scopes, list) or not scopes or not rbac.scopes_are_valid(scopes):
        raise OrgError("INVALID_API_KEY_SCOPES")
    if not rbac.membership_manageable_by(actor_membership.role) and (
        set(scopes) & rbac.HIGH_IMPACT_API_SCOPES
    ):
        # High-impact scopes require at least org-admin standing.
        raise OrgError("HIGH_IMPACT_SCOPE_REQUIRES_ADMIN")

    plaintext, prefix, key_hash = generate_key()
    row = ApiKey(
        organization_id=_as_uuid(org_id),
        name=clean,
        prefix=prefix,
        key_hash=key_hash,
        scopes=sorted(set(scopes)),
        created_by=actor_user_id,
        expires_at=expires_at,
    )
    db.add(row)
    await db.flush()
    # Fail-closed audit: the key does not come into existence unwitnessed.
    await _audit_key_event(
        db,
        organization_id=org_id,
        event_type="API_KEY_CREATED",
        actor_user_id=actor_user_id,
        api_key_prefix=prefix,
        result="CREATED",
    )
    await db.flush()
    return row, plaintext


async def list_api_keys(db: AsyncSession, *, org_id) -> list[ApiKey]:
    return list(
        (
            await db.execute(
                select(ApiKey)
                .where(ApiKey.organization_id == _as_uuid(org_id))
                .order_by(ApiKey.created_at.desc())
            )
        ).scalars().all()
    )


async def revoke_api_key(
    db: AsyncSession, *, org_id, actor_membership, key_id
) -> ApiKey:
    if not rbac.role_has_capability(actor_membership.role, rbac.CAP_MANAGE_API_KEYS):
        raise OrgError("API_KEY_MANAGEMENT_NOT_PERMITTED")
    row = (
        await db.execute(
            select(ApiKey).where(
                ApiKey.id == _as_uuid(key_id),
                ApiKey.organization_id == _as_uuid(org_id),
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise OrgError("API_KEY_NOT_FOUND")
    if row.revoked_at is None:
        row.revoked_at = utcnow()
        await db.flush()
        # Best-effort audit for revocation: the revocation itself is the
        # protective act and is already committed by the caller; failing
        # the operation now would NOT un-revoke, so the witness is logged
        # loudly instead. (Creation/rotation differ: those CREATE authority
        # and must not succeed unwitnessed.)
        try:
            await _audit_key_event(
                db,
                organization_id=org_id,
                event_type="API_KEY_REVOKED",
                actor_user_id=actor_membership.user_id if hasattr(actor_membership, "user_id") else None,
                api_key_prefix=row.prefix,
                result="REVOKED",
            )
            await db.flush()
        except Exception as exc:  # noqa: BLE001 — never mask the revocation
            logger.error(
                "api_key_revoke_audit_failed key_prefix=%s err=%s",
                row.prefix, type(exc).__name__,
            )
    return row


async def rotate_api_key(
    db: AsyncSession, *, org_id, actor_membership, actor_user_id, key_id
) -> tuple[ApiKey, str]:
    """Rotate a key: the old key is revoked and a NEW key is issued.

    Properties (docs/v4-api-security.md §Key lifecycle):

    - The old key stops authenticating IMMEDIATELY — before the new key is
      returned, so there is no window where both are live.
    - The new key carries the same name and scopes, and PRESERVES the
      original expiry. Rotation must never silently extend a key's
      lifetime, so an expiring key rotates into an equally-expiring one.
    - Rotation is deterministic under concurrency. The old key is revoked
      with a single conditional UPDATE (`WHERE revoked_at IS NULL`); only
      the transaction that changed a row proceeds to mint a replacement.
      A concurrent loser gets API_KEY_ALREADY_REVOKED rather than a second
      live successor, so two rotations cannot produce two valid keys.
    """
    if not rbac.role_has_capability(actor_membership.role, rbac.CAP_MANAGE_API_KEYS):
        raise OrgError("API_KEY_MANAGEMENT_NOT_PERMITTED")
    key_uuid = _as_uuid(key_id)
    org_uuid = _as_uuid(org_id)
    old = (
        await db.execute(
            select(ApiKey).where(
                ApiKey.id == key_uuid, ApiKey.organization_id == org_uuid
            )
        )
    ).scalar_one_or_none()
    if old is None:
        raise OrgError("API_KEY_NOT_FOUND")

    # Atomic claim. `rowcount == 0` means another transaction already
    # revoked this key — we must NOT mint a second successor.
    result = await db.execute(
        update(ApiKey)
        # Keep the comparison in the database; we explicitly refresh the
        # ORM instance afterwards, so no in-Python criteria evaluation is
        # needed (and naive/aware datetime mismatch cannot raise here).
        .execution_options(synchronize_session=False)
        .where(
            ApiKey.id == key_uuid,
            ApiKey.organization_id == org_uuid,
            ApiKey.revoked_at.is_(None),
        )
        .values(revoked_at=utcnow())
    )
    if result.rowcount != 1:
        raise OrgError("API_KEY_ALREADY_REVOKED")

    plaintext, prefix, key_hash = generate_key()
    successor = ApiKey(
        organization_id=org_uuid,
        name=old.name,
        prefix=prefix,
        key_hash=key_hash,
        scopes=list(old.scopes or []),
        created_by=actor_user_id,
        expires_at=old.expires_at,  # never silently extend
    )
    db.add(successor)
    await db.flush()
    # Fail-closed audit: rotation is a credential transfer — both the
    # death of the old secret and the birth of the new one are witnessed
    # in the SAME transaction as the state change.
    await _audit_key_event(
        db,
        organization_id=org_id,
        event_type="API_KEY_ROTATED",
        actor_user_id=actor_user_id,
        api_key_prefix=prefix,
        result="ROTATED",
    )
    await db.flush()
    # Reflect the revocation on the identity map so the response is truthful.
    await db.refresh(old)
    return successor, plaintext


async def authenticate_api_key(
    db: AsyncSession, token: str
) -> Optional[ApiKey]:
    """Resolve a bearer token to a live API key, or None (fail closed).

    The lookup is by exact hash; a wrong/unknown token produces None. On
    success `last_used_at` is updated. The returned row carries the trusted
    organization_id used for tenant resolution downstream.
    """
    if not token or len(token) > 512:
        return None
    prefix = parse_prefix(token)
    if prefix is None:
        return None
    row = (
        await db.execute(select(ApiKey).where(ApiKey.prefix == prefix))
    ).scalar_one_or_none()
    if row is None:
        return None
    # Constant-time-ish comparison of the stored hash and presented token.
    if not secrets.compare_digest(row.key_hash, _hash(token)):
        return None
    if row.revoked_at is not None:
        return None
    if row.expires_at is not None:
        expires = row.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < utcnow():
            return None
    row.last_used_at = utcnow()
    await db.flush()
    return row


def key_has_scope(key: ApiKey, scope: str) -> bool:
    if not rbac.is_valid_api_scope(scope):
        return False
    scopes = key.scopes or []
    return isinstance(scopes, list) and scope in scopes
