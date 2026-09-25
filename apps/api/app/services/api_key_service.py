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
import secrets
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ApiKey, utcnow
from app.services import v4_rbac as rbac
from app.services.organization_service import OrgError, _as_uuid

_KEY_PREFIX = "cyv"


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
    return row


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
