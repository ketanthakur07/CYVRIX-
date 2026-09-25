"""CYVRIX V4.0 — tenant resolution + capability dependencies.

Everything here is SERVER-DERIVED. The client never supplies an
organization, role, or capability as authority:

    authenticated user
      → active membership (server state)
        → organization
          → resource ownership
            → capability

Routes take an organization id in the PATH only as a *selector*; it is
verified against the caller's membership before any work happens. A
non-member receives 404 (existence never confirmed).
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.database import get_db
from app.models import GithubInstallation, Organization, OrganizationMembership, User  # noqa: F401
from app.rate_limit import check_rate_limit
from app.services import api_key_service, organization_service, v4_rbac as rbac


async def rate_limit_org(request: Request, *, org_id, bucket: str, limit: int) -> None:
    """Organization-scoped rate limit (Phase 29/30). Fails closed."""
    allowed, _ = await check_rate_limit(f"org:{org_id}:{bucket}", limit, 3600)
    if not allowed:
        raise HTTPException(status_code=429, detail="ORG_RATE_LIMITED")


async def _load_membership(db: AsyncSession, user: User, organization_id):
    """Resolve the caller's ACTIVE membership AND the organization state in
    one query. A DELETED organization is indistinguishable from a
    non-existent one (404) even for its former members, so a deletion
    request cannot leave a still-usable tenant behind (Phase 33)."""
    row = (
        await db.execute(
            select(OrganizationMembership, Organization.state)
            .join(Organization, Organization.id == OrganizationMembership.organization_id)
            .where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.user_id == user.id,
            )
        )
    ).first()
    if row is None:
        # 404: never confirm that an organization exists to a non-member.
        raise HTTPException(status_code=404, detail="ORGANIZATION_NOT_FOUND")
    membership, org_state = row
    if membership.state != rbac.MembershipState.ACTIVE or org_state == "DELETED":
        raise HTTPException(status_code=404, detail="ORGANIZATION_NOT_FOUND")
    return membership


def require_org_capability(capability: str):
    """Dependency factory: caller must be an ACTIVE member with `capability`."""

    async def _dep(
        organization_id: UUID,
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> tuple[User, OrganizationMembership]:
        membership = await _load_membership(db, user, organization_id)
        if not rbac.member_has_capability(membership.role, membership.state, capability):
            raise HTTPException(status_code=403, detail="ORG_CAPABILITY_REQUIRED")
        return user, membership

    return _dep


def require_active_membership():
    """Dependency factory: caller must be any ACTIVE member."""

    async def _dep(
        organization_id: UUID,
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> tuple[User, OrganizationMembership]:
        membership = await _load_membership(db, user, organization_id)
        return user, membership

    return _dep


async def get_organization_or_404(
    db: AsyncSession, organization_id
) -> Organization:
    org = await organization_service.get_organization(db, organization_id)
    if org is None or org.state == "DELETED":
        raise HTTPException(status_code=404, detail="ORGANIZATION_NOT_FOUND")
    return org


# ── API key authentication (Phase 22–25) ─────────────────────────────


async def api_key_auth(
    authorization: str = Header(default=""),
    db: AsyncSession = Depends(get_db),
):
    """Authenticate a bearer API key and return the key row.

    The organization is derived from the KEY, never from the request. A
    missing/invalid/revoked/expired key is 401; a key lacking the required
    scope is 403.
    """
    token = (authorization or "").removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="API_KEY_REQUIRED")
    key = await api_key_service.authenticate_api_key(db, token)
    if key is None:
        raise HTTPException(status_code=401, detail="API_KEY_INVALID")
    return key


def require_api_scope(scope: str):
    async def _dep(key=Depends(api_key_auth)):
        if not api_key_service.key_has_scope(key, scope):
            raise HTTPException(status_code=403, detail="API_SCOPE_REQUIRED")
        return key

    return _dep


# ── Progressive V3-route adoption helper ─────────────────────────────

def owned_installation_condition(user_id):
    """SQL predicate for V3 ownership migrated to V4 tenancy.

    A resource is visible to the caller when EITHER:
      - the caller is the legacy installation owner (`user_id`), OR
      - the caller has an ACTIVE membership in the installation's
        organization.

    This is a strict superset of the V3 predicate, so it can only ADD
    access for genuine active members — it never grants cross-organization
    access (membership is server-derived). It is provided so V3 routes can
    be migrated incrementally; mutation routes MUST additionally check a
    capability before adopting it.
    """
    active_org_ids = select(OrganizationMembership.organization_id).where(
        OrganizationMembership.user_id == user_id,
        OrganizationMembership.state == rbac.MembershipState.ACTIVE,
    )
    return or_(
        GithubInstallation.user_id == user_id,
        GithubInstallation.organization_id.in_(active_org_ids),
    )


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
