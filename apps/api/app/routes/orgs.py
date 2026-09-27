"""CYVRIX V4.0 — organization management routes.

Every route resolves the caller's ACTIVE membership server-side; an
organization id in the path is only a selector and a non-member gets 404.
Capabilities are checked per route. No route here can approve, authorize,
or execute a remediation — organization administration never bypasses the
V3 security chain.

This is NOT the public API: public, API-key-authenticated access under
/api/v1 is deliberately narrower (see docs/v4-api.md).
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.database import get_db
from app.models import Organization, OrganizationMembership, User
from app.services import api_key_service, organization_service, v4_rbac as rbac
from app.services.organization_service import OrgError
from app.services.org_auth import (
    get_organization_or_404,
    rate_limit_org,
    require_active_membership,
    require_org_capability,
)

logger = logging.getLogger("cyvrix.org_routes")
router = APIRouter(prefix="/api/orgs", tags=["organizations"])
invitation_router = APIRouter(prefix="/api", tags=["organizations"])

_MANAGE = rbac.CAP_MANAGE_MEMBERS


def _org_error(exc: OrgError) -> HTTPException:
    conflict = {
        "LAST_OWNER_PROTECTED", "INVITATION_ALREADY_ACCEPTED",
        "INVITATION_REVOKED", "INVITATION_EXPIRED", "MEMBERSHIP_NOT_FOUND",
        "ORGANIZATION_NOT_FOUND", "API_KEY_NOT_FOUND", "INVITATION_NOT_FOUND",
        # Rotation of an already-revoked key is a state conflict, not a
        # malformed request: a concurrent rotation loser must be told it
        # lost the race, deterministically.
        "API_KEY_ALREADY_REVOKED",
    }
    status_code = 409 if exc.reason_code in conflict else 400
    if exc.reason_code.endswith("NOT_PERMITTED") or exc.reason_code in (
        "OWNER_CHANGE_REQUIRES_OWNER", "HIGH_IMPACT_SCOPE_REQUIRES_ADMIN",
    ):
        status_code = 403
    return HTTPException(
        status_code=status_code,
        detail={"reason_code": exc.reason_code, "message": exc.detail or exc.reason_code},
    )


# ── Schemas (response-only; no authority fields exist) ───────────────


class OrganizationOut(BaseModel):
    id: str
    name: str
    slug: str
    state: str
    is_personal: bool
    policy_version: int
    role: Optional[str] = None
    membership_state: Optional[str] = None
    created_at: Optional[str] = None


class MemberOut(BaseModel):
    user_id: str
    email: Optional[str] = None
    role: str
    state: str
    created_at: Optional[str] = None


class InvitationOut(BaseModel):
    id: str
    email: Optional[str] = None
    role: str
    expires_at: Optional[str] = None
    accepted_at: Optional[str] = None
    revoked_at: Optional[str] = None
    created_at: Optional[str] = None


class InvitationCreated(InvitationOut):
    token: str  # plaintext, returned exactly once


class RoleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str = Field(min_length=3, max_length=32)


class StateUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    state: str = Field(min_length=3, max_length=16)


class OrganizationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)


class InvitationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: Optional[str] = Field(default=None, max_length=320)
    role: str = Field(default="VIEWER", max_length=32)


class InvitationAccept(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=8, max_length=512)


class PolicyOut(BaseModel):
    policy: dict
    version: int


class PolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy: dict


class ApiKeyOut(BaseModel):
    id: str
    name: str
    prefix: str
    scopes: list[str]
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    last_used_at: Optional[str] = None
    revoked_at: Optional[str] = None


class ApiKeyCreated(ApiKeyOut):
    secret: str  # plaintext, returned exactly once


class ApiKeyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    scopes: list[str] = Field(min_length=1)
    expires_at: Optional[datetime] = None


class CapabilitiesOut(BaseModel):
    organization_id: str
    role: str
    membership_state: str
    capabilities: list[str]


def _iso(value) -> Optional[str]:
    return value.isoformat() if value else None


def _org_out(org: Organization, membership: Optional[OrganizationMembership]) -> OrganizationOut:
    return OrganizationOut(
        id=str(org.id), name=org.name, slug=org.slug, state=org.state,
        is_personal=bool(org.is_personal),
        policy_version=int(org.policy_version or 1),
        role=membership.role if membership else None,
        membership_state=membership.state if membership else None,
        created_at=_iso(org.created_at),
    )


# ── Organization list / create / detail ──────────────────────────────


@router.get("", response_model=list[OrganizationOut])
async def list_organizations(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Organizations the caller has any recorded membership in (active
    memberships are marked; non-active ones carry their state)."""
    rows = (
        await db.execute(
            select(Organization, OrganizationMembership)
            .join(OrganizationMembership,
                  OrganizationMembership.organization_id == Organization.id)
            .where(OrganizationMembership.user_id == user.id,
                   Organization.state != "DELETED")
            .order_by(Organization.created_at.asc())
        )
    ).all()
    return [_org_out(org, membership) for org, membership in rows]


@router.post("", response_model=OrganizationOut, status_code=201)
async def create_organization(
    body: OrganizationCreate,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        org = await organization_service.create_organization(
            db, name=body.name, creator_user_id=user.id
        )
        await db.commit()
    except OrgError as exc:
        await db.rollback()
        raise _org_error(exc)
    membership = await organization_service.get_membership(
        db, org_id=org.id, user_id=user.id
    )
    return _org_out(org, membership)


@router.get("/{organization_id}", response_model=OrganizationOut)
async def get_organization(
    organization_id: UUID,
    request: Request,
    ctx=Depends(require_active_membership()),
    db: AsyncSession = Depends(get_db),
):
    user, membership = ctx
    await rate_limit_org(request, org_id=organization_id, bucket="org-read", limit=600)
    org = await get_organization_or_404(db, organization_id)
    return _org_out(org, membership)


@router.get("/{organization_id}/capabilities", response_model=CapabilitiesOut)
async def get_capabilities(
    organization_id: UUID,
    request: Request,
    ctx=Depends(require_active_membership()),
):
    user, membership = ctx
    caps = sorted(rbac.effective_capabilities(membership.role, membership.state))
    return CapabilitiesOut(
        organization_id=str(organization_id),
        role=membership.role,
        membership_state=membership.state,
        capabilities=caps,
    )


# ── Members ──────────────────────────────────────────────────────────


@router.get("/{organization_id}/members", response_model=list[MemberOut])
async def list_members(
    organization_id: UUID,
    request: Request,
    ctx=Depends(require_active_membership()),
    db: AsyncSession = Depends(get_db),
):
    await rate_limit_org(request, org_id=organization_id, bucket="members-read", limit=600)
    memberships = await organization_service.list_memberships(db, org_id=organization_id)
    emails = {
        str(u.id): u.email
        for u in (
            await db.execute(
                select(User).where(User.id.in_([m.user_id for m in memberships]))
            )
        ).scalars().all()
    } if memberships else {}
    return [
        MemberOut(
            user_id=str(m.user_id),
            email=emails.get(str(m.user_id)),
            role=m.role,
            state=m.state,
            created_at=_iso(m.created_at),
        )
        for m in memberships
    ]


@router.patch("/{organization_id}/members/{user_id}", response_model=MemberOut)
async def change_member_role(
    organization_id: UUID,
    user_id: UUID,
    body: RoleUpdate,
    request: Request,
    ctx=Depends(require_org_capability(_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    actor, actor_membership = ctx
    await rate_limit_org(request, org_id=organization_id, bucket="members-write", limit=120)
    try:
        membership = await organization_service.change_member_role(
            db, org_id=organization_id, actor_membership=actor_membership,
            target_user_id=user_id, new_role=body.role,
        )
        await db.commit()
    except OrgError as exc:
        await db.rollback()
        raise _org_error(exc)
    target = await db.get(User, membership.user_id)
    return MemberOut(
        user_id=str(membership.user_id), email=target.email if target else None,
        role=membership.role, state=membership.state, created_at=_iso(membership.created_at),
    )


@router.post("/{organization_id}/members/{user_id}/state", response_model=MemberOut)
async def change_member_state(
    organization_id: UUID,
    user_id: UUID,
    body: StateUpdate,
    request: Request,
    ctx=Depends(require_org_capability(_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    actor, actor_membership = ctx
    await rate_limit_org(request, org_id=organization_id, bucket="members-write", limit=120)
    try:
        if body.state == rbac.MembershipState.REMOVED:
            membership = await organization_service.remove_member(
                db, org_id=organization_id, actor_membership=actor_membership,
                target_user_id=user_id,
            )
        else:
            membership = await organization_service.set_member_state(
                db, org_id=organization_id, actor_membership=actor_membership,
                target_user_id=user_id, state=body.state,
            )
        await db.commit()
    except OrgError as exc:
        await db.rollback()
        raise _org_error(exc)
    target = await db.get(User, membership.user_id)
    return MemberOut(
        user_id=str(membership.user_id), email=target.email if target else None,
        role=membership.role, state=membership.state, created_at=_iso(membership.created_at),
    )


# ── Invitations ──────────────────────────────────────────────────────


@router.get("/{organization_id}/invitations", response_model=list[InvitationOut])
async def list_invitations(
    organization_id: UUID,
    request: Request,
    ctx=Depends(require_org_capability(_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    await rate_limit_org(request, org_id=organization_id, bucket="invites", limit=120)
    rows = await organization_service.list_invitations(db, org_id=organization_id)
    return [
        InvitationOut(
            id=str(i.id), email=i.email, role=i.role,
            expires_at=_iso(i.expires_at), accepted_at=_iso(i.accepted_at),
            revoked_at=_iso(i.revoked_at), created_at=_iso(i.created_at),
        )
        for i in rows
    ]


@router.post("/{organization_id}/invitations", response_model=InvitationCreated, status_code=201)
async def create_invitation(
    organization_id: UUID,
    body: InvitationCreate,
    request: Request,
    ctx=Depends(require_org_capability(_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    actor, actor_membership = ctx
    await rate_limit_org(request, org_id=organization_id, bucket="invites", limit=120)
    try:
        invitation, token = await organization_service.create_invitation(
            db, org_id=organization_id, actor_membership=actor_membership,
            actor_user_id=actor.id, email=body.email, role=body.role,
        )
        await db.commit()
    except OrgError as exc:
        await db.rollback()
        raise _org_error(exc)
    return InvitationCreated(
        id=str(invitation.id), email=invitation.email, role=invitation.role,
        expires_at=_iso(invitation.expires_at), created_at=_iso(invitation.created_at),
        token=token,
    )


@router.post("/{organization_id}/invitations/{invitation_id}/revoke",
             response_model=InvitationOut)
async def revoke_invitation(
    organization_id: UUID,
    invitation_id: UUID,
    request: Request,
    ctx=Depends(require_org_capability(_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    actor, actor_membership = ctx
    await rate_limit_org(request, org_id=organization_id, bucket="invites", limit=120)
    try:
        invitation = await organization_service.revoke_invitation(
            db, org_id=organization_id, actor_membership=actor_membership,
            invitation_id=invitation_id,
        )
        await db.commit()
    except OrgError as exc:
        await db.rollback()
        raise _org_error(exc)
    return InvitationOut(
        id=str(invitation.id), email=invitation.email, role=invitation.role,
        expires_at=_iso(invitation.expires_at), accepted_at=_iso(invitation.accepted_at),
        revoked_at=_iso(invitation.revoked_at), created_at=_iso(invitation.created_at),
    )


@invitation_router.post("/invitations/accept", response_model=OrganizationOut)
async def accept_invitation(
    body: InvitationAccept,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Accept a one-time organization invitation. The token IS the authority
    here (it was issued by a member); it is hashed, single-use, expiring and
    email-bound."""
    try:
        membership = await organization_service.accept_invitation(
            db, token=body.token, user=user
        )
        await db.commit()
    except OrgError as exc:
        await db.rollback()
        raise _org_error(exc)
    org = await organization_service.get_organization(db, membership.organization_id)
    if org is None:
        raise HTTPException(status_code=404, detail="ORGANIZATION_NOT_FOUND")
    return _org_out(org, membership)


# ── Policy ───────────────────────────────────────────────────────────


@router.get("/{organization_id}/policy", response_model=PolicyOut)
async def get_policy(
    organization_id: UUID,
    request: Request,
    ctx=Depends(require_active_membership()),
    db: AsyncSession = Depends(get_db),
):
    await rate_limit_org(request, org_id=organization_id, bucket="policy-read", limit=300)
    org = await get_organization_or_404(db, organization_id)
    return PolicyOut(policy=org.policy or {}, version=int(org.policy_version or 1))


@router.put("/{organization_id}/policy", response_model=PolicyOut)
async def update_policy(
    organization_id: UUID,
    body: PolicyUpdate,
    request: Request,
    ctx=Depends(require_org_capability(rbac.CAP_MANAGE_POLICY)),
    db: AsyncSession = Depends(get_db),
):
    actor, actor_membership = ctx
    await rate_limit_org(request, org_id=organization_id, bucket="policy-write", limit=60)
    try:
        org = await organization_service.set_policy(
            db, org_id=organization_id, actor_membership=actor_membership,
            actor_user_id=actor.id, policy=body.policy,
        )
        await db.commit()
    except OrgError as exc:
        await db.rollback()
        raise _org_error(exc)
    return PolicyOut(policy=org.policy or {}, version=int(org.policy_version or 1))


# ── API keys ─────────────────────────────────────────────────────────


@router.get("/{organization_id}/api-keys", response_model=list[ApiKeyOut])
async def list_api_keys(
    organization_id: UUID,
    request: Request,
    ctx=Depends(require_org_capability(rbac.CAP_MANAGE_API_KEYS)),
    db: AsyncSession = Depends(get_db),
):
    await rate_limit_org(request, org_id=organization_id, bucket="keys", limit=120)
    rows = await api_key_service.list_api_keys(db, org_id=organization_id)
    return [
        ApiKeyOut(
            id=str(k.id), name=k.name, prefix=k.prefix, scopes=list(k.scopes or []),
            created_at=_iso(k.created_at), expires_at=_iso(k.expires_at),
            last_used_at=_iso(k.last_used_at), revoked_at=_iso(k.revoked_at),
        )
        for k in rows
    ]


@router.post("/{organization_id}/api-keys", response_model=ApiKeyCreated, status_code=201)
async def create_api_key(
    organization_id: UUID,
    body: ApiKeyCreate,
    request: Request,
    ctx=Depends(require_org_capability(rbac.CAP_MANAGE_API_KEYS)),
    db: AsyncSession = Depends(get_db),
):
    actor, actor_membership = ctx
    await rate_limit_org(request, org_id=organization_id, bucket="keys", limit=60)
    try:
        row, secret = await api_key_service.create_api_key(
            db, org_id=organization_id, actor_membership=actor_membership,
            actor_user_id=actor.id, name=body.name, scopes=body.scopes,
            expires_at=body.expires_at,
        )
        await db.commit()
    except OrgError as exc:
        await db.rollback()
        raise _org_error(exc)
    return ApiKeyCreated(
        id=str(row.id), name=row.name, prefix=row.prefix, scopes=list(row.scopes or []),
        created_at=_iso(row.created_at), expires_at=_iso(row.expires_at), secret=secret,
    )


@router.post("/{organization_id}/api-keys/{key_id}/revoke", response_model=ApiKeyOut)
async def revoke_api_key(
    organization_id: UUID,
    key_id: UUID,
    request: Request,
    ctx=Depends(require_org_capability(rbac.CAP_MANAGE_API_KEYS)),
    db: AsyncSession = Depends(get_db),
):
    actor, actor_membership = ctx
    await rate_limit_org(request, org_id=organization_id, bucket="keys", limit=60)
    try:
        row = await api_key_service.revoke_api_key(
            db, org_id=organization_id, actor_membership=actor_membership, key_id=key_id,
        )
        await db.commit()
    except OrgError as exc:
        await db.rollback()
        raise _org_error(exc)
    return ApiKeyOut(
        id=str(row.id), name=row.name, prefix=row.prefix, scopes=list(row.scopes or []),
        created_at=_iso(row.created_at), expires_at=_iso(row.expires_at),
        last_used_at=_iso(row.last_used_at), revoked_at=_iso(row.revoked_at),
    )


@router.post("/{organization_id}/api-keys/{key_id}/rotate",
             response_model=ApiKeyCreated, status_code=201)
async def rotate_api_key(
    organization_id: UUID,
    key_id: UUID,
    request: Request,
    ctx=Depends(require_org_capability(rbac.CAP_MANAGE_API_KEYS)),
    db: AsyncSession = Depends(get_db),
):
    """Rotate a key: the old key stops working immediately and a new secret
    is issued once. The successor keeps the same name, scopes and expiry —
    rotation never silently extends a key's lifetime."""
    actor, actor_membership = ctx
    await rate_limit_org(request, org_id=organization_id, bucket="keys", limit=60)
    try:
        row, secret = await api_key_service.rotate_api_key(
            db, org_id=organization_id, actor_membership=actor_membership,
            actor_user_id=actor.id, key_id=key_id,
        )
        await db.commit()
    except OrgError as exc:
        await db.rollback()
        raise _org_error(exc)
    # V4.2 completion: fan the REAL rotation event out to subscribed
    # webhook receivers (prefix + key id only — never the new secret).
    try:
        from app.services.outbound_event_emitter import emit_api_key_rotated
        await emit_api_key_rotated(
            organization_id=organization_id,
            api_key_id=str(row.id),
            key_prefix=row.prefix,
        )
    except Exception:  # noqa: BLE001 — fan-out must not break rotation
        pass
    return ApiKeyCreated(
        id=str(row.id), name=row.name, prefix=row.prefix, scopes=list(row.scopes or []),
        created_at=_iso(row.created_at), expires_at=_iso(row.expires_at), secret=secret,
    )
