"""CYVRIX V4.0 — organizations, memberships, invitations, policy.

Security properties (docs/v4-multitenancy.md, docs/v4-rbac.md):

- The organization is NEVER taken from a request field as authority; it is
  resolved server-side from the resource (installation → organization) or
  from an explicit capability-checked route parameter.
- Membership is server-side state. Only state=ACTIVE confers capabilities.
- Invitations are hashed, expiring, single-use and organization-bound.
- Policy is versioned; history is append-only via policy revisions.
- Last-owner protection makes an organization permanently unmanageable
  impossible.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    GithubInstallation,
    Organization,
    OrganizationInvitation,
    OrganizationMembership,
    OrganizationPolicyRevision,
    utcnow,
)
from app.services import v4_rbac as rbac


class OrgError(Exception):
    """An organization operation refused by a rule (fail closed)."""

    def __init__(self, reason_code: str, detail: Optional[str] = None) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.detail = detail


INVITATION_TTL_HOURS = 72

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(value: str) -> str:
    slug = _SLUG_RE.sub("-", (value or "").strip().lower()).strip("-")
    return slug[:48] or "org"


# ── Policy (closed-world, validated, versioned) ──────────────────────

ALLOWED_POLICY_KEYS = frozenset({
    "max_risk_level",
    "allowed_action_types",
    "require_second_approver",
    "require_verification",
    "max_concurrent_executions",
    "network_allowed",
})

_RISK_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def validate_policy(policy: object) -> dict:
    """Validate an organization policy. Unknown keys or bad values are
    refused (fail closed) rather than ignored."""
    if not isinstance(policy, dict):
        raise OrgError("INVALID_POLICY", "policy must be an object")
    unknown = set(policy) - ALLOWED_POLICY_KEYS
    if unknown:
        raise OrgError("INVALID_POLICY", f"unknown keys: {sorted(unknown)}")
    out: dict = {}
    if "max_risk_level" in policy:
        level = policy["max_risk_level"]
        if level not in _RISK_ORDER:
            raise OrgError("INVALID_POLICY", "invalid max_risk_level")
        out["max_risk_level"] = level
    if "allowed_action_types" in policy:
        types = policy["allowed_action_types"]
        if not isinstance(types, list) or not all(isinstance(t, str) for t in types):
            raise OrgError("INVALID_POLICY", "allowed_action_types must be a string list")
        out["allowed_action_types"] = sorted(set(types))
    for flag in ("require_second_approver", "require_verification", "network_allowed"):
        if flag in policy:
            if not isinstance(policy[flag], bool):
                raise OrgError("INVALID_POLICY", f"{flag} must be a boolean")
            out[flag] = policy[flag]
    if "max_concurrent_executions" in policy:
        value = policy["max_concurrent_executions"]
        if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > 100:
            raise OrgError("INVALID_POLICY", "max_concurrent_executions must be 1..100")
        out["max_concurrent_executions"] = value
    return out


class PolicyOverlay:
    """Deterministic organization-policy overlay evaluation.

    The overlay can only ADD constraints: the V3 policy engine remains the
    authority and a V3 DENY is always terminal. Precedence (Phase 12/13):

        GLOBAL (V3 policy)  →  ORGANIZATION (this)  →  ACTION

    A `False`/empty result is the safe default; an overlay never upgrades a
    decision.
    """

    def __init__(self, decision: str, reason_code: str) -> None:
        self.decision = decision  # "ALLOW" | "DENY"
        self.reason_code = reason_code

    @property
    def denied(self) -> bool:
        return self.decision == "DENY"


def evaluate_policy_overlay(
    policy: Optional[dict],
    *,
    risk_level: Optional[str] = None,
    action_type: Optional[str] = None,
) -> PolicyOverlay:
    """Evaluate only the deny-shaped org constraints. Missing policy → allow
    (no additional constraint); malformed policy → DENY (fail closed)."""
    if not policy:
        return PolicyOverlay("ALLOW", "NO_ORG_POLICY")
    if not isinstance(policy, dict):
        return PolicyOverlay("DENY", "ORG_POLICY_INVALID")

    max_risk = policy.get("max_risk_level")
    if max_risk:
        if risk_level is None:
            return PolicyOverlay("DENY", "ORG_POLICY_RISK_UNKNOWN")
        if _RISK_ORDER.get(str(risk_level).upper(), 99) > _RISK_ORDER.get(max_risk, -1):
            return PolicyOverlay("DENY", "ORG_POLICY_RISK_EXCEEDED")

    allowed = policy.get("allowed_action_types")
    if allowed is not None:
        if not isinstance(allowed, list):
            return PolicyOverlay("DENY", "ORG_POLICY_INVALID")
        if action_type is None or action_type not in allowed:
            return PolicyOverlay("DENY", "ORG_POLICY_ACTION_TYPE_NOT_ALLOWED")

    return PolicyOverlay("ALLOW", "ORG_POLICY_SATISFIED")


# ── Organization creation / lookup ───────────────────────────────────


async def _unique_slug(db: AsyncSession, base: str) -> str:
    base = slugify(base)
    for _ in range(50):
        candidate = f"{base}-{secrets.token_hex(3)}"
        exists = (
            await db.execute(select(Organization.id).where(Organization.slug == candidate))
        ).scalar_one_or_none()
        if exists is None:
            return candidate
    raise OrgError("SLUG_GENERATION_FAILED")


async def create_organization(
    db: AsyncSession, *, name: str, creator_user_id, is_personal: bool = False
) -> Organization:
    """Create an organization with the creator as its first ORG_OWNER and a
    versioned policy revision v1."""
    clean = (name or "").strip()
    if not clean or len(clean) > 120:
        raise OrgError("INVALID_ORGANIZATION_NAME")
    org = Organization(
        name=clean,
        slug=await _unique_slug(db, clean),
        state="ACTIVE",
        is_personal=is_personal,
        created_by=creator_user_id,
        policy={},
        policy_version=1,
    )
    db.add(org)
    await db.flush()
    db.add(OrganizationMembership(
        organization_id=org.id, user_id=creator_user_id,
        role=rbac.OrgRole.ORG_OWNER, state=rbac.MembershipState.ACTIVE,
    ))
    db.add(OrganizationPolicyRevision(
        organization_id=org.id, version=1, policy={}, changed_by=creator_user_id,
    ))
    await db.flush()
    return org


async def ensure_personal_organization(db: AsyncSession, *, user) -> Organization:
    """Idempotently provision the acting user's personal organization.

    Used on login/registration so every user has a valid organization
    context without granting any remediation authority."""
    existing = (
        await db.execute(
            select(Organization)
            .join(OrganizationMembership,
                  OrganizationMembership.organization_id == Organization.id)
            .where(
                OrganizationMembership.user_id == user.id,
                OrganizationMembership.state == rbac.MembershipState.ACTIVE,
                Organization.is_personal.is_(True),
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    return await create_organization(
        db, name="Personal", creator_user_id=user.id, is_personal=True
    )


async def get_organization(db: AsyncSession, org_id) -> Optional[Organization]:
    return (
        await db.execute(select(Organization).where(Organization.id == _as_uuid(org_id)))
    ).scalar_one_or_none()


# ── Membership ───────────────────────────────────────────────────────


def _as_uuid(value) -> Optional[UUID]:
    if value is None:
        return None
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None


async def get_membership(
    db: AsyncSession, *, org_id, user_id
) -> Optional[OrganizationMembership]:
    oid, uid = _as_uuid(org_id), _as_uuid(user_id)
    if oid is None or uid is None:
        return None
    return (
        await db.execute(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == oid,
                OrganizationMembership.user_id == uid,
            )
        )
    ).scalar_one_or_none()


async def list_memberships(db: AsyncSession, *, org_id) -> list[OrganizationMembership]:
    return list(
        (
            await db.execute(
                select(OrganizationMembership)
                .where(OrganizationMembership.organization_id == _as_uuid(org_id))
                .order_by(OrganizationMembership.created_at.asc())
            )
        ).scalars().all()
    )


async def active_org_ids(db: AsyncSession, *, user_id) -> list[UUID]:
    """Organization ids where the user has an ACTIVE membership."""
    uid = _as_uuid(user_id)
    if uid is None:
        return []
    rows = (
        await db.execute(
            select(OrganizationMembership.organization_id).where(
                OrganizationMembership.user_id == uid,
                OrganizationMembership.state == rbac.MembershipState.ACTIVE,
            )
        )
    ).scalars().all()
    return list(rows)


async def _fresh_actor_manage(db: AsyncSession, actor_membership: OrganizationMembership) -> OrganizationMembership:
    """Re-read the actor's membership AFTER taking the organization lock.

    Closes a TOCTOU: an actor demoted/suspended by a concurrent transaction
    must not be able to complete a management action with a stale role."""
    row = await db.get(OrganizationMembership, actor_membership.id)
    if row is None:
        raise OrgError("MEMBER_MANAGEMENT_NOT_PERMITTED")
    # The caller already loaded this row, so the identity map would return the
    # stale copy without a round trip: force a re-read of committed state.
    await db.refresh(row)
    if (
        row.state != rbac.MembershipState.ACTIVE
        or not rbac.membership_manageable_by(row.role)
    ):
        raise OrgError("MEMBER_MANAGEMENT_NOT_PERMITTED")
    return row


async def _lock_org(db: AsyncSession, *, org_id) -> None:
    """Serialize membership changes on the organization row.

    Last-owner protection is a read-then-write rule; without a lock two
    concurrent demotions could each observe 2 owners and both commit,
    leaving the organization with none. `SELECT ... FOR UPDATE` makes the
    rule atomic on PostgreSQL (SQLite ignores FOR UPDATE, and tests there
    are single-writer)."""
    await db.execute(
        select(Organization.id).where(Organization.id == _as_uuid(org_id)).with_for_update()
    )


async def _active_owner_count(db: AsyncSession, *, org_id) -> int:
    return int(
        (
            await db.execute(
                select(func.count()).select_from(OrganizationMembership).where(
                    OrganizationMembership.organization_id == _as_uuid(org_id),
                    OrganizationMembership.role == rbac.OrgRole.ORG_OWNER,
                    OrganizationMembership.state == rbac.MembershipState.ACTIVE,
                )
            )
        ).scalar()
        or 0
    )


async def change_member_role(
    db: AsyncSession, *, org_id, actor_membership: OrganizationMembership,
    target_user_id, new_role: str,
) -> OrganizationMembership:
    target = await get_membership(db, org_id=org_id, user_id=target_user_id)
    if target is None:
        raise OrgError("MEMBERSHIP_NOT_FOUND")
    await _lock_org(db, org_id=org_id)
    actor = await _fresh_actor_manage(db, actor_membership)
    owners = await _active_owner_count(db, org_id=org_id)
    try:
        rbac.assert_can_change_role(
            actor_role=actor.role, target_role=target.role,
            new_role=new_role, active_owner_count=owners,
        )
    except rbac.MembershipRuleError as exc:
        raise OrgError(str(exc))
    target.role = new_role
    target.updated_at = utcnow()
    await db.flush()
    return target


async def set_member_state(
    db: AsyncSession, *, org_id, actor_membership: OrganizationMembership,
    target_user_id, state: str,
) -> OrganizationMembership:
    """Suspend/reactivate a member. Removing (state=REMOVED) uses
    remove_member. Suspending the last active owner is refused."""
    if not rbac.is_valid_membership_state(state):
        raise OrgError("INVALID_MEMBERSHIP_STATE")
    target = await get_membership(db, org_id=org_id, user_id=target_user_id)
    if target is None:
        raise OrgError("MEMBERSHIP_NOT_FOUND")
    if state == rbac.MembershipState.ACTIVE:
        # Reactivation is a management action; verify the actor's CURRENT role
        # (a concurrently demoted actor must not retain management rights).
        await _fresh_actor_manage(db, actor_membership)
    else:
        await _lock_org(db, org_id=org_id)
        actor = await _fresh_actor_manage(db, actor_membership)
        owners = await _active_owner_count(db, org_id=org_id)
        try:
            rbac.assert_can_remove(
                actor_role=actor.role, target_role=target.role,
                active_owner_count=owners,
            )
        except rbac.MembershipRuleError as exc:
            raise OrgError(str(exc))
    target.state = state
    target.updated_at = utcnow()
    await db.flush()
    return target


async def remove_member(
    db: AsyncSession, *, org_id, actor_membership: OrganizationMembership,
    target_user_id,
) -> OrganizationMembership:
    return await set_member_state(
        db, org_id=org_id, actor_membership=actor_membership,
        target_user_id=target_user_id, state=rbac.MembershipState.REMOVED,
    )


# ── Invitations ──────────────────────────────────────────────────────


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def create_invitation(
    db: AsyncSession, *, org_id, actor_membership: OrganizationMembership,
    actor_user_id, email: Optional[str], role: str,
) -> tuple[OrganizationInvitation, str]:
    """Create a one-time invitation. Returns (row, plaintext_token).

    The plaintext is returned EXACTLY ONCE and never persisted or logged.
    """
    if not rbac.membership_manageable_by(actor_membership.role):
        raise OrgError("MEMBER_MANAGEMENT_NOT_PERMITTED")
    if not rbac.is_valid_role(role):
        raise OrgError("INVALID_ROLE")
    if role == rbac.OrgRole.ORG_OWNER and actor_membership.role != rbac.OrgRole.ORG_OWNER:
        raise OrgError("OWNER_CHANGE_REQUIRES_OWNER")
    clean_email = email.strip().lower() if email else None
    if clean_email is not None and ("@" not in clean_email or len(clean_email) > 320):
        raise OrgError("INVALID_INVITATION_EMAIL")

    token = secrets.token_urlsafe(32)
    invitation = OrganizationInvitation(
        organization_id=_as_uuid(org_id),
        email=clean_email,
        role=role,
        token_hash=_hash_token(token),
        created_by=actor_user_id,
        expires_at=utcnow() + timedelta(hours=INVITATION_TTL_HOURS),
    )
    db.add(invitation)
    await db.flush()
    return invitation, token


async def list_invitations(db: AsyncSession, *, org_id) -> list[OrganizationInvitation]:
    return list(
        (
            await db.execute(
                select(OrganizationInvitation)
                .where(OrganizationInvitation.organization_id == _as_uuid(org_id))
                .order_by(OrganizationInvitation.created_at.desc())
            )
        ).scalars().all()
    )


async def revoke_invitation(
    db: AsyncSession, *, org_id, actor_membership: OrganizationMembership,
    invitation_id,
) -> OrganizationInvitation:
    if not rbac.membership_manageable_by(actor_membership.role):
        raise OrgError("MEMBER_MANAGEMENT_NOT_PERMITTED")
    invitation = (
        await db.execute(
            select(OrganizationInvitation).where(
                OrganizationInvitation.id == _as_uuid(invitation_id),
                OrganizationInvitation.organization_id == _as_uuid(org_id),
            )
        )
    ).scalar_one_or_none()
    if invitation is None:
        raise OrgError("INVITATION_NOT_FOUND")
    if invitation.accepted_at is not None:
        raise OrgError("INVITATION_ALREADY_ACCEPTED")
    invitation.revoked_at = utcnow()
    await db.flush()
    return invitation


async def accept_invitation(
    db: AsyncSession, *, token: str, user
) -> OrganizationMembership:
    """Accept a one-time invitation for the authenticated user.

    Verifies: token hash exists, not revoked, not accepted, not expired, and
    the email binding (when set) matches the user's email. The invitation is
    then marked accepted in the same transaction as the membership write, so
    a replay finds it already consumed.
    """
    if not token or len(token) > 512:
        raise OrgError("INVITATION_INVALID")
    # SELECT ... FOR UPDATE serializes concurrent accepts of the same token:
    # without it two transactions could both observe accepted_at IS NULL and
    # both mint a membership (a replay). The lock makes single-use atomic.
    invitation = (
        await db.execute(
            select(OrganizationInvitation)
            .where(OrganizationInvitation.token_hash == _hash_token(token))
            .with_for_update()
        )
    ).scalar_one_or_none()
    if invitation is None:
        raise OrgError("INVITATION_INVALID")
    if invitation.revoked_at is not None:
        raise OrgError("INVITATION_REVOKED")
    if invitation.accepted_at is not None:
        raise OrgError("INVITATION_ALREADY_ACCEPTED")
    now = utcnow()
    expires = invitation.expires_at
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires is None or expires < now:
        raise OrgError("INVITATION_EXPIRED")
    if invitation.email and (user.email or "").lower() != invitation.email:
        raise OrgError("INVITATION_EMAIL_MISMATCH")

    membership = await get_membership(
        db, org_id=invitation.organization_id, user_id=user.id
    )
    if membership is None:
        membership = OrganizationMembership(
            organization_id=invitation.organization_id,
            user_id=user.id,
            role=invitation.role,
            state=rbac.MembershipState.ACTIVE,
        )
        db.add(membership)
    else:
        # Re-joining reactivates but never silently upgrades a higher role.
        membership.state = rbac.MembershipState.ACTIVE
        membership.updated_at = utcnow()
    invitation.accepted_at = now
    invitation.accepted_by_user_id = user.id
    await db.flush()
    return membership


# ── Policy updates ───────────────────────────────────────────────────


async def set_policy(
    db: AsyncSession, *, org_id, actor_membership: OrganizationMembership,
    actor_user_id, policy: object,
) -> Organization:
    if not rbac.role_has_capability(actor_membership.role, rbac.CAP_MANAGE_POLICY):
        raise OrgError("POLICY_MANAGEMENT_NOT_PERMITTED")
    org = await get_organization(db, org_id)
    if org is None:
        raise OrgError("ORGANIZATION_NOT_FOUND")
    validated = validate_policy(policy)
    org.policy = validated
    org.policy_version = int(org.policy_version or 1) + 1
    org.updated_at = utcnow()
    db.add(OrganizationPolicyRevision(
        organization_id=org.id, version=org.policy_version,
        policy=validated, changed_by=actor_user_id,
    ))
    await db.flush()
    return org
