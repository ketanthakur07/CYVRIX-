"""CYVRIX V4.0 — Organization RBAC (roles → capabilities).

Design rules (docs/v4-rbac.md is normative):

- A ROLE is a named bundle of CAPABILITIES. A capability is the unit of
  authorization; roles are never the only primitive.
- Capabilities are SERVER-DERIVED. No client field can select a role or a
  capability.
- Organization membership is NOT execution authority. Holding
  APPROVE_ACTION / AUTHORIZE_EXECUTION means the member may *invoke* the
  V3.2/V3.3 gates — every V3 control (digest, policy, kill switch,
  approval validity, sandbox, verification) still applies in full.
- There is deliberately no ALL / SUPERUSER capability and no capability
  that bypasses the V3 authorization chain.
- Last-owner protection is a pure rule here and enforced transactionally
  in organization_service.
"""
from __future__ import annotations

from typing import Iterable, Optional


class OrgRole:
    ORG_OWNER = "ORG_OWNER"
    ORG_ADMIN = "ORG_ADMIN"
    SECURITY_ENGINEER = "SECURITY_ENGINEER"
    DEVELOPER = "DEVELOPER"
    AUDITOR = "AUDITOR"
    VIEWER = "VIEWER"


ALL_ROLES: frozenset[str] = frozenset({
    OrgRole.ORG_OWNER, OrgRole.ORG_ADMIN, OrgRole.SECURITY_ENGINEER,
    OrgRole.DEVELOPER, OrgRole.AUDITOR, OrgRole.VIEWER,
})


class MembershipState:
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    INVITED = "INVITED"
    REMOVED = "REMOVED"


ALL_MEMBERSHIP_STATES: frozenset[str] = frozenset({
    MembershipState.ACTIVE, MembershipState.SUSPENDED,
    MembershipState.INVITED, MembershipState.REMOVED,
})

# Only ACTIVE membership confers any authority. INVITED has not accepted;
# SUSPENDED and REMOVED are inert. This is intentional and fail-closed.
AUTHORIZING_STATES: frozenset[str] = frozenset({MembershipState.ACTIVE})


# ── Capabilities (closed world) ──────────────────────────────────────

# Read
CAP_VIEW_REPOSITORIES = "VIEW_REPOSITORIES"
CAP_VIEW_FINDINGS = "VIEW_FINDINGS"
CAP_VIEW_ACTIONS = "VIEW_ACTIONS"
CAP_VIEW_EXECUTIONS = "VIEW_EXECUTIONS"

# Remediation workflow (invoke the V3 gates — never bypass them)
CAP_CREATE_ACTION = "CREATE_ACTION"
CAP_APPROVE_ACTION = "APPROVE_ACTION"
CAP_AUTHORIZE_EXECUTION = "AUTHORIZE_EXECUTION"
CAP_START_REMEDIATION = "START_REMEDIATION"
CAP_START_VERIFICATION = "START_VERIFICATION"
CAP_START_ROLLBACK = "START_ROLLBACK"

# Audit (V3.8 capabilities, re-expressed at the org layer)
CAP_VIEW_AUDIT = "VIEW_AUDIT"
CAP_VERIFY_AUDIT = "VERIFY_AUDIT"
CAP_EXPORT_AUDIT = "EXPORT_AUDIT"

# Administration
CAP_MANAGE_REPOSITORY = "MANAGE_REPOSITORY"
CAP_MANAGE_INTEGRATIONS = "MANAGE_INTEGRATIONS"
CAP_MANAGE_MEMBERS = "MANAGE_MEMBERS"
CAP_MANAGE_API_KEYS = "MANAGE_API_KEYS"
CAP_MANAGE_POLICY = "MANAGE_POLICY"
CAP_MANAGE_OPERATIONS = "MANAGE_OPERATIONS"
CAP_VIEW_OPERATIONS = "VIEW_OPERATIONS"
CAP_VIEW_DIAGNOSTICS = "VIEW_DIAGNOSTICS"
CAP_MANAGE_QUOTAS = "MANAGE_QUOTAS"

# Owner-only
CAP_TRANSFER_OWNERSHIP = "TRANSFER_OWNERSHIP"
CAP_DELETE_ORGANIZATION = "DELETE_ORGANIZATION"

ALL_CAPABILITIES: frozenset[str] = frozenset({
    CAP_VIEW_REPOSITORIES, CAP_VIEW_FINDINGS, CAP_VIEW_ACTIONS,
    CAP_VIEW_EXECUTIONS,
    CAP_CREATE_ACTION, CAP_APPROVE_ACTION, CAP_AUTHORIZE_EXECUTION,
    CAP_START_REMEDIATION, CAP_START_VERIFICATION, CAP_START_ROLLBACK,
    CAP_VIEW_AUDIT, CAP_VERIFY_AUDIT, CAP_EXPORT_AUDIT,
    CAP_MANAGE_REPOSITORY, CAP_MANAGE_INTEGRATIONS, CAP_MANAGE_MEMBERS,
    CAP_MANAGE_API_KEYS, CAP_MANAGE_POLICY, CAP_MANAGE_OPERATIONS,
    CAP_VIEW_OPERATIONS, CAP_VIEW_DIAGNOSTICS, CAP_MANAGE_QUOTAS,
    CAP_TRANSFER_OWNERSHIP, CAP_DELETE_ORGANIZATION,
})

# Capabilities that must never be silently granted: audited + owner/admin only.
ADMIN_ONLY_CAPABILITIES: frozenset[str] = frozenset({
    CAP_MANAGE_MEMBERS, CAP_MANAGE_API_KEYS, CAP_MANAGE_POLICY,
    CAP_MANAGE_OPERATIONS, CAP_MANAGE_INTEGRATIONS, CAP_MANAGE_REPOSITORY,
    CAP_MANAGE_QUOTAS, CAP_TRANSFER_OWNERSHIP, CAP_DELETE_ORGANIZATION,
})

HIGH_IMPACT_CAPABILITIES: frozenset[str] = frozenset({
    CAP_APPROVE_ACTION, CAP_AUTHORIZE_EXECUTION, CAP_START_REMEDIATION,
    CAP_START_VERIFICATION, CAP_START_ROLLBACK, CAP_EXPORT_AUDIT,
    CAP_MANAGE_MEMBERS, CAP_MANAGE_API_KEYS, CAP_MANAGE_INTEGRATIONS,
    CAP_MANAGE_OPERATIONS, CAP_TRANSFER_OWNERSHIP, CAP_DELETE_ORGANIZATION,
})


_READ_BASE = frozenset({
    CAP_VIEW_REPOSITORIES, CAP_VIEW_FINDINGS, CAP_VIEW_ACTIONS,
    CAP_VIEW_EXECUTIONS,
})

_DEVELOPER = _READ_BASE | frozenset({CAP_CREATE_ACTION})

_SECURITY_ENGINEER = _DEVELOPER | frozenset({
    CAP_APPROVE_ACTION, CAP_AUTHORIZE_EXECUTION, CAP_START_REMEDIATION,
    CAP_START_VERIFICATION, CAP_START_ROLLBACK,
    CAP_VIEW_OPERATIONS, CAP_VIEW_DIAGNOSTICS,
})

_AUDITOR = _READ_BASE | frozenset({
    CAP_VIEW_AUDIT, CAP_VERIFY_AUDIT, CAP_EXPORT_AUDIT, CAP_VIEW_OPERATIONS,
})

_ORG_ADMIN = _SECURITY_ENGINEER | _AUDITOR | frozenset({
    CAP_MANAGE_REPOSITORY, CAP_MANAGE_INTEGRATIONS, CAP_MANAGE_MEMBERS,
    CAP_MANAGE_API_KEYS, CAP_MANAGE_POLICY, CAP_MANAGE_OPERATIONS,
    CAP_MANAGE_QUOTAS,
})

_ORG_OWNER = _ORG_ADMIN | frozenset({
    CAP_TRANSFER_OWNERSHIP, CAP_DELETE_ORGANIZATION,
})

ORG_ROLE_CAPABILITIES: dict[str, frozenset[str]] = {
    OrgRole.VIEWER: _READ_BASE,
    OrgRole.AUDITOR: _AUDITOR,
    OrgRole.DEVELOPER: _DEVELOPER,
    OrgRole.SECURITY_ENGINEER: _SECURITY_ENGINEER,
    OrgRole.ORG_ADMIN: _ORG_ADMIN,
    OrgRole.ORG_OWNER: _ORG_OWNER,
}


def is_valid_role(role: object) -> bool:
    return isinstance(role, str) and role in ALL_ROLES


def is_valid_membership_state(state: object) -> bool:
    return isinstance(state, str) and state in ALL_MEMBERSHIP_STATES


def capabilities_for_role(role: Optional[str]) -> frozenset[str]:
    """Capabilities granted by a role. Unknown/invalid role → none."""
    if not is_valid_role(role):
        return frozenset()
    return ORG_ROLE_CAPABILITIES.get(role, frozenset())


def role_has_capability(role: Optional[str], capability: str) -> bool:
    """Server-side check. Unknown role or unknown capability → False."""
    if capability not in ALL_CAPABILITIES:
        return False
    return capability in capabilities_for_role(role)


def effective_capabilities(role: Optional[str], state: Optional[str]) -> frozenset[str]:
    """Capabilities for a membership: role caps only while ACTIVE."""
    if state not in AUTHORIZING_STATES:
        return frozenset()
    return capabilities_for_role(role)


def member_has_capability(
    role: Optional[str], state: Optional[str], capability: str
) -> bool:
    if capability not in ALL_CAPABILITIES:
        return False
    return capability in effective_capabilities(role, state)


# ── Role-change / membership rules (pure) ────────────────────────────

class MembershipRuleError(ValueError):
    """A membership change refused by a rule (fail closed)."""


def assert_can_change_role(
    *, actor_role: Optional[str], target_role: Optional[str],
    new_role: Optional[str], active_owner_count: int,
) -> None:
    """Rules for changing a member's role.

    - actor must be able to manage members (ORG_ADMIN/OWNER)
    - only an ORG_OWNER may grant or revoke ORG_OWNER
    - the last ACTIVE ORG_OWNER may not be demoted (no unmanageable org)
    """
    if not membership_manageable_by(actor_role):
        raise MembershipRuleError("MEMBER_MANAGEMENT_NOT_PERMITTED")
    if not is_valid_role(new_role):
        raise MembershipRuleError("INVALID_ROLE")
    if (new_role == OrgRole.ORG_OWNER or target_role == OrgRole.ORG_OWNER):
        if actor_role != OrgRole.ORG_OWNER:
            raise MembershipRuleError("OWNER_CHANGE_REQUIRES_OWNER")
    if target_role == OrgRole.ORG_OWNER and new_role != OrgRole.ORG_OWNER:
        if active_owner_count <= 1:
            raise MembershipRuleError("LAST_OWNER_PROTECTED")


def assert_can_remove(
    *, actor_role: Optional[str], target_role: Optional[str],
    active_owner_count: int,
) -> None:
    """Rules for removing/suspending a member."""
    if not membership_manageable_by(actor_role):
        raise MembershipRuleError("MEMBER_MANAGEMENT_NOT_PERMITTED")
    if target_role == OrgRole.ORG_OWNER:
        if actor_role != OrgRole.ORG_OWNER:
            raise MembershipRuleError("OWNER_CHANGE_REQUIRES_OWNER")
        # An owner may remove themselves only if another active owner remains.
        if active_owner_count <= 1:
            raise MembershipRuleError("LAST_OWNER_PROTECTED")


def membership_manageable_by(actor_role: Optional[str]) -> bool:
    return role_has_capability(actor_role, CAP_MANAGE_MEMBERS)


# ── API key scopes (Phase 23/24) ─────────────────────────────────────
# API-key scopes are deliberately narrower than member capabilities:
# a key may never manage members, policy, operations, or transfer/delete
# an organization, and may never perform high-impact mutations unless the
# scope is explicitly issued.

API_SCOPES: frozenset[str] = frozenset({
    "findings:read",
    "repositories:read",
    "actions:read",
    "actions:create",
    "executions:read",
    "audit:read",
    "audit:export",
})

HIGH_IMPACT_API_SCOPES: frozenset[str] = frozenset({
    "actions:create", "audit:export",
})


def is_valid_api_scope(scope: object) -> bool:
    return isinstance(scope, str) and scope in API_SCOPES


def scopes_are_valid(scopes: Iterable[str]) -> bool:
    return all(is_valid_api_scope(s) for s in scopes)
