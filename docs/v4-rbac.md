# CYVRIX V4 — Role-Based Access Control (normative)

Status: IMPLEMENTED
Source of truth: `apps/api/app/services/v4_rbac.py` (pure rules) and
`apps/api/app/services/organization_service.py` (transactional enforcement).
This document is the specification those modules implement; where they
disagree, the code wins and this document is the bug.

---

## 1. The governing rule

> **A role is a named bundle of capabilities. A capability is the unit of
> authorization. Roles are never the only primitive, and capabilities are
> never derived on the client.**

Three consequences that shape every route:

1. **Capabilities are server-derived.** No request field can select a role,
   a capability, or an organization. A route that reads such a field as
   authority is a defect regardless of what else it checks.
2. **Membership is not execution authority.** Holding `APPROVE_ACTION` or
   `AUTHORIZE_EXECUTION` means the member may *invoke* the V3.2/V3.3 gates —
   not bypass them. Digest binding, policy evaluation, kill switch, approval
   validity windows, sandbox isolation, verification and rollback all still
   apply in full. V4 adds a tenant layer; it does not shorten the V3 chain.
3. **There is no `ALL`, `SUPERUSER` or `*` capability.** The capability set
   is a closed world. A capability name that is not in the registry is
   refused, not ignored, and a capability that skips a V3 control does not
   exist.

---

## 2. Membership states

| State | Confers capability? | Meaning |
|---|---|---|
| `ACTIVE` | **Yes** | A current, usable membership. |
| `INVITED` | No | An invitation exists; it has not been accepted. |
| `SUSPENDED` | No | Temporarily stripped; reversible by an admin. |
| `REMOVED` | No | Terminal for that membership row. |

Only `ACTIVE` is in the authorizing set. This is enforced in
`effective_capabilities()` and re-applied in the client so a suspended
member whose capability payload is still cached cannot see actions.

A `DELETED` organization is treated as non-existent: even its former members
receive `404 ORGANIZATION_NOT_FOUND`, so a deletion request cannot leave a
still-usable tenant behind.

---

## 3. Capability registry (closed world)

### Read

`VIEW_REPOSITORIES` · `VIEW_FINDINGS` · `VIEW_ACTIONS` · `VIEW_EXECUTIONS`

### Remediation workflow — invoke the V3 gates

`CREATE_ACTION` · `APPROVE_ACTION` · `AUTHORIZE_EXECUTION`
`START_REMEDIATION` · `START_VERIFICATION` · `START_ROLLBACK`

### Audit (V3.8 capabilities, re-expressed at the organization layer)

`VIEW_AUDIT` · `VERIFY_AUDIT` · `EXPORT_AUDIT`

Note there is deliberately **no** `EDIT_AUDIT` or `DELETE_AUDIT`: the audit
surface is append-and-read only at every privilege level.

### Administration

`MANAGE_REPOSITORY` · `MANAGE_INTEGRATIONS` · `MANAGE_MEMBERS` ·
`MANAGE_API_KEYS` · `MANAGE_POLICY` · `MANAGE_OPERATIONS` ·
`VIEW_OPERATIONS` · `VIEW_DIAGNOSTICS` · `MANAGE_QUOTAS`

### Owner-only

`TRANSFER_OWNERSHIP` · `DELETE_ORGANIZATION`

---

## 4. Role → capability matrix

| Capability | VIEWER | AUDITOR | DEVELOPER | SECURITY_ENGINEER | ORG_ADMIN | ORG_OWNER |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| View repositories / findings / actions / executions | ● | ● | ● | ● | ● | ● |
| `CREATE_ACTION` | | | ● | ● | ● | ● |
| `APPROVE_ACTION` | | | | ● | ● | ● |
| `AUTHORIZE_EXECUTION` | | | | ● | ● | ● |
| `START_REMEDIATION` / `START_VERIFICATION` / `START_ROLLBACK` | | | | ● | ● | ● |
| `VIEW_AUDIT` / `VERIFY_AUDIT` / `EXPORT_AUDIT` | | ● | | | ● | ● |
| `VIEW_OPERATIONS` | | ● | | ● | ● | ● |
| `VIEW_DIAGNOSTICS` | | | | ● | ● | ● |
| `MANAGE_REPOSITORY` / `MANAGE_INTEGRATIONS` | | | | | ● | ● |
| `MANAGE_MEMBERS` / `MANAGE_API_KEYS` / `MANAGE_POLICY` | | | | | ● | ● |
| `MANAGE_OPERATIONS` / `MANAGE_QUOTAS` | | | | | ● | ● |
| `TRANSFER_OWNERSHIP` / `DELETE_ORGANIZATION` | | | | | | ● |

Intent of the two low-privilege roles:

- **DEVELOPER** can propose work but cannot approve, authorize or execute it.
  This is the separation-of-duties floor: the author of a change is not
  automatically able to ship it.
- **AUDITOR** can read and verify history but can change nothing. It exists so
  compliance review does not require administrative standing.

---

## 5. Membership-change rules

Implemented as pure predicates in `v4_rbac.py`, enforced transactionally in
`organization_service.py` (so two concurrent demotions cannot each see
`active_owner_count == 2` and both succeed).

| Rule | Reason code |
|---|---|
| Only `MANAGE_MEMBERS` holders may change memberships | `MEMBER_MANAGEMENT_NOT_PERMITTED` |
| Only an `ORG_OWNER` may grant **or** revoke `ORG_OWNER` | `OWNER_CHANGE_REQUIRES_OWNER` |
| The last `ACTIVE` owner cannot be demoted | `LAST_OWNER_PROTECTED` |
| The last `ACTIVE` owner cannot be suspended or removed | `LAST_OWNER_PROTECTED` |
| The new role must be in the registry | `INVALID_ROLE` |

`LAST_OWNER_PROTECTED` exists so an organization can never be left with no
member able to administer it — including when an owner tries to remove
themselves.

---

## 6. API-key scopes are narrower than capabilities

An API key authenticates the `/api/v1` public surface. Its scopes are a
separate, deliberately smaller closed world:

```
findings:read   repositories:read   actions:read   actions:create
executions:read   audit:read   audit:export
```

There is **no** key scope that can:

- manage members, policy, operations, or quotas;
- transfer ownership or delete an organization;
- approve, authorize, execute, verify or roll back anything.

Issuing a *high-impact* scope (`actions:create`, `audit:export`) additionally
requires at least `ORG_ADMIN` standing, enforced server-side as
`HIGH_IMPACT_SCOPE_REQUIRES_ADMIN`. The console surfaces this before the key
is created.

---

## 7. How routes consume this

```python
# apps/api/app/routes/orgs.py
@router.patch("/{organization_id}/members/{user_id}", ...)
async def change_member_role(
    organization_id: UUID,
    user_id: UUID,
    body: RoleUpdate,
    ctx=Depends(require_org_capability(rbac.CAP_MANAGE_MEMBERS)),
    ...
):
```

`require_org_capability(X)` resolves the caller's `ACTIVE` membership for the
organization named in the **path**, then checks `X`. A non-member receives
`404` (existence is never confirmed); a member lacking the capability receives
`403 ORG_CAPABILITY_REQUIRED`.

`RoleUpdate` is declared `extra="forbid"`, so a request that tries to smuggle
an unexpected field is rejected rather than silently accepted.

---

## 8. What the client is allowed to do

`apps/web/lib/org.tsx` holds the caller's role and capabilities and exposes
`hasCapability()`. This is a **display** affordance only: it decides which
buttons render, never whether an action is permitted. Every route re-checks
the capability server-side, so hiding a control and denying a request are
independent facts. `apps/web/__tests__/org-rbac.test.ts` pins the fail-closed
properties (unknown capability → `false`; non-`ACTIVE` membership → no
capabilities).

---

## 9. Tests

| Concern | Where |
|---|---|
| Role/capability rules, last-owner protection, invitation lifecycle, API-key scopes, IDOR | `tests/test_v4_platform.py` |
| Concurrent membership/role changes | `tests/test_v4_races.py` |
| Org-scoped rate-limit isolation (real Redis) | `tests/test_v4_rate_limits.py` |
| Client fail-closed capability semantics | `apps/web/__tests__/org-rbac.test.ts` |
