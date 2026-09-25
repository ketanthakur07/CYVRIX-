# CYVRIX V4 — Platform Foundation Architecture

Status: IMPLEMENTED
Supersedes in scope (not in kind): the V3 console described in
`v3.9-console.md`. V4 **extends** V3; it does not replace any V3 control.

---

## 1. What V4 adds

V3.9 is a single-tenant security workflow console. V4.0 turns it into a
multi-tenant platform without touching the security chain:

| Concern | V3.9 | V4.0 |
|---|---|---|
| Tenancy | implicit: the installation owner is the tenant | explicit: `organizations` + memberships |
| Authorization | one ops role (`USER`/`OPERATOR`/`ADMIN`) | roles → capabilities → resource scope, per organization |
| Membership | none | invitations, states, last-owner protection |
| Programmatic access | session cookie only | `/api/v1` + scoped, hashed, revocable API keys |
| Policy | global policy engine | versioned per-organization policy revisions |
| Rate limits | keyed by user/ip | keyed by organization bucket |
| UI | workflow console | + organization context, members, API keys, settings |

### The non-negotiable rule

> **V4 EXTENDS the V3 security chain. It never bypasses it.**

```
policy → approval → authorization → sandbox → execution
       → verification → rollback → audit
```

An organization capability lets a member *invoke* a gate. It never removes a
gate. `APPROVE_ACTION` does not skip digest binding; `START_ROLLBACK` does not
skip the rollback preconditions; `EXPORT_AUDIT` does not skip chain
verification. V4 adds a tenant layer in front of the chain and a public read
API beside it.

---

## 2. Layering

```
┌──────────────────────────────────────────────────────────────┐
│ Web (Next.js 14, app router)                                 │
│   /orgs, /orgs/[id]/{members,api-keys}, /invitations/accept  │
│   lib/org.tsx  — tenant context: selector + capabilities      │
└───────────────────────────┬──────────────────────────────────┘
                            │ session cookie          │ Bearer API key
                            ▼                         ▼
┌──────────────────────────────────────────────────────────────┐
│ API (FastAPI)                                                │
│   routes/orgs.py      organization administration            │
│   routes/api_v1.py    public, key-authenticated reads         │
│   routes/{actions,executions,...}.py   V3 workflow (unchanged)│
├──────────────────────────────────────────────────────────────┤
│ services/org_auth.py   tenant resolution + capability deps    │
│ services/v4_rbac.py    roles → capabilities (pure)            │
│ services/organization_service.py   membership/invite/policy   │
│ services/api_key_service.py        hashed, scoped keys        │
├──────────────────────────────────────────────────────────────┤
│ V3 services: policy, approval, authorization, sandbox,        │
│ execution, remediation, verification, rollback, audit         │
└──────────────────────────────────────────────────────────────┘
```

`org_auth.py` is the only place tenancy is decided. Nothing else may read an
organization from a request.

---

## 3. Request flow (session-authenticated organization route)

```
PATCH /api/orgs/{org_id}/members/{user_id}
  1. get_current_user()                    → authenticate (session cookie)
  2. require_org_capability(MANAGE_MEMBERS)
       a. _load_membership(user, org_id)   → ACTIVE membership + org state
          · missing / non-member / DELETED org → 404 (never confirm existence)
       b. member_has_capability(role, state, MANAGE_MEMBERS)
          · insufficient → 403 ORG_CAPABILITY_REQUIRED
  3. rate_limit_org("members-write", 120/h)  → 429 ORG_RATE_LIMITED
  4. validate body (extra="forbid")
  5. service enforces the membership rules transactionally
     (last-owner protection, owner-only owner changes)
  6. commit; DB constraint violations surface as 409
```

Step 2 is where tenancy and authorization happen, in that order. Steps 3–6
never see a client-supplied organization, role or capability.

---

## 4. Request flow (public API)

```
GET /api/v1/findings
  1. api_key_auth()                → SHA-256(token) lookup
       · missing/invalid/revoked/expired → 401 API_KEY_INVALID
  2. require_api_scope("findings:read")
       · absent scope → 403 API_SCOPE_REQUIRED
  3. rate_limit_org(key.organization_id, "v1-read", 600/h)
  4. query scoped to key.organization_id through the
     installation → repository → finding join
```

The organization is derived **from the key**. The request cannot select one,
so a key cannot reach another tenant.

---

## 5. Data model (migration `012`, additive)

```
organizations
  id, name, slug (unique), state, is_personal, created_by,
  policy JSONB, policy_version, created_at, updated_at

organization_memberships
  organization_id → organizations.id
  user_id         → users.id
  role, state, created_at, updated_at
  UNIQUE(organization_id, user_id)          uq_org_membership

organization_invitations
  organization_id, email (nullable), role, token_hash (unique),
  created_by, expires_at, accepted_at, accepted_by_user_id, revoked_at

organization_policy_revisions
  organization_id, version, policy JSONB, changed_by, created_at
  UNIQUE(organization_id, version)          uq_org_policy_version

api_keys
  organization_id, name, prefix (unique), key_hash (unique),
  scopes JSONB, created_by, created_at, expires_at, last_used_at, revoked_at

github_installations (+)
  organization_id → organizations.id   (nullable, backfilled)
```

Design notes:

- `slug` is unique globally, so an organization URL namespace is unambiguous.
- `prefix` on `api_keys` is unique and non-secret, allowing a key to be
  identified in the UI and in logs without any secret material.
- `token_hash` / `key_hash` are unique, so a token cannot be issued twice and
  lookups are a single indexed probe.
- Policy history is a separate table with a unique `(organization_id,
  version)`, so an action evaluated against version *N* can always be
  explained against version *N*.

---

## 6. Entity relationships

```
User ──< OrganizationMembership >── Organization
                                        │
                                        ├──< OrganizationInvitation
                                        ├──< OrganizationPolicyRevision
                                        ├──< ApiKey
                                        └──< GithubInstallation ──< Repository
                                                                     ├──< Finding
                                                                     ├──< Scan
                                                                     └──< ActionProposal
```

A user reaches an organization's resources only through a membership; a
resource reaches its organization through its installation.
`GithubInstallation` is therefore the single tenancy hinge in the whole
system.

---

## 7. Policy: versioned, closed-world, never rewritten

`organization_service.py` validates an organization policy against a closed
world of keys and refuses unknown ones (`INVALID_POLICY`) rather than
ignoring them:

```
max_risk_level             allowed_action_types      require_second_approver
require_verification       max_concurrent_executions network_allowed
```

Saving writes the new document to `organizations.policy`, increments
`policy_version`, and appends an immutable `organization_policy_revisions`
row. History is monotonic: superseding a policy never rewrites the version an
existing decision was evaluated against.

---

## 8. Secrets: shown once, stored hashed

| Secret | Format | Storage | Returned |
|---|---|---|---|
| Invitation token | 32 random bytes | SHA-256 hash, 72-hour TTL | once, at creation |
| API key | `cyv_<8-hex-prefix>_<token_urlsafe(32)>` | SHA-256 hash of the full plaintext; `prefix` in clear for lookup | once, at creation |

Neither the invitation token nor the API key secret is ever logged,
re-derivable, or retrievable after issuance. The console renders each exactly
once through `components/org/secret-reveal.tsx`, which never writes the value
to storage or a URL.

---

## 9. Frontend structure

```
lib/org.tsx                     tenant context (selector + capabilities)
lib/types.ts                    V4 contracts (+ ORG_CAP, API_SCOPES)
lib/api.ts                      V4 client functions
lib/workflow.ts                 V4 presentation tones
components/org/org-selector.tsx organization switcher
components/org/org-header.tsx   shared org page header + tabs
components/org/secret-reveal.tsx one-time secret display
app/orgs/page.tsx               list + create
app/orgs/[id]/page.tsx          settings + versioned policy
app/orgs/[id]/members/page.tsx  members + invitations
app/orgs/[id]/api-keys/page.tsx API keys
app/invitations/accept/page.tsx accept a one-time invitation
```

Every page reads its role and capabilities from the server and treats them as
display data. Acceptance of an invitation is an explicit click — never an
auto-accept on page load — so a prefetched or shared link cannot silently
join the caller to a tenant.

---

## 10. Verification status

| Area | Evidence |
|---|---|
| RBAC, membership, invitations, API keys, IDOR | `tests/test_v4_platform.py` — 71 passed |
| Concurrent membership/role/policy changes | `tests/test_v4_races.py` — 99 passed |
| Org-scoped rate-limit isolation (real Redis) | `tests/test_v4_rate_limits.py` — 7 passed |
| V4 tables/columns vs models | `tests/test_migrations.py` |
| Migration fresh/upgrade/downgrade on real PG | `cyvrix_test` @ `:5433`, certified (see `v4-multitenancy.md` §5) |
| Client tenancy + fail-closed capabilities | `apps/web/__tests__/{org-rbac,org-context,api-v4}.test.*` |
| V3 chain regression | full gated suite incl. `test_git_remediation_races.py` (53 passed) and `test_sandbox_real_container.py` (12 passed, real Linux containers) |
