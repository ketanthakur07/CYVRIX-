# CYVRIX V4 — Multi-Tenancy

Status: IMPLEMENTED
Related: `v4-rbac.md` (authorization), `v4-security.md` (security model),
`v4-architecture.md` (layering).

---

## 1. What an organization is

An **organization** is a *namespace*, not a security boundary by itself.

Tenant isolation is never "the organization id in the request matched, so
allow". Every request resolves, in order:

```
authenticated user
  → ACTIVE membership              (server state)
    → organization                 (derived)
      → resource ownership         (the resource's own organization_id)
        → capability               (v4_rbac)
```

The organization id in a URL is a **selector**, verified against the caller's
membership before any work happens. It is never accepted as authority.

---

## 2. Tenant resolution rules

### 2.1 The client never names its own tenant as authority

`organization_id` is accepted only in the **path**, and only as a selector.
No request body contains `organization_id`, and no handler reads one. The
client's request builders in `apps/web/lib/api.ts` are tested to never send
it (`apps/web/__tests__/api-v4.test.ts`, "tenancy invariant").

### 2.2 Non-members see nothing

`_load_membership()` in `app/services/org_auth.py` answers a non-member with
`404 ORGANIZATION_NOT_FOUND` — the same response a genuinely missing
organization produces. Existence is never confirmed to a non-member, so the
endpoint cannot be used to enumerate organizations.

`apps/api/app/routes/orgs.py` documents this as: *"Routes take an
organization id in the PATH only as a selector; it is verified against the
caller's membership before any work happens."*

### 2.3 A deleted organization is gone for everyone

`org_auth._load_membership()` treats `state == "DELETED"` as not found, even
for a member whose membership row still says `ACTIVE`. A deletion request
therefore cannot leave a still-usable tenant behind.

### 2.4 Only ACTIVE membership grants anything

`INVITED`, `SUSPENDED` and `REMOVED` memberships resolve to zero
capabilities. Suspension is therefore immediate: no cache, no token, and no
follow-up request needs to expire for access to stop.

---

## 3. Resource ownership

Resources reach an organization through the `GithubInstallation` that owns
them:

```
Organization ──< GithubInstallation ──< Repository ──< Finding
                                                  └──< ActionProposal
```

`GithubInstallation.organization_id` is the tenancy binding. Migration `012`
adds it as a nullable foreign key and **backfills** it for every existing
installation (see §5).

For incremental adoption, `org_auth.owned_installation_condition()` provides
a SQL predicate that admits a resource when *either* the caller is the legacy
installation owner (`user_id`) *or* the caller holds an `ACTIVE` membership in
the installation's organization. This is a strict superset of the V3
predicate: it can only **add** access for genuine members and never grants
cross-organization access. Mutation routes must still check a capability on
top of it.

The `/api/v1` read routes scope through the same join, so a key can only ever
read its own organization's repositories, findings and actions.

---

## 4. Tenant-scoped rate limiting

Rate limits are per organization, not per user and not global:

```
ratelimit:org:<organization_id>:<bucket>:<window_start>
```

Buckets used by the organization routes:

| Bucket | Limit |
|---|---|
| `org-read` | 600 / hour |
| `members-read` | 600 / hour |
| `members-write` | 120 / hour |
| `invites` | 120 / hour |
| `policy-read` | 300 / hour |
| `policy-write` | 60 / hour |
| `keys` | 120 / hour (read), 60 / hour (write) |
| `v1-read` (public API) | 600 / hour |

Two properties are certified against **real Redis** in
`tests/test_v4_rate_limits.py`:

1. **Isolation** — one organization exhausting a bucket does not throttle
   another, and cannot spend another tenant's budget.
2. **Fail closed** — if Redis is unreachable, `check_rate_limit` returns
   `(False, 0)` and the dependency raises `429 ORG_RATE_LIMITED`. A limiter
   that silently allows everything under load is worse than no limiter.

---

## 5. Migration and backfill (V3 → V4)

Migration `012_v40_platform_foundation.py` is **additive only**: it creates
five tables (`organizations`, `organization_memberships`,
`organization_invitations`, `organization_policy_revisions`, `api_keys`),
adds `github_installations.organization_id`, and then backfills so no
existing data loses its tenant:

1. one personal organization per existing user
   (`slug = 'personal-' || <user uuid without dashes>`),
2. one `ACTIVE` `ORG_OWNER` membership per personal organization,
3. `github_installations.organization_id` bound to its owner's personal
   organization,
4. an initial `organization_policy_revisions` row at version 1.

Legacy rows keep working throughout, because the V3 ownership predicate
(`installation.user_id`) is still honoured when `organization_id` is `NULL`,
and the backfill sets it explicitly for existing rows.

**Certified on real PostgreSQL** (`cyvrix_test` on `:5433`):

| Scenario | Result |
|---|---|
| Fresh `alembic upgrade head` (001 → 012) | all tables, indexes and the FK created |
| V3 → V4 upgrade with legacy rows (2 users, 2 installations) | 2 personal orgs, 2 `ORG_OWNER` memberships, 2 policy revisions at v1, 2 installations bound to their owner's org, 0 users lost |
| `downgrade 012 → 011` with legacy rows present | V4 tables and the column dropped, users and installations preserved |
| Re-`upgrade head` | backfill re-created identically |

`tests/test_migrations.py` additionally asserts the V4 tables exist and that
`github_installations.organization_id` is present, in both SQLite (fast CI)
and, when `MIGRATION_TEST_DB_URL` is set, real PostgreSQL.

---

## 6. Client-side tenancy

The browser holds a **selector**, not a boundary. `apps/web/lib/org.tsx`
provides the current organization and its server-derived capabilities, and
enforces two rules:

1. **Never auto-select a non-`ACTIVE` membership.** Selection prefers a
   personal organization, then the first `ACTIVE` membership; a `SUSPENDED`,
   `INVITED` or `REMOVED` row is shown but never becomes the active tenant.
2. **Drop cached tenant data on switch.** Changing the organization removes
   every react-query entry except the caller's own organization list. Without
   this, organization A's findings would render under organization B's name.
   The retained exception is `["orgs"]` — the caller's own membership list,
   which is identical for every tenant.

There is **no browser storage of the selector**. It lives in memory for the
session, so nothing tenant-related survives a reload, a logout, or a shared
machine, and a stale id can never be replayed. (This is also why the source
scan in `apps/web/__tests__/frontend-security.test.ts` — which forbids
`localStorage` — passes unchanged.)

Both rules are covered by `apps/web/__tests__/org-context.test.tsx`.

---

## 7. What is deliberately NOT multi-tenant

- **The audit chain is per installation**, as in V3.8. V4 does not re-key
  audit history; a personal organization created by the backfill inherits the
  chains of the installations bound to it.
- **The V3 workflow routes remain session-authenticated console operations.**
  Organization administration never approves, authorizes or executes
  anything. `/api/v1` re-exports only read-oriented, tenant-scoped resources.
- **No cross-organization sharing is possible in V4.0.** There is no
  `share`, `transfer-resource`, or cross-org delegation primitive, and no
  capability grants access to an organization the caller is not a member of.
