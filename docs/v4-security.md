# CYVRIX V4 — Security Model

Status: IMPLEMENTED
Related: `v3-security-model.md` (the chain V4 extends), `v4-rbac.md`,
`v4-multitenancy.md`, `v4-threat-model.md`.

---

## 1. The single rule

> **The backend is always the authority. Nothing a client sends is
> authority — only a selector that the backend will verify.**

V4 specializes this into a concrete list of fields that are *never* trusted as
authority, because they are decisions the server owns:

| Field | Where it may appear | Treated as |
|---|---|---|
| `organization_id` | URL **path** only | a selector, verified against the caller's ACTIVE membership |
| `role` | request body | the **target** member's new role, checked against the membership rules |
| `state` | request body | the **target** membership's new state, checked against the rules |
| `approved`, `authorized`, `verified` | — | do not exist on the wire |
| `capabilities`, `policy_decision` | response only | data for display |
| `is_personal`, `policy_version` | response only | data for display |

A route that reads any of the left column as authority is a defect regardless
of what else it validates.

---

## 2. Authority boundaries

```
  authenticated identity   (session cookie or hashed API key — server state)
        │
        ├── session routes ──► ACTIVE membership ──► capability ──► V3 chain
        │
        └── /api/v1 ─────────► organization from the KEY ──► scope ──► read-only query
```

Two independent authentication mechanisms, one authorization model. Neither
path lets a request name its own tenant, and neither path can shorten the V3
chain.

---

## 3. Isolation properties and how they are enforced

### 3.1 Non-members learn nothing

`org_auth._load_membership()` returns `404 ORGANIZATION_NOT_FOUND` for a
non-member, for a missing organization, and for a `DELETED` organization —
the same response in all three cases. The API cannot be used to enumerate
organization ids, and organization deletion is immediate even for a member
whose membership row still says `ACTIVE`.

### 3.2 Only ACTIVE membership authorizes

`INVITED`, `SUSPENDED` and `REMOVED` resolve to the empty capability set.
Suspension therefore takes effect on the next request with no cache to
expire and no token to revoke. The client re-applies the same rule so the UI
cannot show controls for a membership that is no longer active.

### 3.3 The tenant is derived, never supplied

- Session routes derive the organization from the ACTIVE membership row.
- `/api/v1` derives it from the authenticated key; the request cannot select
  one.
- Resource queries scope through the installation ownership join, so a row
  from another organization is never selected rather than filtered.

### 3.4 The order is fixed

Tenancy is resolved **before** authorization: capability is checked only
after an ACTIVE membership is established. A caller cannot probe
capabilities across organizations, because a non-member never reaches the
capability check.

---

## 4. Separation of duties

- **The author of a change cannot ship it by default.** `DEVELOPER` may
  `CREATE_ACTION` but not `APPROVE_ACTION`, `AUTHORIZE_EXECUTION`, or start
  remediation, verification or rollback.
- **Audit is append-and-read at every level.** No capability and no API scope
  can edit or delete audit history; `VIEW_AUDIT`/`VERIFY_AUDIT`/`EXPORT_AUDIT`
  are the complete set.
- **Organization administration is not execution authority.** No route under
  `/api/orgs` can approve, authorize, execute or roll back anything.
- **High-impact capabilities are explicitly marked** in
  `v4_rbac.HIGH_IMPACT_CAPABILITIES` and require the corresponding role.

---

## 5. Secret handling

| Secret | Lifetime | Stored | Shown |
|---|---|---|---|
| Session cookie | configured TTL | signed id | — |
| Invitation token | 72 hours, single-use | SHA-256 hash | once |
| API key secret | until revoked/expired | SHA-256 hash of the full plaintext | once |

Properties:

- **Hash-only at rest.** A database read does not yield a usable credential.
- **Non-secret lookup handles.** `api_keys.prefix` (8 hex chars) identifies a
  key in the UI and in logs without exposing the secret.
- **Unique constraints** on `token_hash`, `key_hash` and `prefix` mean a
  token cannot be silently reissued.
- **Single use.** An invitation records `accepted_at`; a second acceptance is
  refused (`INVITATION_ALREADY_ACCEPTED`).
- **Revocation is terminal and immediate.** `revoked_at` is checked on every
  authentication.
- **Expiry is checked on every authentication**, not only at issuance.

The console renders a secret exactly once, through
`components/org/secret-reveal.tsx`, which never writes the value to browser
storage, a URL or a log. The client source scan
(`apps/web/__tests__/frontend-security.test.ts`) fails the build if browser
storage of credentials appears anywhere in the client.

---

## 6. Abuse resistance

- **Organization-scoped rate limits** on every administration route and on
  `/api/v1`, keyed `ratelimit:org:<id>:<bucket>:<window>`.
- **Fail closed.** If Redis is unreachable, `check_rate_limit` returns
  `(False, 0)` and the request is refused with `429 ORG_RATE_LIMITED`. A
  limiter that degrades to "allow" under load is a bypass, not a degradation.
- **Budget isolation.** One organization exhausting a bucket cannot throttle
  another or spend another tenant's budget. Certified against real Redis.
- **Enumeration resistance.** Uniform `404` for non-members (§3.1) plus
  rate-limited administration routes bound how fast ids can be probed.
- **No client-side authority.** Hiding a button is a UX affordance; the
  server authorizes every route independently.

---

## 7. Invitations

An invitation is a capability grant in a URL, so it is constrained on every
axis available:

- **Hashed at rest** — a database read yields nothing usable.
- **Single use** — `accepted_at`, and a second acceptance is refused.
- **Expiring** — 72 hours (`INVITATION_TTL_HOURS`).
- **Bound to one organization** — the token cannot be redirected to another
  tenant.
- **Optionally email-bound** — when an email is supplied it is stored
  lower-cased and must match the accepting user.
- **Explicitly accepted** — the console requires a click; there is no
  auto-accept on page load, so a prefetched or shared link cannot silently
  join the caller to a tenant.
- **Revocable** — `revoked_at` is terminal.
- **Minimum privilege by default** — the role defaults to `VIEWER`.

---

## 8. Client-side tenancy

The client holds a selector and a set of server-derived capabilities, and
nothing else:

- **No browser storage of tenant state.** The selector lives in memory only,
  so nothing tenant-related survives a reload, a logout or a shared machine,
  and a stale id cannot be replayed.
- **Tenant cache is dropped on switch.** Changing organization removes every
  cached react-query entry except the caller's own organization list,
  preventing organization A's data from rendering under organization B's
  name. Covered by `apps/web/__tests__/org-context.test.tsx`.
- **Never auto-select a non-ACTIVE membership.**
- **Secrets are never persisted** — no storage, no URL, no log.

---

## 9. Migration safety

Migration `012` is additive and backfills tenancy rather than asserting it:

- No V1–V3 table is altered destructively; `github_installations` only gains a
  nullable column and an FK.
- Legacy rows keep working because the V3 ownership predicate
  (`installation.user_id`) is still honoured when `organization_id` is `NULL`.
- The backfill is deterministic and idempotent in effect: after
  `downgrade 012 → 011` and a re-upgrade, it re-creates the same personal
  organizations, owner memberships, policy revision at v1, and installation
  bindings.

Certified on real PostgreSQL — see `v4-multitenancy.md` §5.

---

## 10. Fail-closed inventory

Every V4 decision point refuses on the unsafe branch:

| Condition | Outcome |
|---|---|
| Unknown role | no capabilities |
| Unknown or non-`ACTIVE` membership state | no capabilities |
| Unknown capability name | refused |
| Unknown organization policy key | `INVALID_POLICY` (refused, not ignored) |
| Unknown API scope | `INVALID_API_SCOPES` at issuance; `API_SCOPE_REQUIRED` at use |
| Redis unavailable (rate limit) | `429 ORG_RATE_LIMITED` |
| Invitation expired/revoked/accepted/email-mismatch | refused with a specific reason code |
| Last ACTIVE owner demotion/removal | `LAST_OWNER_PROTECTED` |
| Deleted organization | `404` for everyone |

---

## 11. Explicitly out of scope for V4.0

- **Cross-organization resource sharing.** No `share`, delegation or
  transfer-resource primitive exists.
- **SSO / external identity providers.** Authentication remains the existing
  GitHub OAuth session flow.
- **Self-service organization deletion.** `DELETE_ORGANIZATION` exists as a
  capability, and a `DELETED` organization is already treated as gone
  everywhere; the deletion *workflow* and its retention policy are not part
  of this release.
- **Per-organization quotas.** `MANAGE_QUOTAS` is defined and marked
  high-impact; the enforcement layer is future work.

Stating these plainly is deliberate: an unimplemented control must not appear
to be covered by a capability name.
