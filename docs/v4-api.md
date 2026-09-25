# CYVRIX V4 — Public API (`/api/v1`)

> **SUPERSEDED by [`docs/v4-public-api.md`](v4-public-api.md) (V4.1).**
>
> This page was the V4.0 sketch. Two things in it are now out of date and
> this notice is deliberately left in place rather than quietly edited:
>
> 1. **List endpoints now return a paginated envelope** `{items,
>    next_cursor, has_more}` instead of a bare array.
> 2. **The scope set changed.** `actions:create` and `audit:export` were
>    listed here as "reserved" but had no endpoint to enforce them; V4.1
>    refuses to issue a scope that backs no endpoint, so those moved to
>    `PLANNED_API_SCOPES` and the currently issuable set is the one in
>    `v4-public-api.md` §2.
>
> Error responses remain backward compatible: the `detail` token is
> preserved and `code`/`message`/`request_id` are added.

Status: IMPLEMENTED (V4.0 baseline)
Source: `apps/api/app/routes/api_v1.py`
Authentication: `apps/api/app/routes/org_auth.py` (`api_key_auth`,
`require_api_scope`)
Keys are issued in the console under **Organizations → API keys**.

---

## 1. Scope of this API

`/api/v1` is deliberately **narrow**. It exposes read-oriented,
tenant-scoped resources that are safe for an organization API key. It does
**not** re-export the workflow mutation routes: approving, authorizing,
executing, verifying and rolling back remain session-authenticated console
operations with their full V3 chain.

The reason is an authority boundary, not an oversight. An approval is a human
decision bound to an action digest and a policy version — putting it behind a
long-lived bearer token would recast a deliberate human act as a machine
capability.

---

## 2. Authentication

```
Authorization: Bearer cyv_<prefix>_<secret>
```

- The key is looked up by the SHA-256 hash of the **full** plaintext; only the
  hash is stored.
- A missing, malformed, unknown, revoked or expired key is `401
  API_KEY_INVALID`. The response never distinguishes these cases.
- The **organization is derived from the key**. The request cannot select a
  tenant, so a leaked key is confined to its own organization.
- `last_used_at` is recorded on successful authentication.

### Scopes

See `docs/v4-public-api.md` §2 for the authoritative, endpoint-backed table.
The V4.0 set was `repositories:read`, `findings:read`, `actions:read`,
`executions:read`, `audit:read` (issued) plus `actions:create` and
`audit:export` (listed as reserved but **not backed by any endpoint**). V4.1
removed the unbacked ones from the issuable set.

A key without the required scope receives `403 API_SCOPE_REQUIRED`.

There is no scope that can manage members, policy, operations or quotas, and
none that can transfer ownership or delete an organization. Issuing any key
at all requires `MANAGE_API_KEYS` (i.e. `ORG_ADMIN`/`ORG_OWNER`); see
`v4-api-security.md` §3 for the high-impact guard and its reachability.

---

## 3. Endpoints

### `GET /api/v1/me`

Identity for the presented key. Requires no scope beyond a valid key.

```json
{
  "organization_id": "…",
  "key_name": "CI pipeline",
  "key_prefix": "1f3a9c02",
  "scopes": ["findings:read"]
}
```

Never reveals secret material.

### `GET /api/v1/repositories`

Scope: `repositories:read`. Repositories belonging to the key's
organization, ordered by creation, capped at 500.

```json
[{ "id": "…", "owner": "acme", "name": "api",
   "default_branch": "main", "is_active": true }]
```

### `GET /api/v1/findings`

Scope: `findings:read`.

| Query | Type | Default | Notes |
|---|---|---|---|
| `severity` | string | — | upper-cased before matching (`HIGH`, `CRITICAL`, …) |
| `limit` | int | 100 | 1–500 |

```json
[{ "id": "…", "repository_id": "…", "title": "…",
   "severity": "HIGH", "status": "OPEN",
   "source_type": "DEPENDENCY", "vulnerability_id": "CVE-…" }]
```

### `GET /api/v1/actions`

Scope: `actions:read`.

| Query | Type | Default | Notes |
|---|---|---|---|
| `limit` | int | 100 | 1–500 |

```json
[{ "id": "…", "repository_id": "…", "action_type": "UPDATE_DEPENDENCY_VERSION",
   "status": "APPROVED", "risk_level": "MEDIUM",
   "policy_decision": "ALLOW", "action_digest": "…" }]
```

`policy_decision` and `action_digest` are included so a consumer can reconcile
what the platform decided without re-deriving it.

---

## 4. Tenant scoping

Every list endpoint resolves rows through the ownership join:

```
api_keys.organization_id
  → github_installations.organization_id
    → repositories
      → findings | action_proposals
```

A row that does not belong to the key's organization is not filtered out of
the response — it is never selected. There is no code path in `/api/v1` that
accepts an organization identifier from the caller.

---

## 5. Rate limiting

All `/api/v1` reads share the key's organization `v1-read` bucket:
**600 requests / hour**, keyed
`ratelimit:org:<organization_id>:v1-read:<window_start>`. Exceeding it returns
`429 ORG_RATE_LIMITED`. Limits are per organization, so one noisy integration
cannot throttle another tenant, and a limiter that loses Redis denies rather
than allows (see `v4-multitenancy.md` §4).

---

## 6. Error model

| Status | `detail` | Meaning |
|---|---|---|
| `401` | `API_KEY_REQUIRED` | no `Authorization` header |
| `401` | `API_KEY_INVALID` | unknown, revoked, expired or malformed key |
| `403` | `API_SCOPE_REQUIRED` | key lacks the endpoint's scope |
| `429` | `ORG_RATE_LIMITED` | organization bucket exhausted |
| `422` | — | request validation failed (e.g. `limit` out of range) |

Errors carry a machine-readable `reason_code` (or a bare token string) that
the console maps to a structured message. Free-form internal text is never
returned.

---

## 7. Console (session-authenticated) API

Organization administration lives under `/api/orgs` and requires a session
cookie plus the relevant capability. It is **not** part of `/api/v1` and is
not reachable with an API key.

| Method | Path | Capability |
|---|---|---|
| `GET` | `/api/orgs` | any authenticated user (own memberships) |
| `POST` | `/api/orgs` | any authenticated user (creator becomes owner) |
| `GET` | `/api/orgs/{id}` | ACTIVE membership |
| `GET` | `/api/orgs/{id}/capabilities` | ACTIVE membership |
| `GET` | `/api/orgs/{id}/members` | ACTIVE membership |
| `PATCH` | `/api/orgs/{id}/members/{user_id}` | `MANAGE_MEMBERS` |
| `POST` | `/api/orgs/{id}/members/{user_id}/state` | `MANAGE_MEMBERS` |
| `GET` | `/api/orgs/{id}/invitations` | `MANAGE_MEMBERS` |
| `POST` | `/api/orgs/{id}/invitations` | `MANAGE_MEMBERS` |
| `POST` | `/api/orgs/{id}/invitations/{invitation_id}/revoke` | `MANAGE_MEMBERS` |
| `POST` | `/api/invitations/accept` | the invitation token itself |
| `GET` | `/api/orgs/{id}/policy` | ACTIVE membership |
| `PUT` | `/api/orgs/{id}/policy` | `MANAGE_POLICY` |
| `GET` | `/api/orgs/{id}/api-keys` | `MANAGE_API_KEYS` |
| `POST` | `/api/orgs/{id}/api-keys` | `MANAGE_API_KEYS` |
| `POST` | `/api/orgs/{id}/api-keys/{key_id}/revoke` | `MANAGE_API_KEYS` |

Request bodies are declared `extra="forbid"`; a request that attempts to add
an unexpected field is rejected rather than silently accepted.

---

## 8. Versioning policy

`/api/v1` is the first versioned public surface. The contract it commits to:

- **Additive changes only** within `v1`: new optional fields and new
  endpoints. No field is renamed, retyped or removed.
- **No new authority.** A future `v1` endpoint will not introduce a scope
  that can approve, authorize, execute, or administer an organization.
- **Breaking changes require `/api/v2`.** The unversioned console routes
  (`/api/orgs`, `/api/actions`, …) are internal and may evolve with the
  console; they are not covered by this promise.

---

## 9. Tests

| Concern | Where |
|---|---|
| Key hashing, scopes, expiry, revocation, rotation | `tests/test_v4_platform.py` |
| Cross-organization read attempts | `tests/test_v4_platform.py` (IDOR cases) |
| Concurrent key creation/revocation | `tests/test_v4_races.py` |
| Rate-limit isolation and fail-closed behaviour | `tests/test_v4_rate_limits.py` |
| Client request shape and tenancy invariant | `apps/web/__tests__/api-v4.test.ts` |
