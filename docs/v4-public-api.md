# CYVRIX V4.1 — Public API (`/api/v1`)

Status: IMPLEMENTED (this document is the contract)
Source: `apps/api/app/routes/api_v1.py`, `apps/api/app/services/idempotency_service.py`
Replaces as the authority: `docs/v4-api.md` (the V4.0 sketch). Where the two
disagree, this document and the running OpenAPI schema win.

---

## 1. What this API is for

CYVRIX becomes externally integrable here: automation can read an
organization's security state, submit analysis requests, poll them, and
verify audit history — without ever gaining a way to approve, authorize,
execute or roll back anything.

Every request passes, in order:

```
authentication (hashed API key)
  → organization            (derived FROM THE KEY)
    → scope                 (closed world)
      → resource authorization (the resource's own organization)
        → existing V3 security controls (unchanged)
```

### Deliberate absences

These are design decisions, not gaps:

- **No endpoint accepts an organization identifier.** The tenant comes from
  the key. A key cannot reach another organization, and a body naming a
  tenant is rejected (`extra="forbid"` → `422`).
- **No endpoint accepts a URL, owner, or remote address.** Every GitHub
  destination derives from trusted integration state, so the API is not an
  SSRF proxy.
- **No endpoint declares security state.** Only server-computed
  verification is ever reported as a verdict.

---

## 2. Scope → endpoint backing

A scope is a closed world, and a scope grants nothing by itself: it gates an
endpoint that independently re-checks the organization and the V3 chain.

| Scope | Impact | Endpoint |
|---|---|---|
| `repositories:read` | read | `GET /repositories` |
| `findings:read` | read | `GET /findings` |
| `scans:read` | read | `GET /scans`, `GET /scans/{scan_id}` |
| `actions:read` | read | `GET /actions` |
| `executions:read` | read | `GET /executions` |
| `verifications:read` | read | `GET /verifications` |
| `rollback:read` | read | `GET /rollbacks` |
| `audit:read` | read | `GET /audit/chains` |
| `audit:verify` | read | `GET /audit/chains/{chain_id}/verify` |
| `integrations:read` | read | `GET /integrations` |
| `scans:create` | **high** | `POST /scans` |

**Not issuable yet** (`PLANNED_API_SCOPES` in `services/v4_rbac.py`):
`findings:write`, `actions:create`, `executions:create`, `rollback:create`,
`integrations:manage`, `audit:export`. Each awaits the endpoint that would
enforce it. They are rejected at issuance (`INVALID_API_KEY_SCOPES`) rather
than accepted as inert decoration — a scope advertised as a control that does
not exist is worse than no scope.

There is **no `admin:*`**, and no scope can manage members, policy,
operations or quotas.

---

## 3. Authentication

```
Authorization: Bearer cyv_<prefix>_<secret>
```

- The key is resolved by the SHA-256 hash of the **full** plaintext; only the
  hash is stored.
- Missing, malformed, unknown, revoked and expired keys all produce
  `401 API_KEY_INVALID` — the response never distinguishes them.
- The **organization is derived from the key row**.

`GET /me` returns the identity the server derived, never the secret:

```json
{
  "organization_id": "…",
  "key_name": "CI pipeline",
  "key_prefix": "1f3a9c02",
  "scopes": ["scans:read", "scans:create"],
  "read_only": false,
  "api_version": "v1"
}
```

---

## 4. Endpoints

All collection endpoints return the same bounded envelope (§5).

### `GET /api/v1/me`
Scope: none beyond a valid key.

### `GET /api/v1/repositories`
Scope `repositories:read`. Filter: `is_active` (bool).

### `GET /api/v1/findings`
Scope `findings:read`. Filters: `severity`, `status`, `source_type`,
`repository_id`. Filter values are **allowlisted**; an unrecognised value is
refused with `400 INVALID_FILTER` rather than silently ignored.

### `GET /api/v1/actions`
Scope `actions:read`. Filters: `status`, `repository_id`.

### `GET /api/v1/scans`
Scope `scans:read`. Filters: `status` (allowlisted), `repository_id`.

### `GET /api/v1/scans/{scan_id}`
Scope `scans:read`. A scan outside the key's organization is `404`.

### `GET /api/v1/executions` · `GET /api/v1/verifications` · `GET /api/v1/rollbacks`
Scopes `executions:read`, `verifications:read`, `rollback:read`.
Verification `result` is server-computed; the API reports it and can never
accept, infer or override a verdict.

### `GET /api/v1/integrations`
Scope `integrations:read`. GitHub installations bound to this organization.
Credential material is never exposed.

### `GET /api/v1/audit/chains`
Scope `audit:read`.

### `GET /api/v1/audit/chains/{chain_id}/verify`
Scope `audit:verify`. Verification is performed **server-side**; the client
receives a verdict (`VALID` / `INVALID` / `EMPTY` / `UNSUPPORTED_VERSION`)
with machine-readable issue codes, or nothing. A client never computes
digests.

### `POST /api/v1/scans` — the only public mutation
Scope `scans:create` (high impact). Body:

```json
{ "repository_id": "…", "commit_sha": "40-hex (optional, V4.1)" }
```

Returns **`202 Accepted`**:

```json
{ "scan_id": "…", "repository_id": "…", "status": "QUEUED", "reused": false }
```

This is a **request**, not an execution. It can only name a repository the
key's organization owns (otherwise `404`), and it cannot approve, authorize,
execute, verify or roll back anything — those remain session-authenticated
console operations with their full V3 chain.

**Commit binding (V4.1).** The optional `commit_sha` (full 40-character
hex; uppercase is normalized to lowercase) pins the request to a commit.
The binding is VERIFIED by the worker against the actual clone: a mismatch
fails the scan with `COMMIT_MISMATCH` rather than analyzing a different
commit silently. See `v4-async-jobs.md` §3.

**Quotas (V4.1).** Submissions consume the organization's daily scan quota
and the platform's global quota; exhaustion is `429 QUOTA_ORG_EXCEEDED` /
`QUOTA_GLOBAL_EXCEEDED` (`v4-quotas.md`). The request is also audited as
`SCAN_REQUESTED` on the organization's V3.8 chain.

### `GET /api/v1/scans/{scan_id}/status` — async job status (V4.1)
Scope `scans:read`. Machine-readable job view with SERVER-computed `result`
(`PASS`/`FAIL`/null/`INCONCLUSIVE`) and `commit_binding`
(`UNBOUND`/`PENDING`/`VERIFIED`/`MISMATCH`/`INCONCLUSIVE`). A CI caller can
never declare its own security outcome. See `v4-async-jobs.md`.

---

## 5. Collection envelope, pagination and limits

```json
{
  "items": [ … ],
  "next_cursor": "eyJ…",
  "has_more": true
}
```

> **Documented v1 change.** In V4.0 these four endpoints returned a bare
> JSON array. V4.1 returns the paginated envelope above. This was corrected
> deliberately, before the API had external consumers (nothing in the
> platform or console calls `/api/v1`): an unbounded array lets one tenant
> force an arbitrarily large read, and a limit-only array cannot be paged
> stably. Error bodies keep the V4.0 `detail` field, so failure handling
> written against V4.0 is unaffected.

- `limit`: 1–200, default 50. Out of range → `422`.
- `cursor`: opaque keyset cursor over `(created_at DESC, id DESC)`. A cursor
  is used rather than an offset because these collections are appended to
  while a client pages: an offset would silently skip or repeat rows.
- A malformed cursor → `400 INVALID_CURSOR`. Never silently ignored.

---

## 6. Idempotency

Send `Idempotency-Key` on a mutation to make retries safe.

| Case | Result |
|---|---|
| same key, same request | the original outcome is replayed; the side effect happens **once** |
| same key, different request | `409 IDEMPOTENCY_KEY_REUSED` — the other request's result is never returned |
| different key | a distinct operation |
| no key | a new operation every time (documented, not implied safe) |
| malformed key | `400 IDEMPOTENCY_KEY_INVALID` — refused, not ignored |
| key still in flight | `409 IDEMPOTENCY_IN_PROGRESS` |
| key expired (24 h) | reclaimable as a new operation |

Key format: 8–200 characters from `A-Za-z0-9_-.:`.

Properties that make this real rather than decorative (see
`v4-api-security.md` §4): the record commits **with** the effect, the
database's unique constraint decides concurrency, and authorization is
re-evaluated on every request so a replay can never bypass a capability
check.

---

## 7. Errors

```json
{
  "detail": "API_SCOPE_REQUIRED",
  "code": "API_SCOPE_REQUIRED",
  "message": "This API key does not carry the required scope.",
  "request_id": "9f2c…",
  "details": { … }
}
```

`detail` is preserved from the V4.0 shape (the same token), so the envelope
is additive.

| Status | Code | Meaning |
|---|---|---|
| `400` | `INVALID_IDENTIFIER`, `INVALID_CURSOR`, `INVALID_FILTER`, `IDEMPOTENCY_KEY_INVALID` | malformed request |
| `401` | `API_KEY_REQUIRED`, `API_KEY_INVALID` | no usable key |
| `403` | `API_SCOPE_REQUIRED` | key lacks the endpoint's scope |
| `404` | `REPOSITORY_NOT_FOUND`, `SCAN_NOT_FOUND`, `AUDIT_CHAIN_NOT_FOUND`, `NOT_FOUND` | not in this organization, or absent (indistinguishable) |
| `409` | `IDEMPOTENCY_KEY_REUSED`, `IDEMPOTENCY_IN_PROGRESS`, `REPOSITORY_INACTIVE`, `SCAN_IN_PROGRESS` | state conflict |
| `422` | `VALIDATION_ERROR` | schema failure |
| `429` | `ORG_RATE_LIMITED`, `QUOTA_ORG_EXCEEDED`, `QUOTA_GLOBAL_EXCEEDED` | budget/quota exhausted |
| `503` | `ANALYSIS_UNAVAILABLE`, `QUOTA_UNAVAILABLE` | queue or quota enforcement unavailable (fail closed) |

Response-security properties: no stack traces, SQL, filesystem paths, or
secrets; `422` exposes only each error's *field path* and *rule name* — never
the submitted value (which may be a credential). `request_id` is echoed as a
header and in the body for triage.

---

## 8. Rate limits

| Class | Limit | Bucket |
|---|---|---|
| reads (all read endpoints) | 600 / hour | `v1-read` |
| mutations | 60 / hour | `v1-write` |

All reads share one bucket and all writes share another, so a caller cannot
multiply its budget by spreading requests across endpoints. Buckets are
namespaced per organization, so one tenant cannot consume another's.

Headers are returned on success **and** on `429`:

```
x-ratelimit-limit: 60
x-ratelimit-remaining: 42
x-ratelimit-reset: 1770000000
x-ratelimit-class: v1-write
```

They describe only the caller's own organization. The limiter fails closed:
if Redis is unreachable the request is refused rather than allowed.

---

## 9. OpenAPI

The schema `/openapi.json` is generated from the implementation and
annotated so it reflects reality:

- an `ApiKeyBearer` (HTTP bearer) security scheme, declared on **every**
  `/api/v1` operation and on **no** internal operation;
- `info.version` = `4.1.0`;
- response documentation for `401`, `403`, `404`, `409`, `429`.

Nothing is documented that the server does not enforce, and no example
contains a credential.

---

## 10. Versioning

Within `v1`, changes are additive: new optional fields, new endpoints. No
field is renamed, retyped, or has its meaning changed, and no new `v1`
endpoint will introduce a scope that can approve, authorize, execute or
administer. Breaking changes require `/api/v2`. The unversioned console
routes (`/api/orgs`, `/api/actions`, …) are internal and outside this
promise.

The one v1 change made so far — the list envelope in §5 — is documented
above rather than shipped silently, and was made before external adoption.

---

## 11. Not yet implemented (explicit)

So nothing here is mistaken for a shipped control:

- **Outbound webhooks** (signing, delivery ids, retry, dead-letter) — not
  implemented. The inbound GitHub webhook is implemented: see
  `v4-webhooks.md`.
- **Mutation scopes** — `actions:create`, `executions:create`,
  `rollback:create`, `integrations:manage`, `audit:export` remain designed
  but not issuable (§2): their request-only endpoints do not exist yet.
- **CI event ingestion as a distinct event type** — CI integrates today by
  submitting commit-bound scans through `POST /scans` with the thin GitHub
  Action (`v4-cicd.md`); a dedicated CI-event intake with its own audit
  events (`CI_EVENT_*`) is designed and registered but not wired.
- **`GET /api/v1/jobs` list and `POST /jobs/{id}/cancel`** — not
  implemented (`v4-async-jobs.md` §5 states the semantics honestly).
- **Metrics gauges from workers** — `queue_depth`/`active_jobs` are
  registered but not yet exported by the worker process (`v4-metrics.md`
  §4).
- **Load-test certification at platform scale** — failure-injection and
  race suites run on real PostgreSQL + Redis; a bounded load-test harness
  is still outstanding (see `roadmap-v3.md` V4.1 status).

---

## 12. Tests

| Concern | Where |
|---|---|
| Scopes, rotation, idempotency, errors, pagination, isolation, headers, OpenAPI | `tests/test_v41_public_api.py` (48 tests) |
| Race safety on real PostgreSQL: rotate × rotate, rotate × revoke, revoke × N, duplicate idempotency × N, same-key-different-request | `tests/test_v41_races.py` (6 tests, 10 repetitions/class) |
| Quota / webhook-replay / audit-chain races (real PostgreSQL + Redis) | `tests/test_v41_boundary_races.py` (5 tests, 10 repetitions/class) |
| Webhooks: signatures, replay, bindings, allowlist, records | `tests/test_v41_webhooks.py` (25 tests) |
| CI: commit binding, result semantics, action mapping | `tests/test_v41_cicd.py` (11 tests) |
| Failure injection: Redis/queue/audit failures | `tests/test_v41_failures.py` (6 tests) |
| Audit integration, quotas, metrics, job semantics | `tests/test_v41_integration.py` (22 tests) |
| Migration 013 tables + invariants | `tests/test_migrations.py` |
| Tenant isolation for API keys | `tests/test_v4_platform.py` |
