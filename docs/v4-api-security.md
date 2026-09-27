# CYVRIX V4.1 — API Security Model

Status: IMPLEMENTED
Related: `v4-security.md` (platform model), `v4-public-api.md` (contract),
`v4-threat-model.md` (adversary enumeration), `v4-rbac.md` (capabilities).

This document covers the parts of the security model that exist **because**
there is now an external interface: key lifecycle, scope enforcement,
idempotency safety, and the properties the public surface must not weaken.

---

## 1. The single rule, specialized

> **The backend is always the authority. A field the client sends is a
> selector the backend verifies — never a decision the backend accepts.**

For the public API this means, concretely:

| Value | Where it may appear | Treated as |
|---|---|---|
| API key | `Authorization` header | identity — hashed lookup, single indexed probe |
| organization | **nowhere** | derived from the key row |
| scope | **nowhere** | derived from the key row |
| resource id | path / body | a selector, verified through the organization join |
| `Idempotency-Key` | header | a label for the *operation*, never an authorization |
| repository / owner / URL of the target repo | body | **not accepted at all** |

A request that names a tenant (`{"organization_id": …}`) is rejected by
schema (`extra="forbid"` → `422`), not ignored. Ignoring it would leave a
caller believing it had selected a tenant.

---

## 2. Key lifecycle

### Generation

- Secret: `secrets.token_urlsafe(32)`; prefix: `secrets.token_hex(4)`.
- Plaintext form `cyv_<prefix>_<secret>` is returned **exactly once**.
- Only `SHA-256(plaintext)` is persisted. A database read yields no usable
  credential.
- Never logged. `prefix` is the only key-derived value intended for logs,
  the console and audit.

### Authentication

- Resolved by exact hash comparison (`secrets.compare_digest`).
- Revoked → `None`. Expired → `None`. Unknown prefix → `None`. All surface
  as the same `401 API_KEY_INVALID`, so the endpoint leaks no distinction
  between "no such key" and "key was revoked".
- `last_used_at` is recorded on success, giving operators a leak-detection
  signal.

### Rotation (V4.1)

`POST /api/orgs/{id}/api-keys/{key_id}/rotate` — old key in, new key out.

| Property | How |
|---|---|
| Old key dies immediately | revoked **before** the successor is returned |
| No silent privilege gain | successor inherits the same name and scopes |
| No silent lifetime extension | successor **preserves the original `expires_at`** |
| Deterministic under concurrency | the old key is revoked with one conditional `UPDATE … WHERE revoked_at IS NULL`; only the transaction that changed a row mints a successor |
| Loser is told it lost | `409 API_KEY_ALREADY_REVOKED` (never a second live successor) |

Verified on real PostgreSQL with 10 repetitions: 1 winner, 1 refusal, exactly
1 live key per lineage.

### Revocation

Idempotent and final. 10 concurrent revokes leave one revoked row, and the
secret authenticates no more. There is no "unrevoke".

---

## 3. Scope enforcement

- Scopes are a **closed world** (`API_SCOPES`). `is_valid_api_scope` rejects
  anything else, so a caller cannot invent a scope name and have it honoured.
- Issuance validates the scope set (`INVALID_API_KEY_SCOPES`).
- Use is checked per endpoint (`require_api_scope`), producing
  `403 API_SCOPE_REQUIRED`.
- **A scope grants nothing by itself.** It gates an endpoint; the endpoint
  independently re-checks the organization and, for anything with side
  effects, the V3 chain. Holding `scans:create` is permission to *ask*.
- **`PLANNED_API_SCOPES` are refused at issuance** so the platform never
  advertises a control it does not enforce.
- No scope administers the organization: there is no `admin:*`, and no scope
  can manage members, policy, operations or quotas.

### Known finding (documented, not hidden)

`HIGH_IMPACT_SCOPE_REQUIRES_ADMIN` in `create_api_key` is currently
**unreachable**: every role that holds `CAP_MANAGE_API_KEYS` also holds
`CAP_MANAGE_MEMBERS`. That is not a hole — it means high-impact scope
issuance already requires `ORG_ADMIN`/`ORG_OWNER` standing, which is the
intended property. The guard is retained as defence in depth, and
`test_high_impact_issuance_requires_admin_standing_by_construction` pins the
property that makes it unreachable, so tightening or relaxing the role ladder
fails loudly instead of silently opening a hole.

### Key lifecycle is now hash-chained (V4.1)

Key events land in the organization's V3.8 audit chain:

- `API_KEY_CREATED` and `API_KEY_ROTATED` are **fail-closed**: the audit
  append is part of the same transaction, so a credential can never be
  minted or transferred without its witness (tested: an audit failure
  aborts creation and no key row persists).
- `API_KEY_REVOKED` is a best-effort witness: the revocation is the
  protective act and is already committed by the time the append runs;
  failing the operation afterwards could not un-revoke, so the failure is
  logged loudly instead.
- Only the key PREFIX (designed for logs) and server-side facts enter the
  chain. Never the plaintext secret, never the hash.
- The chain itself is per-ORGANIZATION for key-only tenants (zero
  installations) — `v4-async-jobs.md` §4 — and its tamper evidence is
  inherited from V3.8 and tested (direct-DB payload mutation is detected).

---

## 4. Idempotency: three properties that make it load-bearing

The primitive lives in `services/idempotency_service.py` and is shared with
future webhook replay protection.

1. **The record commits with the effect.** The reservation row is inserted
   inside the caller's transaction, so "the effect happened" and "we recorded
   that we did it" cannot diverge. A crash between them rolls back both.
2. **The database decides concurrency.** `UNIQUE(organization_id, scope,
   key_value)` means a duplicate cannot insert a second record. Postgres
   makes the loser *wait* on the index until the winner commits, then raises a
   unique violation — so the loser observes a committed outcome, never a torn
   one.
3. **Authorization is never cached.** `reserve()` runs only after
   authentication, organization resolution and scope checks have passed, and
   the record is tenant-scoped. A replay can therefore never skip a
   capability recheck, and a key value used by organization A can never match
   organization B's record.

| Attack | Outcome |
|---|---|
| Replay a request to duplicate a side effect | one effect; the original outcome is replayed |
| Same key, different body, hoping for the other result | `409` — the other request's result is never returned |
| Steal another tenant's key value to read their outcome | distinct record per tenant; no cross-tenant match |
| Send a malformed key to look protected | `400` — refused, not silently ignored |
| Hold a key open forever | bounded: records expire (24 h) and are reclaimable; `IN_PROGRESS` never returns a partial result |

Scope namespaces the record, so the same key value against two operations is
two distinct operations.

---

## 5. Rate limiting

Organization-scoped, class-based, fail-closed.

- One bucket for all reads (`v1-read`, 600/h) and one for all writes
  (`v1-write`, 60/h), so **alternate-endpoint bypass is not possible** — a key
  cannot multiply its budget by rotating which endpoint it calls.
- Buckets are namespaced `ratelimit:org:<org_id>:<class>:<window>`, so one
  tenant cannot consume or observe another's budget.
- Headers (`limit`/`remaining`/`reset`/`class`) are returned on success and on
  `429`, and describe only the caller's own organization.
- **Fails closed**: if Redis is unreachable, `check_rate_limit` returns
  not-allowed → `429`. A limiter that degrades to "allow" under load is a
  bypass, not a degradation.

---

## 6. Response and error security

- Errors are content-free: no stack traces, SQL, filesystem paths, tokens or
  internal identifiers.
- `422` bodies expose only each error's **field path** and **rule name**.
  Pydantic can carry the offending *input*, which for a security API may be a
  credential, so the input is deliberately dropped.
- `404` is uniform for "absent" and "not in your organization", preserving
  the platform's existence-hiding rule. A non-member cannot use the API to
  enumerate tenants or resources.
- `request_id` is echoed for triage without exposing internals.
- The public envelope is scoped to `/api/v1` only; the console API keeps its
  existing shape, so this change does not alter internal behaviour.

---

## 7. Tenant isolation on the public surface

- Every list and detail query is built from the key's organization through
  the ownership join
  (`organization → github_installations → repositories → findings/actions/…`).
- A row from another organization is **never selected**, not filtered out.
- `GET /scans/{id}` for another tenant is `404`; `POST /scans` with another
  tenant's `repository_id` is `404` (not `403`), so the endpoint cannot be
  used to probe which repositories exist elsewhere.
- Audit chains resolve through the installation's organization, so chain
  verification is tenant-scoped too.

---

## 8. What the public API cannot do (V3 chain preservation)

| Control | Public API |
|---|---|
| Policy evaluation | unreachable — no public mutation reaches policy |
| Human approval | no endpoint; approval stays a session-bound console transition |
| Execution authorization | no endpoint |
| Sandbox execution | no endpoint |
| Verification / rollback | read-only reporting of server-computed results |
| Operational controls | no endpoint |
| Audit | read + server-side verify; no write path |

The single public mutation submits an analysis **request**. The
`OPENAPI`-derived test in `TestNoChainBypass` asserts a CLOSED mutation
set (V4.2: the scan request plus the request-only mutation endpoints of
§2.1 — nothing else), so an accidental new mutation fails the build rather
than shipping. A public key can never approve, authorize, mint a token, or
execute: the V3 chain's write surface stays session/service-only.

---

## 9. Failure behaviour

| Failure | Behaviour |
|---|---|
| Redis unavailable (limiter) | `429` — fail closed |
| Redis unavailable (quota) | `503 QUOTA_UNAVAILABLE` — fail closed (`v4-quotas.md` §5) |
| Redis unavailable (queue) | `503 ANALYSIS_UNAVAILABLE`; the scan row is marked `FAILED` with `ENQUEUE_FAILED` so no request hangs in `QUEUED` with no worker; the idempotency record stores the SAME error envelope the client received, so a retry replays it byte-identically |
| Database unavailable | request fails; no partial effect (the idempotency record rolls back with it) |
| Concurrent duplicate | one effect; the loser observes a committed outcome |
| Concurrent rotation | one successor; the loser gets a specific conflict |
| Webhook signature invalid | `401`; no tenant resolution, no reservation, no side effect |
| Audit append fails on key creation/rotation | the OPERATION fails — no unwitnessed credential (fail closed) |
| Malformed cursor / filter / idempotency key | refused with a specific reason code, never silently ignored |

`503` is a notable honest case: the ambiguous "did the queue accept it?"
situation is resolved by recording the failure and completing the
idempotency record with it, so a retry with the same key replays the same
deterministic answer, and a retry with a new key is a clean new attempt.

---

## 10. Explicitly not yet done

Stated so none of it is assumed covered:

- **`findings:write`**: remains planned, non-issuable — no endpoint
  enforces it.
- **`queue_depth` gauge export**: registered, not yet exported by the
  worker process (`active_jobs` IS exported as of V4.2).
- **Load-test certification at platform scale**: failure-injection and race
  suites run on real PostgreSQL + Redis; a bounded load-test harness remains
  outstanding.

Shipped in V4.2 (previously listed here as not done):

- **Outbound webhooks** — org-scoped subscriptions, HMAC-SHA-256 signing
  with stable delivery ids, closed-world event registry, SSRF protection
  (https-only, global-unicast-only resolution, connection-time
  revalidation, no redirects, no proxy env), bounded retries with backoff +
  full jitter, dead-letter, DB-unique idempotency, per-org/endpoint rate
  limits, `WEBHOOK_*` audit events (`v4-webhooks.md` §12–15).
- **Dedicated CI event intake** — `POST /api/ci/events` (`ci:ingest`,
  HIGH_IMPACT): org→installation→repository resolved from trusted state
  only, `event_id` idempotency on `UNIQUE(organization_id, repository_id,
  event_id)`, worker-verified commit binding (`CI_EVENT_COMMIT_MISMATCH`),
  full `CI_EVENT_*` audit chain, machine-readable results (`ACCEPTED` /
  `REJECTED` / `ALREADY_PROCESSED` / `FAILED` / `UNAVAILABLE` — the result
  is server-set and NEVER `PASS`; there is still no path by which CI
  states a security verdict).
- **Mutation scopes** (`actions:create`, `executions:create`,
  `rollback:create`, `integrations:manage`, `audit:export`): now issuable
  (HIGH_IMPACT — ORG_ADMIN standing required at issuance) with enforcing
  request-only endpoints; the V3 chain is preserved unchanged
  (`v4-public-api.md` §2.1).
- **Worker `active_jobs` gauge**: heartbeat-published per worker,
  fleet-aggregated on `GET /api/ops/metrics`, TTL crash recovery
  (`v4-metrics.md` §4).

---

## 11. Invariants this increment establishes

1. The public API is versioned (`/api/v1`), and its OpenAPI declares real
   authentication.
2. API keys are hashed; only the hash is stored.
3. A key is bound to exactly one organization, derived from the key.
4. A key is bound to a closed-world scope set, refused at issuance if invalid.
5. A revoked key fails immediately.
6. An expired key fails.
7. A client cannot escalate its own scopes; unbacked scopes are not issuable.
8. A client cannot choose its organization; naming one is a validation error.
9. The public API cannot bypass V3 authorization — only one mutation exists,
   and it is a request.
10. Public mutations are idempotent when a key is supplied, and the record is
    tenant-scoped.
11. The same idempotency key with a different request is refused.
12. Rate limits cannot be bypassed by switching endpoints, and fail closed.
13. Cross-tenant access is impossible on every public endpoint.
14. API errors reveal no secrets and no submitted values.
15. Verification results are always server-computed.
16. Webhooks and CI never state a security verdict: CI results are
    server-set (`ACCEPTED`/`REJECTED`/`ALREADY_PROCESSED`/`FAILED`/
    `UNAVAILABLE` — never `PASS`), and outbound webhook payloads carry no
    repository content.
