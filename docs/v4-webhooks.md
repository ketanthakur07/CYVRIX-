# CYVRIX V4.1 — Inbound GitHub Webhooks

Status: IMPLEMENTED (this document is the contract)
Source: `apps/api/app/services/webhook_service.py`, `apps/api/app/routes/webhooks.py`
Replay primitive: `services/idempotency_service.py` (migration 013)
Related: `v4-api-security.md` (§4 idempotency), `v4-cicd.md`, `v4-async-jobs.md`

---

## 1. The security chain (normative)

```
GitHub
  → signature verification (HMAC-SHA-256, constant-time)
  → replay protection (delivery id, DB-unique per tenant)
  → event allowlist
  → installation binding (from TRUSTED DB state, never the payload)
  → organization binding (installation → organization)
  → repository binding (github_repo_id → repository row)
  → commit binding (push head SHA, verified later at clone)
  → enqueue ONE analysis request
  → audit (V3.8 chain) + metrics
```

The webhook can ONLY request analysis. There is no code path — none —
from a webhook to approval, authorization, execution, verification or
rollback. `WEBHOOK → REMEDIATION` is impossible by construction.

The endpoint is `POST /api/webhooks/github` (fixed route, SERVICE-class).
It is the only route in the platform that accepts unauthenticated
traffic, and every response is one of: `202` (accepted), `200` (unknown
event, safely ignored), `400` (bad delivery id / payload), `401`
(signature), `404` (unbound installation/repository/org), `409`
(replay / conflict / scan already running), `413` (oversized), `429`
(IP or org rate limit), `503` (enqueue failed / secret unconfigured).

---

## 2. Signature verification

GitHub's `X-Hub-Signature-256` (HMAC-SHA-256 over the raw request body).

| Input | Result |
|---|---|
| header absent/empty | `401 SIGNATURE_MISSING` |
| wrong secret or tampered body | `401 SIGNATURE_INVALID` |
| non-`sha256=` prefix, wrong length, non-hex | `401 SIGNATURE_MALFORMED` |
| `GITHUB_WEBHOOK_SECRET` unconfigured | the whole intake is disabled: `503 WEBHOOK_SECRET_NOT_CONFIGURED` (fail closed — an unsigned intake is never offered) |

Comparison is `hmac.compare_digest` over the exact bytes GitHub signed.
The secret is never logged, never echoed, never stored; the delivery
record stores only a signature STATE (`VALID`/`INVALID`/`MISSING`/
`MALFORMED`/`UNCONFIGURED`).

---

## 3. Replay protection

One delivery id → at most one side effect, enforced twice:

1. **The idempotency primitive** (`UNIQUE(organization_id, scope,
   key_value)` with scope `webhook:<event>`), which stores the original
   outcome. A redelivered event whose original attempt COMPLETED
   replays the original scan id with `created=False` — the route does
   NOT enqueue again, so a lost response followed by a GitHub redelivery
   cannot double-scan.
2. **The delivery record** (`UNIQUE(organization_id,
   github_delivery_id)`), the DB-level backstop.

| Case | Result |
|---|---|
| same delivery id, same payload digest | replay: original scan id, no new side effect |
| same delivery id, DIFFERENT payload digest | `409 DUPLICATE_DELIVERY` — an attacker probing key reuse never gets the other request's result |
| same delivery id, different organization | a DISTINCT record (replay protection is tenant-scoped) |

Records expire after 7 days (`WEBHOOK_REPLAY_TTL_HOURS`): bounded
retention, plain indexed cleanup.

---

## 4. Event allowlist

`push`, `pull_request`, `installation`, `installation_repositories`.

- `push` → the full chain above (the one event that causes analysis).
- The others → recorded (`ACCEPTED`, reason `NO_ACTION_FOR_EVENT`),
  no side effect.
- Anything else → `200`, safely ignored (documented semantics; an
  allowlist miss must not be an outage), counted in
  `webhooks_rejected_total{reason="EVENT_NOT_ALLOWED"}`.

---

## 5. Binding (trusted state only)

- The payload's `installation.id` is a SELECTOR. The row is resolved
  from the database; an unknown installation number is `404` — a webhook
  for an installation CYVRIX does not hold never reaches the pipeline.
- The installation must carry an `organization_id` (V4 tenancy). A
  legacy unbound installation is refused (`ORGANIZATION_UNRESOLVED`),
  fail-closed: there is no tenant to rate-limit or audit to.
- The repository is resolved via
  `github_repo_id AND installation_id`: a repository that belongs to a
  DIFFERENT installation row is `404` even if the payload is internally
  consistent. Fork/owner/renamed-repo confusion dies here.
- No payload field can ever select the tenant. There is no code path
  that accepts `organization_id` from a webhook.

---

## 6. Commit binding

The push's `after` (head SHA) must be a full 40-hex commit id; the
payload's commit list is bounded before counting; the `ref` string is
length-bounded and control-character-stripped, and only ever stored as
the delivery record's `ref` — never interpolated into commands, queries
or metric labels.

The SHA is stored as `scans.requested_commit_sha`. The WORKER verifies
it against the actual clone (`docs/v4-async-jobs.md` §3): a mismatch
fails the scan with `COMMIT_MISMATCH`. A stale push is never silently
analyzed at a different commit, and its result is never attributed to
one.

---

## 7. Flood control (Phase 42)

| Limit | Scope | Default |
|---|---|---|
| pre-authentication | per source IP | 240/hour |
| post-binding | per organization | 1200/hour |

Both fail closed (Redis unreachable → refuse). The IP limit binds a
flood before parsing/DB work; the org limit is the strong one. Both are
server configuration (`webhook_ip_rate_limit_per_hour`,
`webhook_rate_limit_per_hour`); no client can raise them.

---

## 8. Bounded intake

- Body size capped at 10 MiB (`webhook_max_payload_bytes`), checked on
  `Content-Length` AND the actual body → `413`.
- JSON payload bounded structurally (≤200 top-level keys) before any
  semantic use.
- Delivery ids are charset- and length-checked before becoming
  idempotency keys.

---

## 9. Records and audit

**`webhook_deliveries`** is a structured SECURITY RECORD, not a log:
delivery id, event type, signature state, outcome, allowlisted reason
code, resolved installation/repository PKs, commit SHA, ref, derived
scan id. There is NO payload column — the table cannot become a shadow
store of repository content. Refused deliveries are stored tenant-less
(`organization_id NULL`): the installation cannot be trusted, so the
row claims no tenant.

**V3.8 audit chain events** (org-level chain, `docs/v4-async-jobs.md`
§4): `WEBHOOK_ACCEPTED` (OPERATIONAL), `WEBHOOK_REJECTED`
(SECURITY-CRITICAL), `WEBHOOK_REPLAY_REJECTED` (SECURITY-CRITICAL).
Payloads contain only `{event_type, signature_state}` — no branch
names, no commit messages, no payload content.

**Metrics**: `webhooks_received_total{event}`,
`webhooks_rejected_total{reason}`, `webhooks_replayed_total`.

---

## 10. Failure behavior (tested)

| Failure | Behavior |
|---|---|
| audit chain append fails on ACCEPTED | acceptance stands (the delivery row IS the record); failure logged loudly; no 500 |
| enqueue fails after acceptance | `503`, no scan left in QUEUED |
| worker dies after acceptance | GitHub redelivers (or not); the delivery claim makes redelivery idempotent |
| DB failure mid-processing | transaction rolls back atomically (reservation + scan + delivery record) |

Tests: `tests/test_v41_webhooks.py` (25), failure paths in
`tests/test_v41_failures.py` (6), races in
`tests/test_v41_boundary_races.py` (real PostgreSQL).
