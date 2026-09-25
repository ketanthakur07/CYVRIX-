# CYVRIX V4.1 — Quotas

Status: IMPLEMENTED (this document is the contract)
Source: `apps/api/app/quota_service.py`, wired in `routes/api_v1.py`
(`_enforce_quota`), limits in `app/config.py`
Related: `v4-api-security.md` §5 (rate limits), `v4-public-api.md` §8

---

## 1. Quotas vs rate limits

```
rate limit  = burst protection per window (fixed window, per class)
quota       = absolute ceiling per period (per organization, per action)
```

Both are server-enforced, both fail closed, and neither can be raised by
a client: limits come from server configuration only, and no endpoint
accepts a quota parameter.

---

## 2. Hierarchy and precedence (Phase 31)

```
GLOBAL  (platform ceiling — consumed by every organization)
  → ORGANIZATION  (per-tenant ceiling)
```

The GLOBAL quota is consumed FIRST, the ORGANIZATION quota second; a
request is admitted only when BOTH have capacity. If the global ceiling
is exhausted, every tenant is refused until the window resets — a
platform-scale fuse, not a per-tenant complaint.

## 3. Current limits (daily, per action)

| Action | Organization | Global |
|---|---|---|
| `scans` (all triggers: API, CI, webhook) | `quota_scans_org_per_day` = 200 | `quota_scans_global_per_day` = 5000 |

An action that is not registered refuses (`503 QUOTA_UNAVAILABLE` at the
service boundary): there is no unlimited tier, so an action gains quota
enforcement only by being added to the table explicitly.

---

## 4. Atomicity (Phase 32)

Enforcement is a Redis pipeline of two `INCR`s — never a
read-then-increment in Python. Two simultaneous requests around the
final slot cannot both be admitted: the database-equivalent atomic
counter decides.

Refusals are COMPENSATED (the over-consuming increment is decremented
back), so a refused request never burns capacity:

- global refusal → global counter restored; org counter never touched
- org refusal → both restored

Verified on real Redis with 12 concurrent requests against a limit of 5:
exactly 5 admitted, every refusal compensated, final counter exactly 5
(`tests/test_v41_boundary_races.py::TestQuotaRaces`).

---

## 5. Fail-closed (Phase 41)

Redis unreachable → the request is REFUSED (`429` from the rate limiter,
which runs first, or `503 QUOTA_UNAVAILABLE` if the limiter passed and
quota refused). A quota that degrades to "allow" under infrastructure
failure is a bypass, not a degradation. The service-level refusal is
tested directly with a dead Redis.

---

## 6. Refusal contract

| Case | Status | Code |
|---|---|---|
| organization ceiling reached | `429` | `QUOTA_ORG_EXCEEDED` |
| global ceiling reached | `429` | `QUOTA_GLOBAL_EXCEEDED` |
| Redis unavailable | `503` | `QUOTA_UNAVAILABLE` |
| action not registered | `503` | `QUOTA_UNAVAILABLE` |

Org refusals are audited as `QUOTA_LIMIT_REACHED` on the org chain
(best-effort: the refusal itself is the protection; the event is the
witness). Refusals are counted in `api_quota_rejections_total{scope}`.

Window: fixed 24h (`period_seconds=86400`), keys
`quota:org:{org_id}:{action}:{window_start}` and
`quota:global:{action}:{window_start}`.

---

## 7. Noisy-neighbor property (Phase 33)

One organization cannot exhaust shared capacity beyond its own quota,
and the GLOBAL quota is the sum-ceiling that protects the platform from
aggregate abuse (e.g. a compromised tenant fanning out through many
keys — all keys of one org share the org quota; distinct orgs share the
global one). Rate limits bound the burst; quotas bound the total.
