# CYVRIX V4.1 — CI/CD Integration

Status: IMPLEMENTED (this document is the contract)
Source: `.github/actions/cyvrix-ci/index.js`,
`.github/workflows/cyvrix-analysis.yml.example`,
public API: `apps/api/app/routes/api_v1.py`
Related: `v4-webhooks.md`, `v4-async-jobs.md`, `v4-public-api.md`

---

## 1. Trust model (normative)

```
CI (GitHub Action)
  → authenticated (scoped CYVRIX API key)
  → commit-bound (GITHUB_SHA, verified server-side at clone)
  → tenant-bound (the key's organization)
  → server-verified result (CI never declares its own security state)
```

`CI → AUTOMATIC AUTHORIZATION` is impossible: no CI path reaches policy,
approval, execution authorization, sandbox or verification. CI requests
analysis; the existing V3 chain remains the only authority for anything
that changes a repository.

---

## 2. The thin client (GitHub Action)

`.github/actions/cyvrix-ci/index.js` — a single-purpose JavaScript
action that:

1. resolves the repository id through `GET /api/v1/repositories`
   (scoped read; the id is looked up, never accepted from workflow
   input);
2. submits `POST /api/v1/scans` with `{repository_id, commit_sha:
   GITHUB_SHA}` and an `Idempotency-Key` derived from
   `(repository, commit)` — a retried workflow cannot create duplicate
   scans;
3. polls `GET /api/v1/scans/{id}/status` and exits on the
   SERVER-computed `result`.

Static checks in `tests/test_v41_cicd.py` pin that the action references
ONLY `/api/v1` endpoints and can never reach the console/V3 surface.

### Credentials

The Action receives ONLY a CYVRIX API key with `scans:read` +
`scans:create` (or `scans:read` alone for status-only use). No such
thing as a key that can approve, authorize, execute, roll back or
administer exists in the scope registry, so the Action cannot be
over-privileged even by operator mistake.

The example workflow requests `permissions: contents: read` — the
maximum it needs. There is no `contents: write`, no packages, no
secrets scope.

---

## 3. Result semantics (Phase 24)

The result is SERVER-COMPUTED from server-managed scan state. A CI
caller cannot declare its own security outcome because no endpoint
accepts one (`extra="forbid"` rejects `result`/`verdict`/
`security_status` in the body with 422 — tested).

| Server state | `result` | CI exit |
|---|---|---|
| `COMPLETED` | `PASS` | success (analysis completed; findings visible in the console) |
| `FAILED` | `FAIL` | failure |
| `QUEUED`/`CLONING`/`SCANNING`/`ANALYZING` | `null` (still running) | keeps polling |
| anything unknown | `INCONCLUSIVE` | failure — unknown is never silently success |

`commit_binding` is reported alongside:
`UNBOUND | PENDING | VERIFIED | MISMATCH | INCONCLUSIVE`.

---

## 4. Stale commits (Phase 23)

CI requests commit A; the repository advances to B before processing.
The worker's clone records B and the binding check refuses the scan
with `COMMIT_MISMATCH` BEFORE any analysis. The Action maps that to a
failure whose message states the result is not attributable to the
requested commit. A's result is never attached to B — and the platform
cannot be fooled into analyzing B while claiming A.

---

## 5. Fail-closed behavior (Phase 25)

| Condition | Action exit |
|---|---|
| `CYVRIX_API_KEY` unset | immediate failure ("refusing to run — fail closed") |
| CYVRIX unreachable / HTTP error | failure (INCONCLUSIVE) |
| status polling times out (15 min) | failure (INCONCLUSIVE) |
| `COMMIT_MISMATCH` | failure (INCONCLUSIVE) |
| server `result: FAIL` | failure |

CYVRIX unavailable NEVER yields a silent PASS. Security-sensitive
pipelines should treat INCONCLUSIVE as blocking; the action fails the
step, which is the fail-closed default.

---

## 6. Quotas and rate limits apply

CI submissions pass the same `v1-write` rate limit and the same
per-organization daily scan quota as every other public mutation
(`docs/v4-quotas.md`). A runaway matrix cannot exhaust the platform:
the global quota is the ceiling across all tenants, and the org quota
is the ceiling per tenant.

---

## 7. Adoption

1. Copy `.github/actions/cyvrix-ci` into the consumer repository (or
   reference it from a shared repo).
2. Create a CYVRIX API key with `scans:read`, `repositories:read`,
   `scans:create`.
3. Add the key as the `CYVRIX_API_KEY` secret and the API base as
   `CYVRIX_API_URL` (a repository variable).
4. Rename `.github/workflows/cyvrix-analysis.yml.example` to `.yml` and
   adjust triggers.

Tests: `tests/test_v41_cicd.py` (11) — commit binding surface, stale
commit refusal in the worker, result-claim rejection, namespace
isolation of the idempotency key, static action/workflow checks.
