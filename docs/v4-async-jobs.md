# CYVRIX V4.1 — Async Jobs

Status: IMPLEMENTED (this document is the contract)
Source: `apps/api/app/routes/api_v1.py` (`GET /api/v1/scans/{scan_id}/status`),
worker: `services/worker/worker/tasks.py`
Related: `v4-public-api.md`, `v4-webhooks.md`, `v4-cicd.md`

---

## 1. The job model (Phase 7)

For analysis work, **the scan row IS the job**. CYVRIX deliberately does
not introduce a parallel job table that would duplicate the scan state
machine — two sources of truth for one lifecycle is a drift bug waiting
to happen. The scan states are the job states:

```
QUEUED → CLONING → SCANNING → ANALYZING → COMPLETED
                                      ↘ FAILED (bounded reason_code)
```

Polling endpoint (Phase 11):

```
GET /api/v1/scans/{scan_id}/status      scope: scans:read
```

```json
{
  "job_id": "…",
  "kind": "SCAN",
  "status": "COMPLETED",
  "result": "PASS",
  "repository_id": "…",
  "commit_sha": "a…",
  "requested_commit_sha": "a…",
  "commit_binding": "VERIFIED",
  "error_reason": null,
  "created_at": "…", "started_at": "…", "completed_at": "…"
}
```

A scan outside the key's organization is `404` (existence hidden), the
same as every other public read.

---

## 2. Result semantics (server-computed; Phase 24)

| status | `result` |
|---|---|
| `COMPLETED` | `PASS` — the pipeline completed (NOT a "clean bill"; findings are in the console) |
| `FAILED` | `FAIL` |
| running states | `null` — no result exists yet |
| anything unknown | `INCONCLUSIVE` — unknown is never silently success |

There is no client-writable result anywhere in V4.1.

---

## 3. Commit binding

| `commit_binding` | Meaning |
|---|---|
| `UNBOUND` | the request carried no commit (plain analysis request) |
| `PENDING` | requested commit set; clone/verification not finished |
| `VERIFIED` | the clone's actual SHA equals the requested SHA — server-proven |
| `MISMATCH` | the clone's SHA differs → scan FAILED with `COMMIT_MISMATCH`, no analysis ran |
| `INCONCLUSIVE` | terminal state without a verifiable binding (e.g. clone recorded "unknown") |

Worker enforcement (V4.1, `services/worker/worker/tasks.py`): the
comparison happens immediately after clone and BEFORE any scanning. A
mismatched scan never produces findings or dependencies.

---

## 4. Audit integration (Phases 28–30)

V3.8 chains are per-installation; V4.1 adds the per-ORGANIZATION chain
(`audit_chains.organization_id`, migration 013) so key-only tenants —
zero installations — still get tamper-evident history. Exactly one owner
per chain is enforced by partial unique indexes.

Events appended by V4.1 (closed-world registry in `audit_service`):

| Event | Criticality | Producer |
|---|---|---|
| `API_KEY_CREATED` / `API_KEY_ROTATED` | SECURITY-CRITICAL (fail-closed: the operation FAILS if the append fails — no credential is minted or destroyed unwitnessed) | key lifecycle |
| `API_KEY_REVOKED` | best-effort witness (the revocation itself is already committed and protective) | key lifecycle |
| `API_KEY_EXPIRED` | reserved for the expiry sweeper | key lifecycle |
| `WEBHOOK_ACCEPTED` / `WEBHOOK_REJECTED` / `WEBHOOK_REPLAY_REJECTED` | per §10 of v4-webhooks | webhook intake |
| `CI_EVENT_RECEIVED` / `CI_EVENT_ACCEPTED` / `CI_EVENT_REJECTED` / `CI_EVENT_REPLAYED` / `CI_EVENT_COMMIT_MISMATCH` / `CI_EVENT_REPOSITORY_MISMATCH` / `CI_EVENT_PROCESSING_STARTED` / `CI_EVENT_PROCESSING_COMPLETED` / `CI_EVENT_PROCESSING_FAILED` | shipped in V4.2 — the dedicated CI intake (`POST /api/ci/events`, scope `ci:ingest`); commit-mismatch and repository-mismatch events are SECURITY-CRITICAL witnesses, worker-verified | CI intake |
| `SCAN_REQUESTED` | OPERATIONAL witness of the public mutation | `POST /api/v1/scans` |
| `IDEMPOTENCY_CONFLICT` | OPERATIONAL probe signal | idempotency conflicts |
| `QUOTA_LIMIT_REACHED` | OPERATIONAL | quota refusals |

Key-lifecycle payloads contain only the key PREFIX (designed for logs)
and server-side facts. Never the plaintext secret, never the hash.

Tamper evidence is inherited and tested: a direct-DB payload mutation of
an org-chain event is detected (`DIGEST_MISMATCH`) by the V3.8 verifier
(`tests/test_v41_boundary_races.py`).

---

## 5. What is deliberately NOT here (Phase 68: no false capabilities)

- **`GET /api/v1/jobs` (paginated job list)** — not implemented; job
  identity is the scan id and scans are already paginated under
  `/api/v1/scans`.
- **`POST /jobs/{id}/cancel`** — not implemented. Analysis jobs are
  short, side-effect-free reads of a clone; cancellation semantics
  (CANCEL_REQUESTED/CANCELLING/CANCELLED + external reconciliation)
  exist for EXECUTION pipelines in V3.7 and are exposed only in the
  console, where they belong.
- **`SIDE_EFFECT_UNKNOWN`** — deliberately absent from the public job
  surface. Public-API scans have no EXTERNAL side effect (clone +
  read-only analysis), so the ambiguous-external-state class cannot
  arise here. The class is real for GitHub mutations and is handled in
  the V3.7 reconciliation engine, not faked here.
- **Retry of failed jobs** — re-running an analysis is a new request
  (new idempotency key or the same one after expiry). Security denials
  are never retried (V3.7 rule, unchanged).
