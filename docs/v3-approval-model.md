# CYVRIX V3.2 — Approval Model

Status: IMPLEMENTED (V3.2). Human approval of action proposals — **authorization data only**. V3.2 adds NO execution capability: no shell, no subprocess, no file writes, no git, no GitHub writes, no Docker, no worker enqueue. An APPROVED action is still inert; execution belongs to later phases (V3.4+).

Companion: `v3-security-model.md` §6, `v3-action-model.md`, `v3-architecture.md`, `roadmap-v3.md` (ADR-008).

---

## 1. The Question V3.2 Answers

> "Did an authorized human explicitly approve THIS EXACT ACTION?"

The answer never depends on finding ID, recommendation ID, action title, human-readable description, or UI state. It depends only on:

```
ActionProposal + ActionDigest + CurrentPolicyDecision
  + EligibleApprover (+ second principal when required)
  + BoundedExpiry + OneTimeAuthorization
→ Approval
```

---

## 2. Approval Lifecycle & State Machine

Implemented in `apps/api/app/services/approval_model.py` (`ALLOWED_TRANSITIONS`).

```
PENDING ──► APPROVED ──► USED
   │            │
   │            ├──► REVOKED
   │            └──► EXPIRED   (expiry reconciliation)
   ├──► REJECTED
   └──► EXPIRED
```

- `USED`, `REJECTED`, `REVOKED`, `EXPIRED` are **terminal**: nothing resurrects them. A new approval round is a NEW approval row (rejection/revocation of a proposal re-opens the proposal state, but the old approval record is immutable).
- Forbidden transitions (e.g. `USED → APPROVED`, `REJECTED → APPROVED`) raise `ApprovalStateError` and fail closed.
- In V3.2 approvals are granted directly in the `APPROVED` state (there is no async claim step yet); `PENDING` exists as the canonical pre-decision state and is used when a rejection row is materialized.

### Expiry

| Object | TTL | Derived by |
|---|---|---|
| ActionProposal | 24 h (unchanged from V3.1) | server (`proposal_expiry`) |
| Approval | **1 h** (`APPROVAL_TTL_MINUTES = 60`) | server (`approval_expiry`) |

Clients cannot set or extend any expiry. All time math is server-side UTC. `is_step_up_fresh` tolerates ≤60 s of backwards clock skew; markers stamped >60 s in the future are treated as forged.

---

## 3. Digest Binding (server-recalculated, never repaired)

At approval time the service (`approval_service.grant_approval`):

1. Loads the proposal **through the ownership chain** (user → installation → repository); off-chain actors are denied (`UNAUTHORIZED_APPROVER`) — also re-verified inside the service, defense in depth.
2. **Recalculates** the canonical action digest from the persisted proposal content (`compute_action_digest`) and compares it to the stored digest. The client never supplies the binding digest.
3. On mismatch: **DENY + `APPROVAL_DIGEST_MISMATCH` audit event. The stored digest is never repaired or overwritten.** A mutated proposal (e.g. an operation edited after creation) fails this check — scope expansion is structurally impossible.

---

## 4. Policy Re-evaluation (current state, not the snapshot)

Before any approval is granted, the policy engine re-runs against the CURRENT persisted state:

- proposal still exists, is `PROPOSED`/`POLICY_CHECKED`, and is not expired (`PROPOSAL_EXPIRED`)
- finding / recommendation / repository still exist; repo inactive → DENY via POL-002
- recommendation trust/validation unchanged since creation → otherwise `RECOMMENDATION_CHANGED` (stale)
- risk snapshot unchanged → otherwise `RISK_CHANGED` (stale); a latest risk assessment is used by the engine
- current policy version supported → otherwise `POLICY_VERSION_STALE`
- **decision must be exactly `REQUIRE_APPROVAL`**:
  - `DENY` → `POLICY_DENIED` + `APPROVAL_POLICY_DENIED` audit event. **A human can never override a deterministic DENY.**
  - `ALLOW` (future) → not approvable (`POLICY_DECISION_NOT_APPROVABLE`); nothing requires approval.
- current environment must be one of `development | staging | production` (POL-020 fail-closed): an unknown `ENVIRONMENT` (e.g. `test`) DENIES every approval — deployments must use a supported value.

Failure modes are audited durably (the denial audit event is committed even though the request returns an error).

---

## 5. Approver Eligibility & Second-Principal Rule

Implemented in `approval_model.check_approver_eligibility` (pure function) + server-side step-up evidence:

| Risk level | Self-approval | Step-up (fresh GitHub re-auth) | Second principal |
|---|---|---|---|
| LOW | allowed | required for approver | not required |
| MEDIUM | allowed | required for approver | not required |
| HIGH / CRITICAL | **forbidden** | required for approver AND second principal | **required** (`SECOND_APPROVER_REQUIRED`) |
| unknown/missing | — | — | fail closed (`UNKNOWN_RISK_LEVEL`) |

- Eligibility is **server-derived only**: client role/flags/emails are never consulted. The approver identity comes from the authenticated session; the second principal must be an existing user.
- **Current limitation (documented, not downgraded):** the data model has exactly one owner per installation (`GithubInstallation.user_id`), so in a single-owner deployment no second principal can reach the proposal — HIGH/CRITICAL proposals are **denied** (`SECOND_APPROVER_REQUIRED`) rather than approved by the creator. Org-shared installations with a co-owner model arrive with the roles work; the two-person rule is never silently relaxed.
- The same user cannot satisfy the two-person rule by submitting their own ID as `second_approver_user_id` (approver == proposer is rejected before step-up is even evaluated).

### Step-up authentication (honest implementation)

There is no password/MFA in CYVRIX — none is faked. Step-up is a **real GitHub re-authentication round-trip**:

1. `POST /api/actions/step-up` issues a single-use state (Redis, 10 min).
2. `GET /api/auth/step-up/login?state=…` binds that state to the session, mints a marked OAuth state, and redirects to GitHub.
3. The OAuth callback verifies the marker, records `stepup:{user_id}` (epoch seconds, TTL = `step_up_max_age_minutes`, default 15) **only after GitHub re-verifies the user**.
4. `grant_approval` reads the marker at decision time; absence, staleness, or any Redis failure **fails closed** (`STEP_UP_REQUIRED`).

---

## 6. One-Time Authorization Token

- Generated server-side: 256 bits of CSPRNG entropy (`secrets.token_urlsafe`), `cyv1_` prefix.
- **Never persisted in plaintext.** Storage is a keyed HMAC-SHA256 (`hash_token`) derived from the app secret — a stolen DB dump cannot be reversed or rainbow-tabled, and rotating `SECRET_KEY` invalidates outstanding tokens.
- Returned in full **exactly once**, in the `ApprovalIssuedResponse` of a successful first grant. Idempotent re-approvals return the same approval with **no** token. GET responses, listings, and audit events never contain token material.
- **Single use:** consumption sets `authorization_used_at` and transitions `APPROVED → USED`. A second presentation returns `TOKEN_REPLAY` (audited as `AUTHORIZATION_DENIED`).
- **Bound to its approval** (which binds proposal + digest): a token for Action A verified against Action B's approval fails hash comparison (`TOKEN_INVALID`).
- Expiry: an approval past its TTL cannot be consumed (`APPROVAL_EXPIRED`) and transitions explicitly to `EXPIRED`.
- Revocation kills the token: `REVOKED` approvals cannot be consumed even with the real token.

`POST …/consume-token` is a **non-executing verification endpoint** reserved as the single audited consumption point for the future executor (V3.4+). It starts no job, runs no code, writes no repository.

---

## 7. Concurrency & Idempotency

- **One live approval per proposal:** partial unique index `uq_approvals_live` on `action_proposal_id WHERE approval_state IN ('PENDING','APPROVED')` — enforced by PostgreSQL and mirrored in the SQLite test metadata.
- Repeated approve of the same unchanged proposal returns the existing approval (`ALREADY_APPROVED`) — no duplicate rows, no second token.
- Concurrent grants are serialized by a proposal row lock (`SELECT … FOR UPDATE` where supported) with the unique index as the final backstop; the losing committer surfaces the winner's approval (or fails closed as `APPROVAL_CONFLICT`) — never a second usable token.
- **Distinct principals per live round:** partial unique index `uq_approvals_principal` on `(proposal, approver, second_approver) WHERE live` — terminal rounds never block later legitimate rounds.
- **Concurrent decision races are serialized end-to-end.** Every decision path (approve / reject / revoke / consume) takes the proposal row lock, then RE-CHECKS the proposal status, any live approval, and the approval's current state INSIDE the lock before writing, and recovers from commit conflicts by surfacing the winner's state. Deterministic outcomes:
  - approve vs approve → exactly one live approval, at most one token;
  - approve vs reject → exactly one terminal decision wins; the loser gets 403/409 or an idempotent mirror — an APPROVED approval on a REJECTED proposal (or vice versa) is structurally impossible;
  - consume vs consume → exactly one `200`; the loser is denied (`TOKEN_REPLAY`);
  - revoke vs consume → terminal state is exactly `USED` or `REVOKED`; a revoked approval can never become usable afterwards;
  - approve vs revoke → no resurrection, no duplicate live approval.
  Verified by genuine simultaneous-request tests (asyncio barrier, real PostgreSQL, ≥10 repetitions per race class): `tests/test_approval_races.py` (gated behind `RUN_INTEGRATION_TESTS=1`).

---

## 8. Human Approval UI (V3.2 scope)

`/actions/[id]` (Next.js) shows, with nothing hidden behind collapses:

- **What will change** — rationale + full expected diff (plain text)
- **Where** — base commit, target branch, files affected, operation list (JSON rendered as inert text)
- **Risk before → expected risk after**, trust level, validation state
- **Policy** — decision, version, reason code, proposal expiry
- **Action digest** — approval requires typing the digest exactly
- **Evidence** — the finding's evidence object

Controls are exactly `[APPROVE]` and `[REJECT]` — no "fix it", no "approve all", no implicit approval. `APPROVED` is always labeled as approval-recorded, **never** as executed. HIGH/CRITICAL shows the second-principal requirement inline. All proposal-originated strings render as plain text (React default; no `dangerouslySetInnerHTML`). The one-time token is shown once in a copy-once banner.

---

## 9. Audit Events

Emitted for every security-relevant outcome (actor, action digest, proposal id, policy version, reason code, timestamp; token material never logged):

| Event | When |
|---|---|
| `APPROVAL_GRANTED` | approval created (includes approval_level, second_approver, expiry) |
| `APPROVAL_REJECTED` | pending decision → REJECTED |
| `APPROVAL_REVOKED` | APPROVED → REVOKED |
| `APPROVAL_DENIED` | expired / stale / changed context / not-approvable decision |
| `APPROVAL_POLICY_DENIED` | current policy says DENY (never overridable) |
| `APPROVAL_UNAUTHORIZED` | off-chain approver / failed step-up / second-principal violation |
| `APPROVAL_DIGEST_MISMATCH` | stored digest ≠ recalculated digest (never repaired) |
| `AUTHORIZATION_CONSUMED` | one-time token verified (APPROVED → USED) |
| `AUTHORIZATION_DENIED` | replay / invalid token / expired approval / wrong state |

Hash-chained tamper evidence remains **out of V3.2 scope** (V3.8 per roadmap); the existing `audit_events` table is used as-is — no fake chain is created.

---

## 10. Rate Limits & CSRF

- Approval operations (`approve`/`reject`/`revoke`/`consume-token`) are rate-limited per user (`approval_rate_limit_per_hour`, default 30 — security-model §8), fail closed when Redis is unavailable.
- Session cookie is `SameSite=Lax`, `HttpOnly`, `Secure` in production; approval POSTs additionally require the fresh step-up round-trip, which is itself a full cross-site navigation — state-changing approvals cannot be driven by a cross-site form post alone. A dedicated CSRF-token layer remains a hardening item tracked for the execution phases.

---

## 11. No-Execution Guarantee (V3.2 boundary)

Regression-tested (`tests/test_approvals_api.py::TestNoExecutionBoundary`):

- Runtime: every approval endpoint completes with `subprocess.Popen/run/call`, `os.system`, all worker enqueue functions, and all GitHub write-prefixed methods rigged to explode — none fire.
- Static (AST): `approval_model.py` and `approval_service.py` import no `subprocess`, `socket`, `httpx`, `requests`, `urllib`, `shutil`, `ctypes`, `multiprocessing`, `docker`, `git`, and call no `eval`/`exec`/`system`/`popen`/`rmtree`/`enqueue`/`create_pull_request`/`put_file`.
- An APPROVED proposal remains inert: no execution route exists in the application.
- Browser-level (real Chromium, real Docker stack: Next.js + FastAPI + PostgreSQL + Redis): the full approval flow is driven through the actual UI — exact-scope inspection, typed-digest approval, rejection, cross-user denial, expired denial — with direct database verification of hash-only token persistence, correct actor/digest/policy/state, audit content, and absence of execution-shaped routes and controls (`apps/web/e2e/approval-flow.spec.ts`, seeded by `tests/seed_e2e_approvals.py`).

**V3.2 HAS NO EXECUTION CAPABILITY.**
