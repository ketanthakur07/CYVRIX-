# CYVRIX V3.3 — Execution Authorization Model

Status: IMPLEMENTED (V3.3). The final deterministic authorization contract between an APPROVED action and FUTURE EXECUTION. V3.3 adds NO execution capability: no shell, no subprocess, no file writes, no git, no GitHub writes, no Docker, no sandbox, no worker enqueue, no credentials issued. The only outputs are `EXECUTION_AUTHORIZED` / `EXECUTION_DENIED` plus structured audit events.

Companion: `adr-009-execution-authorization-gate.md`, `v3-approval-model.md`, `v3-execution-model.md`, `v3-security-model.md`.

---

## 1. The Question V3.3 Answers

> "Is this exact action still authorized to execute RIGHT NOW?"

The answer is produced from trusted server-side state only. The client request is untrusted: it supplies nothing security-relevant (no digest, no policy decision, no risk, no approval state, no `authorized=true` — the schema is `extra="forbid"`).

```
Trust hierarchy:
SYSTEM SECURITY POLICY  >  DATABASE TRUSTED STATE  >  DETERMINISTIC POLICY ENGINE
  >  APPROVAL RECORD  >  ACTION PROPOSAL  >  CLIENT REQUEST
```

---

## 2. Authorization Flow

Implemented in `apps/api/app/services/execution_authorization_service.py`:

```
authenticate (session; ownership chain on every route)
  → load ActionProposal (ownership chain; 404 on cross-tenant)
  → load Approval (state APPROVED)
  → kill switch (system_controls, fail closed)          [authorize + in-lock + consume]
  → recompute action digest, compare stored             [never repaired]
  → approval ↔ proposal ↔ recomputed digest agree ×3
  → approval unconsumed / unrevoked / unexpired
  → idempotency: return existing live authorization
  → structural staleness (recommendation/risk/repo drift, expiry)
  → policy re-evaluation against CURRENT state
  → policy version check (stale ⇒ deny)
  → PROPOSAL row lock → re-check mutable preconditions inside the lock
  → create immutable ExecutionAuthorization + frozen contract
  → audit (same transaction) → commit
```

Consumption (`POST /api/actions/authorization/{id}/consume`) adds:
one-time token verification (keyed-hash comparison against the approval's
stored hash) → proposal row lock → re-read authorization + approval inside
the lock → `AUTHORIZED → CONSUMED` **and** `APPROVED → USED` in ONE
transaction → `EXECUTION_AUTHORIZATION_CONSUMED` audit event. Exactly one
concurrent consumer commits; every loser receives `AUTHORIZATION_REPLAY`.

---

## 3. State Machine

Implemented in `apps/api/app/services/execution_authorization_model.py` (`ALLOWED_TRANSITIONS`):

```
AUTHORIZED ──► CONSUMED      (one-time atomic consumption)
AUTHORIZED ──► EXPIRED       (approval window closed; also swept by reconcile_expired)
AUTHORIZED ──► REVOKED       (explicit revoke; no resurrection)
```

- `CONSUMED`, `EXPIRED`, `REVOKED` are **terminal**: nothing resurrects them.
- **DENIED is not a state** — a denial creates no record and leaves nothing to resurrect; it is an outcome with a durable audit event.
- Unknown states fail closed (treated as terminal; all transitions refused).
- A new authorization round requires a fresh approval round (fresh approval → fresh contract).

---

## 4. Digest Verification (server-recalculated, never repaired)

At authorize AND at consume:

1. The canonical action digest is **recalculated** from persisted proposal content (`compute_action_digest`).
2. Three-way agreement is enforced: `approval.action_digest == proposal.action_digest == freshly_recomputed`. Any difference ⇒ deny (`ACTION_DIGEST_MISMATCH` / `APPROVAL_DIGEST_MISMATCH`) + `EXECUTION_DIGEST_MISMATCH` audit. The stored digest is **never repaired** and the proposal is never silently updated — a new proposal is required.
3. The **contract digest** (`contract_digest`) is verified at consume against the persisted contract bytes — any tampering with the stored contract (e.g. scope expansion of `allowed_files`) ⇒ `CONTRACT_DIGEST_MISMATCH`, never a repair.

---

## 5. Policy Re-evaluation

The deterministic policy engine re-runs against CURRENT persisted state immediately before authorization (never the snapshot, never a cached or client-supplied decision):

- `DENY` → `POLICY_DENIED` + `EXECUTION_POLICY_DENIED` audit. **Cannot be overridden — not by approval, not by anything.**
- `REQUIRE_APPROVAL` + valid approval → authorizable.
- `ALLOW` (future) → **not** authorization by itself; documented policy semantics keep approval requirements binding. V3.3 authorizes only from `REQUIRE_APPROVAL` + valid approval.
- Unsupported/stale policy version → `POLICY_VERSION_STALE`; versions are never silently upgraded.

---

## 6. Staleness / Expiration / Risk

- Proposal must be in `PROPOSED`/`POLICY_CHECKED`/`APPROVED` and unexpired (`ACTION_EXPIRED`); `REJECTED`/`EXPIRED`/`STALE` authorize nothing.
- Recommendation trust/validation drift since proposal creation ⇒ `RECOMMENDATION_CHANGED`; risk snapshot drift ⇒ `RISK_CHANGED`; risk jumping into HIGH/CRITICAL additionally fails the policy re-evaluation (second-principal unavailability in the single-owner model is fail-closed, unchanged from V3.2).
- **No independent authorization TTL**: the authorization window is exactly the approval window (`authorization_window_expired` ≡ approval expiry). The two can never drift. Boundary semantics: `now >= expires_at` is expired; missing expiry fails closed.

---

## 7. Repository / Branch / Commit Binding

The contract freezes `repository_id`, `base_commit_sha`, `target_branch` from the digest-verified proposal; a request can never substitute other values, and no client input can redefine them. **Format validation now, semantic repository-state verification later** (execution model §4): V3.3 verifies shape and binding; live GitHub re-verification of the pinned SHA is intentionally deferred to the execution phase (V3.4/V3.5) and is NOT claimed as implemented here.

---

## 8. Kill Switch (emergency stop, fail closed)

Server-owned flag `execution_disabled` in the `system_controls` table (migration 006, seeded `'false'`):

- Read at **authorize** (step 1), again **inside the proposal row lock** (no long-cached success), and at **consume**.
- Fail-closed on every failure mode: missing row (`KILL_SWITCH_UNPROVISIONED`), read error (`KILL_SWITCH_READ_FAILED:*`), and any value other than the exact string `'false'` (including `TRUE`, `1`, whitespace) counts as disabled.
- Denials are audited (`KILL_SWITCH_ACTIVE`); toggling is a privileged, audited operation (security-model §12).
- The switch state is also fed into policy re-evaluation (POL-007), which was wired but inactive before V3.3.

---

## 9. The Execution Authorization Contract

`ExecutionAuthorizationContract` (`execution_authorization_model.py`) — frozen dataclass, canonical JSON serialization, SHA-256 `contract_digest`:

```
contract_version, authorization_id, action_proposal_id, approval_id,
action_digest, repository_id, base_commit_sha, target_branch,
policy_version, policy_decision, allowed_files (sorted),
allowed_operations (order preserved), authorized_at, expires_at
```

- **Immutable, typed, bounded, minimal, deterministic, digestable, non-executable.**
- Detects any change to action / repository / branch / commit / scope / policy / expiration (tested field-by-field).
- Contains **no** shell commands, executable paths, credentials, arbitrary URLs, plaintext secrets, or scripts. The future executor reconstructs allowed operations from the authoritative proposal — the contract *authorizes*, it never describes *how* to execute.
- A **security-context digest** (action digest + policy result + recommendation/risk/trust/validation context + approval id) is additionally recorded in the `EXECUTION_AUTHORIZED` audit event, strengthening TOCTOU forensics; it supplements, never replaces, the action digest.

The future executor (V3.4+) receives ONLY the contract from `consume` — never the approval token, GitHub credentials, user session, free-form recommendation, or LLM output.

---

## 10. Concurrency & Idempotency

Verified by genuine simultaneous-request tests (asyncio barrier, two real HTTP requests, separate PG transactions, 10 repetitions per class × 3 consecutive full-suite runs): `tests/test_execution_authorization_races.py`.

| Race | Deterministic outcome |
|---|---|
| authorize vs authorize | exactly one live authorization (same id returned to both — idempotent) |
| consume vs consume | exactly one `200`; loser `409 AUTHORIZATION_REPLAY`; approval `USED` exactly once |
| consume vs revoke | terminal state exactly `CONSUMED` xor `REVOKED`; no resurrection of a consumed/revoked authorization |
| authorize vs approval-expiry | no authorization created after effective expiration |
| policy-change vs authorize | `DENY` wins — never POLICY_DENIED *and* a live authorization |
| risk-change vs authorize | drift detection or raced-ahead authorization, never a contradiction |
| 4-way storm | ≤1 live authorization, one terminal state, zero 5xx, zero deadlocks |

Mechanism: proposal row lock (`SELECT … FOR UPDATE`) shared with the approval service as the single serialization point → in-lock re-checks of every mutable precondition (proposal status, live authorization, approval state/consumption, kill switch) → partial unique index `uq_execution_authorizations_live` as final backstop → commit-conflict recovery surfacing the winner's state. Idempotent repeated authorize returns the existing record; timestamp randomness is never used as identity (the contract binds the authorization UUID, digest, and window).

---

## 11. Transaction Boundaries & Audit Ordering

Atomic in ONE transaction: authorization state transition + approval state transition + mandatory audit event. There is no state where:

- an authorization says CONSUMED without the corresponding durable `EXECUTION_AUTHORIZATION_CONSUMED` audit event, or
- an authorization record exists without its `EXECUTION_AUTHORIZED` event, or
- an authorization is CONSUMED while the approval is not USED (and vice versa).

Pure denial paths commit their audit event durably **before** the error response is returned (§35: the system never returns AUTHORIZED while mandatory audit durability cannot be guaranteed; a commit failure on the authorize path rolls back the record too).

---

## 12. API

All routes authenticated, ownership-chained (cross-tenant ⇒ 404), rate-limited per user (`execution_authorization_rate_limit_per_hour`, fail closed), POST-only for state changes (no GET authorizes, consumes, or mutates):

| Route | Purpose |
|---|---|
| `POST /api/actions/{id}/authorize` | validate + create the immutable authorization (idempotent) |
| `GET /api/actions/{id}/authorization` | list authorizations for a proposal (read-only) |
| `GET /api/actions/authorization/{id}` | read one authorization (read-only) |
| `POST /api/actions/authorization/{id}/consume` | atomic one-time consumption; returns the contract |
| `POST /api/actions/authorization/{id}/revoke` | AUTHORIZED → REVOKED |

Error taxonomy (stable reason codes): `AUTHORIZATION_NOT_FOUND, ACTION_NOT_FOUND, APPROVAL_INVALID, APPROVAL_EXPIRED, APPROVAL_REVOKED, APPROVAL_CONSUMED, ACTION_EXPIRED, ACTION_STALE, ACTION_DIGEST_MISMATCH, APPROVAL_DIGEST_MISMATCH, CONTRACT_INVALID, CONTRACT_DIGEST_MISMATCH, POLICY_DENIED, POLICY_VERSION_STALE, RECOMMENDATION_CHANGED, RISK_CHANGED, AUTHORIZATION_REPLAY, KILL_SWITCH_ACTIVE, KILL_SWITCH_UNPROVISIONED, NOT_AUTHORIZED, TOKEN_INVALID, UNAUTHORIZED_CONSUMER`. HTTP semantics: 401 unauthenticated · 403 unauthorized · 404 cross-tenant hiding · 409 stale/digest/replay/policy/kill-switch conflict · 422 malformed (forged fields rejected). Expected security denials never return 500.

No worker-facing bypass exists: the worker cannot manufacture an authorization record except through the same validated path (the service re-checks ownership, digest, policy, and switch server-side; there is no `authorized=true` boolean anywhere).

---

## 13. Audit Events

| Event | When |
|---|---|
| `EXECUTION_AUTHORIZED` | authorization created (includes authorization_id, contract_digest, security_context_digest, expiry) |
| `EXECUTION_AUTHORIZATION_DENIED` | kill switch, stale/expired state, invalid approval, contract invalid, replay-adjacent denials |
| `EXECUTION_POLICY_DENIED` | current policy says DENY (never overridable) |
| `EXECUTION_DIGEST_MISMATCH` | stored ≠ recalculated digest (never repaired) |
| `EXECUTION_AUTHORIZATION_CONSUMED` | one-time consumption (same transaction as the state change) |
| `EXECUTION_AUTHORIZATION_REVOKED` | live authorization revoked |

Every event carries actor, action digest, proposal id, policy version, reason code, timestamp. Token material, credentials, and session secrets are never logged. Hash-chained tamper evidence remains V3.8 scope (no fake chain).

---

## 14. Threat-G Residual Risk (honest statement)

A fully compromised worker can still bypass in-process gates — V3.3 does **not** move the authorization decision into a separate trust domain. What V3.3 changes:

- authorization is now a separately auditable, digest-bound artifact the executor must verify via `consume` (a second gate, in a different process, with its own audit trail);
- the worker has no standing authorization and no endpoint to self-declare AUTHORIZED — `authorize` requires a valid approval chain, current policy, and a non-tripped kill switch.

The documented path forward (roadmap §5, execution model) is the **external authorizer service** signing per-action push credentials: Worker → External Authorizer → Decision → Executor. V3.3 defines the contract and consumption boundary such that this service can later slot in without changing the executor's side of the interface.

---

## 15. No-Execution Guarantee (V3.3 boundary)

Regression-tested (`tests/test_execution_authorization_api.py::TestNoExecutionBoundary`):

- **Runtime:** the full authorize → consume → revoke flow runs with `subprocess.Popen/run/call` and `os.system` rigged to explode — nothing fires.
- **Static (AST):** `execution_authorization_model.py`, `execution_authorization_service.py`, and `routes/execution_authorization.py` import no `subprocess`, `socket`, `httpx`, `requests`, `urllib`, `shutil`, `ctypes`, `multiprocessing`, `docker`, `git`, and call no `eval`/`exec`/`system`/`popen`/`rmtree`/`enqueue`/`create_pull_request`/`put_file`/`push`.
- **Schema:** no execution-shaped tables (`executions`, `action_executions`, `jobs`, `rq_*`, `queue*`) exist in the metadata; nothing is enqueued to any worker.
- **Credentials:** no installation token, OAuth secret, private key, or session secret is issued, returned, or stored by any V3.3 path; the contract and all responses are credential-free.

**V3.3 HAS NO EXECUTION CAPABILITY.**
