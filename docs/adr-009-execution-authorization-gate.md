# ADR-009: Execution authorization is a distinct deterministic gate between approval and execution

Status: ACCEPTED (implemented in V3.3)
Companion: `v3-execution-authorization.md`, `v3-approval-model.md` (ADR-008), `v3-execution-model.md`

## Problem

After V3.2, the strongest artifact in the system is an APPROVED approval bound to an
action digest and a one-time token. But "approved" answers *was a human's decision
recorded?* — it does not answer the question the future executor (V3.4+) must ask at
execution time: **"Is this exact action still authorized to execute RIGHT NOW?"**
Approval validity decays (expiry), context drifts (risk, validation state, policy),
and emergencies happen (kill switch). An executor that trusts an approval row alone
would re-implement these checks ad hoc, or worse, skip them.

## Decision

V3.3 introduces a dedicated, deterministic **execution authorization gate**:

1. `POST /api/actions/{id}/authorize` validates every security invariant against
   current server-side state and records an immutable, digest-bound
   **ExecutionAuthorization** (the *contract*) — authorization data only.
2. `POST /api/actions/authorization/{id}/consume` atomically consumes the one-time
   authorization (AUTHORIZED → CONSUMED) together with the approval (APPROVED → USED)
   in a single transaction, serialized by the proposal row lock. This is the ONLY
   path by which the future executor may obtain authorization, and it receives only
   the machine-readable contract — never credentials, commands, or session data.

The gate re-validates everything the approval validated at approval time — digest
(recalculated, never repaired), three-way digest agreement, policy re-evaluation
(DENY is never overridable), freshness/staleness, expiry — plus the kill switch,
read fail-closed from a server-owned `system_controls` table, checked at authorize,
inside the authorization lock, and at consume.

## Security rationale

- **No resurrection:** CONSUMED/REVOKED/EXPIRED are terminal; a new authorization
  requires a fresh approval round.
- **No double authorization:** partial unique index `uq_execution_authorizations_live`
  (one live authorization per proposal) + in-lock re-checks + commit-conflict recovery.
- **No TOCTOU:** the contract is frozen at creation and bound by `contract_digest`;
  consumption re-verifies contract integrity, the three-way digest, and the approval
  window inside the serialization window.
- **Fail closed:** kill-switch read failure, missing row, unknown state, unreadable
  contract, or any uncertainty results in denial — never authorization.
- **Least surface:** the contract contains identity/scope/policy/expiry bindings only.
  No commands, paths, URLs, credentials, or secrets — the executor reconstructs
  allowed operations from the authoritative proposal.

## Alternatives considered

- **Executor re-checks the approval row directly** — rejected: scatters security
  invariants across future components, invites omissions, and cannot be regression-
  tested as a single gate.
- **Extend the approval state machine with an AUTHORIZED state** — rejected: it would
  blur two distinct questions (was it approved? is it still authorized?) and complicate
  the approval record's immutability guarantees.
- **Authorize at approval time (no separate step)** — rejected: the time gap between
  approval and execution is exactly where drift, expiry, and kill-switch events
  belong; collapsing the steps would resurrect TOCTOU exposure.

## Consequences

- Execution (V3.4+) has a single, audited consumption point and a machine-readable,
  digestable contract to verify — the executor never trusts its own judgment.
- One additional request precedes any execution; authorization expires with its
  approval (no independent TTL, so the two can never drift).
- V3.3 itself grants no execution capability: nothing here runs code, writes files,
  touches git/GitHub, enqueues executors, or issues credentials.

## Residual risk

A fully compromised worker (Threat G, `v3-threat-model.md`) can still bypass
in-process gates; the documented path forward remains the external authorizer
service signing per-action push credentials (roadmap §5). V3.3 shrinks the attack
surface by making *authorization* a separately auditable, digest-bound artifact that
the executor must verify against the authorization service, but it does not yet
move the gate out of the worker's trust domain.
