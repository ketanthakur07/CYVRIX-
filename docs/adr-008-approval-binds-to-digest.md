# ADR-008 — Human approval binds to the exact action digest

Status: ACCEPTED (V3.2)

## Context

V3.1 produces ActionProposals with a deterministic policy decision
(`ALLOW | REQUIRE_APPROVAL | DENY`) and a canonical SHA-256 action digest
over the proposal's executable semantics. V3.2 introduces human approval.
The core risk: an approval that means "I approve this fix" is socially and
operationally easy to reinterpret as "I approve the current idea of a fix".
Between approval and any future execution, any of these can drift: the
proposal row, its operations, the recommendation behind it, the risk
assessment, the base commit, the policy itself, or the approver's session.

## Decision

1. **Approval binds to the exact digest.** Every approval stores
   `action_digest`; at approval time the server RECALCULATES the digest
   from persisted proposal content and compares. A mismatch denies
   approval, emits `APPROVAL_DIGEST_MISMATCH`, and is never repaired
   automatically — a new proposal is required.
2. **Human approval cannot override a deterministic DENY.** The policy
   engine is re-evaluated against current state at approval time; only a
   current `REQUIRE_APPROVAL` decision is approvable.
3. **Approval is bounded.** Approval TTL is 1 hour (server-derived);
   proposal expiry is unchanged (24 h). No infinite authorizations.
4. **Authorization material is single-use and hashed.** The one-time
   token is 256-bit CSPRNG, stored only as a keyed HMAC (SECRET_KEY-
   derived), shown once, bound to its approval, and consumed atomically
   (`APPROVED → USED`, unique live-approval constraint as backstop).
5. **Eligibility is server-derived.** Self-approval for LOW/MEDIUM with
   fresh GitHub re-authentication step-up; HIGH/CRITICAL require a second
   principal with their own fresh step-up. Unknown risk levels fail
   closed. The single-owner limitation is documented, never downgraded.
6. **Approval ≠ execution.** V3.2 grants no execution capability of any
   kind; `consume-token` is a non-executing verification point reserved
   for the executor phase.

## Alternatives considered

- *Approve by proposal ID only:* rejected — TOCTOU/approval confusion; a
  mutated proposal would inherit an approval it never earned.
- *Client-supplied digest as proof:* rejected — the client is untrusted;
  only a server-side recalculation binds reality to intent.
- *Persist plaintext tokens (encrypted-at-rest):* rejected — DB compromise
  would yield live authorizations; keyed hashes do not.
- *Allow humans to override DENY with justification:* rejected — breaks
  the deterministic-policy invariant (ADR-004) and makes the system
  unauditable; DENY remediation is a new proposal, not a signature.
- *Unbounded or client-settable approval TTL:* rejected — stale human
  intent must not authorize machine action hours or days later.

## Consequences

- Proposals are effectively immutable once approved; material changes
  (recommendation trust/validation, risk snapshot, operations) invalidate
  the approval path and force a new proposal.
- Denial paths are auditable and durable (committed even on error).
- One live approval per proposal is enforced structurally (partial unique
  indexes), making duplicate-approval attacks a DB-level impossibility.
- Single-owner deployments cannot approve HIGH/CRITICAL actions until the
  roles/co-owner model lands — a deliberate, conservative limitation.
- The executor phase (V3.4+) inherits two independent digest checks
  (approval-time and execution-time) plus single-use consumption through
  one audited path.
