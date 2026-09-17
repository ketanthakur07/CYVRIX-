# CYVRIX V3 — Security Model

Status: DESIGN + PARTIAL IMPLEMENTATION. V3.1 implements the action model, policy engine, and read-only + proposal-creation APIs with full ownership-chain enforcement — see docs/v3-action-model.md. V3.2 implements §6 (human approval) as authorization data only: digest-bound approvals, one-time hashed tokens, step-up re-auth, second-principal rule, bounded expiry — see docs/v3-approval-model.md and ADR-008. V3.3 implements TB-3 (the execution-authorization gate): deterministic re-validation of every security invariant, a server-owned fail-closed kill switch (system_controls table, also feeding POL-007), one-time atomic consumption, and the immutable execution-authorization contract — see docs/v3-execution-authorization.md and ADR-009. V3.4 implements the FIRST real execution: sandboxed LOCAL structured execution only (ephemeral container-per-run, non-root uid 10001, cap_drop ALL, no-new-privileges, pinned seccomp, network_mode none, read-only rootfs, frozen resource limits, no credentials in the sandbox, host-side BEFORE/AFTER scope verification, atomic exactly-once admission consuming the V3.3 authorization) — V3.4 does NOT provide GitHub push, pull requests, production repository mutation, rollback (V3.7), or the hash-chained audit chain (V3.8); see docs/v3-execution-model.md.
Companion: `v3-architecture.md`, `v3-action-policy.md`, `v3-approval-model.md`, `v3-execution-authorization.md`, `v3-execution-model.md`, `v3-threat-model.md`

---

## 1. Trust Boundaries

### 1.1 Current V2 boundary map (verified in repository)

```
USER
 ↓  (browser, session cookie cyvrix_session = id.HMAC-SHA256)
BROWSER
 ↓  (HTTPS, SameSite=Lax cookie, CORS allowlist)
NEXT.JS  (apps/web)                      [untrusted client from API's perspective]
 ↓  (JSON over HTTP, session cookie)
FASTAPI  (apps/api)
 ↓  get_current_user: Redis session lookup + HMAC verify — fail closed
AUTHORIZATION
 ↓  user → installation → repository join, 404 on cross-tenant (every route)
REDIS/RQ  (queue: scans, container_scans, log_analysis)
 ↓  job payload = scan_id (DB is the source of truth; no client-controlled data in payload)
WORKER  (services/worker)
 ↓  installation token → clone URL; workspace 0o700; static analysis only
SCANNER / INVESTIGATION  ←─ UNTRUSTED: repository content, OSV/Trivy data, LLM output
 ↓  (SQLAlchemy, sync, no raw client SQL)
DATABASE  (PostgreSQL)
```

### 1.2 V3 boundary map (added components)

```
                        ┌────────────────────────────────────────────┐
  AI provider ──────────▶ Recommendation/AI draft   (data only)      │
                        └───────┬────────────────────────────────────┘
                                ▼
                     ActionProposalService  ──► digest
                                ▼
  ══════════════ TRUST BOUNDARY TB-1: proposal validation ══════════════
                                ▼
                     Policy Engine (deterministic)
                                ▼
  ══════════════ TB-2: policy gate (DENY exits here) ══════════════
                                ▼
  HUMAN APPROVAL  ──► ApprovalService ──► one-time authorization token
                                ▼
  ══════════════ TB-3: authorization (token + digest + expiry + repo state) ══════════════
                                ▼
  WORKER (actions queue) ── re-runs policy engine (does not trust API)
                                ▼
  ══════════════ TB-4: sandbox ingress ══════════════
                                ▼
  SANDBOX (non-root, no network, no socket, ephemeral) ──► Controlled Executor
                                ▼
  ══════════════ TB-5: sandbox egress (verification results only) ══════════════
                                ▼
  Verification Engine ──► Rollback Controller ──► AuditService (hash chain)
```

### 1.3 Where each input class enters

| Input class | Entry point | Trust level | Control |
|---|---|---|---|
| User identity/session | Cookie + Redis | Trusted after verification | HMAC + Redis TTL, fail closed |
| Repository content (files, manifests, Dockerfiles, logs, README) | Clone into workspace | **Hostile** | Static parsing only, path/symlink validation, bounded reads; never executed by scanners; can never influence policy engine inputs except as bounded finding fields |
| Repository metadata (owner/name/branch/SHA) | DB (synced from GitHub) | Trusted-ish | Fetched from GitHub, not client; SHA pinned |
| AI output (investigation, recommendation draft, proposed change content) | LLM HTTP response | **Untrusted** | JSON schema validation, bounded sizes, cross-validation; may only populate proposal content fields which then pass TB-1/TB-2 |
| External advisory data (OSV, Trivy) | HTTP | Untrusted | Schema-validated (`_validate_osv_vuln` etc.), severity normalized |
| Privileged operations | Worker (clone, future: executor, git push) | Most trusted | Least-privilege credentials, short-lived, per-action |

---

## 2. Security Hierarchy (prompt-injection containment)

```
SYSTEM SECURITY POLICY        (code + policy engine + kill switch — not overridable)
  > APPLICATION POLICY        (product rules: which repos active, rate limits)
    > ACTION POLICY           (per action-type rules, decision tables)
      > HUMAN APPROVAL        (binds a specific digest only)
        > REPOSITORY CONTENT  (data — can propose nothing, authorize nothing)
```

Repository content — README text, Dockerfile comments, log lines, package descriptions, even `package.json` description fields — is data. It is rendered as text, stored as evidence, and bounded in size. It can never: create an action, alter a policy decision, replace an approver, extend a scope, or change a validation plan. Any instruction-like content discovered in repository data is treated as evidence of the injection threat and audited, never obeyed.

---

## 3. Action Digest / Immutability (summary)

Full mechanics in execution model §3.

- Canonical serialization: UTF-8 JSON, recursively sorted keys, no insignificant whitespace, all timestamps UTC ISO-8601, all UUIDs lowercase.
- `digest = SHA-256(canonical_bytes)`, computed at proposal creation, stored on proposal and copied into every approval, authorization token, execution, and audit event.
- Executor recomputes digest from the fetched proposal record **and from the materialized operation list** before acting. Any mismatch ⇒ deny + security audit event.
- Approval references the digest, not "the proposal" — approval survives re-fetching but not mutation.

---

## 4. Credential Isolation

**The executor must never receive:**

- GitHub App private key (RS256 JWT signer) — lives only in API/worker config env
- OAuth client secret
- User session tokens
- Database URL/password
- Redis URL
- OpenAI/LLM API keys
- Application SECRET_KEY, webhook secret

### 4.1 Credential flow for V3 execution (design)

```
Approval consumed ──► Orchestrator requests a scoped, short-lived installation token
                        (GitHub App installation token, contents:write+PR:write ONLY,
                         default expiry ≤ 10 min, repository-scoped by GitHub)
                      ► token injected into sandbox via environment/file, read-once
                      ► used ONLY by the single git push / PR-creation step
                      ► never logged, never persisted, destroyed with the sandbox
                      ► executor never receives DB/Redis/LLM/system credentials at all
```

- Credential permissions correspond to exactly one action execution; a new execution mints a new token.
- GitHub App credentials never enter the sandbox; only the derived, short-lived installation token does, via the orchestrator's injection path.
- Sandbox has no network egress except the single GitHub push endpoint during the push step; that step runs in a minimal sidecar phase, not alongside untrusted repository tooling.
- Secrets never logged (V2 worker already enforces this; V3 extends to all new components).

---

## 5. Security Invariants (binding)

| # | Invariant | Enforcement layer |
|---|---|---|
| 1 | No execution without authentication | FastAPI deps (V2), approval endpoints step-up |
| 2 | No execution without authorization | Ownership chain + policy engine ×3 evaluation points |
| 3 | No execution without valid approval where policy requires it | ApprovalService + worker-side re-check |
| 4 | Approval binds to exact action | Digest copied into approval + token + executor check |
| 5 | Executor cannot expand action scope | Structured operation whitelist + path confinement |
| 6 | AI cannot authorize itself | AI has no credentials, no queue access, no policy input beyond proposal fields |
| 7 | AI cannot access secrets by default | Credential isolation (§4); LLM client key held by API/worker only, never in sandbox |
| 8 | Repository content cannot override system policy | Security hierarchy §2; content is data |
| 9 | Execution occurs in isolated workspace | Sandbox (execution model §2) |
| 10 | Verification is mandatory | State machine cannot reach SUCCEEDED without verification_results |
| 11 | Failure does not silently become success | State machine + verification gate + UI symmetry |
| 12 | Every action is auditable | Hash-chained audit events at every transition |
| 13 | Expired approvals cannot execute | Expiry checked at authorize + pre-execution |
| 14 | Changed repository state invalidates authorization | base_commit_sha re-verified at authorize + execute |
| 15 | Critical policy violations are denied | Default-deny policy engine; DENY emits security audit event |

---

## 6. Approval Security Detail

> **V3.2 implementation note:** the rules below are now implemented — see `docs/v3-approval-model.md` for the authoritative implementation semantics (state machine, token model, audit events, no-execution regression). Self-approval requires a fresh GitHub re-authentication step-up (no fake MFA); HIGH/CRITICAL require a second principal; in the current single-owner data model that requirement fails closed (`SECOND_APPROVER_REQUIRED`) until the co-owner/roles model lands.

- **Who can approve:** users on the ownership chain whose role satisfies the policy level (V3.0 roles: `owner`, `approver` — additive; single-user installs are all owners).
- **Who cannot approve:** creator of the proposal when policy level ≥ HIGH (second principal required); users without repository ownership; the AI/automation (no human identity ⇒ cannot approve); revoked or expired sessions.
- **Self-approval:** LOW → allowed with step-up auth; MEDIUM → allowed with step-up + typed justification; HIGH/CRITICAL → not allowed, second principal required, and in single-user installations those classes are out of scope (deny with `SECOND_APPROVER_REQUIRED`).
- **Binding:** approval row stores proposal digest + base_commit_sha + approver id + expiry + one-time auth token (hashed at rest).
- **Replay protection:** token single-use, consumed atomically at execution start (DB unique partial index on unconsumed approvals).
- **Revocation:** approval or proposal revocable by creator/approver until EXECUTING begins; revocation propagates (authorization re-check fails).
- **Duplicate approvals:** second approval of same proposal ⇒ 409, audited; only one unconsumed approval may exist.
- **Session/CSRF threats:** SameSite=Lax baseline (V2), plus: approval POSTs require re-authentication (step-up), tokens verified server-side at execution regardless of UI state, no approval logic in the browser.
- **Approval abuse table:** forged (signature/DB integrity + audit chain), replayed (single-use token), stale (expiry ×2 checks), different diff (digest), unauthorized approver (role + ownership), compromised session (step-up + execution-time re-verification), CSRF (SameSite + step-up), UI manipulation (server-side authoritative state).

---

## 7. Network Policy

- **Default: NO NETWORK in the sandbox.**
- Dependency remediation needs registry access — resolved by a **separate resolution stage**: a resolver container with egress restricted to an allowlist (`registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`), DNS restricted to approved resolvers, private-IP/metadata-endpoint (169.254.169.254, ::ffff:10/8 etc.) denied at network layer, redirects re-validated, timeouts, response size caps. Artifacts land in a content-addressed cache; hashes recorded in the verification plan.
- The executor that applies changes and runs tests runs **network-less**, consuming the cache. Untrusted lifecycle scripts therefore also have no exfiltration channel.
- Push phase: egress only to the GitHub endpoint for that installation.
- Never: unrestricted internet to an autonomous executor.

---

## 8. Rate Limits & Blast Radius

| Operation | Limit |
|---|---|
| Proposal generation | ≤ 20/h/user, ≤ 100/day/repo |
| Approvals | ≤ 30/h/user |
| Executions | ≤ 10/h/repo, ≤ 1 concurrent/repo (advisory lock) |
| Verification attempts | ≤ 2 per execution |
| Rollbacks | ≤ 3/h/repo |

Blast radius rule: **ONE action → ONE repository → ONE branch → ≤10 files → ONE approved changeset.** Batch and org-wide remediation are non-goals (V3.0).

---

## 9. UX Security Requirements

The approval interface must make scope obvious. Mandatory visible elements, not behind collapses: exact files; exact diff; why (finding + recommendation ref); risk before → expected after; validation plan; what will be executed (operation list); **what will NOT be touched** (implicit scope exclusion list); approval expiry countdown; warnings (validation_state, trust level, injection-warning flags). No "Approve all". Failure, rollback, and ROLLBACK_FAILED states get equal visual weight to success.

---

## 10. Failure Modes (fail closed, stop safely)

| Failure | Behavior |
|---|---|
| Policy engine unavailable | Proposals cannot be created/approved/executed; state frozen, audited |
| Database unavailable | Everything halts (source of truth lost) |
| Redis unavailable | No queue dispatch; API falls back to explicit failure, not silent skip |
| Worker unavailable | Proposals age out via expiry; approved-but-unexecuted actions expire |
| GitHub unavailable | Authorization/execution blocked; token cannot be minted ⇒ stop |
| Verification fails | FAILED → deterministic ROLLBACK → audit + notification |
| Sandbox fails to start/teardown | Execution marked FAILED; workspace never reused |
| Recommendation stale (finding state changed) | Proposal invalidated at authorization (re-checked) |
| Repository changed | Stale-state golden path: execution blocked, new proposal required |
| Approval expired | Execution denied, proposal → EXPIRED |
| Credentials expired | Token mint is per-execution; expired ⇒ stop, retry only via new authorization |
| Network unavailable | Resolution/push stage fails ⇒ execution FAILED, rollback of any local application |
| Kill switch on | DENY at proposal/authorization/pre-execution; queue cancelled |

---

## 11. Environment Separation

`environment ∈ {development, staging, production}` is a policy-engine input. Per-environment policy sets: production = stricter approval levels (no LOW auto-allow ever), lower rate caps, mandatory second approver for HIGH/CRITICAL, shorter approval TTL. Development credentials/config cannot satisfy production policy because environment is validated server-side from deploy context, not client input.

---

## 12. Emergency Stop (kill switch)

- Global flag `V3_EXECUTION_DISABLED` in DB + replicated cache. Checked at three points: proposal creation, authorization, pre-execution (worker-side). All three must read "enabled" to proceed — **fails closed** (DB read error ⇒ deny).
- Toggling off: immediate, audited (actor, reason). Optionally cancels queued actions (state → REVOKED, reason KILL_SWITCH).
- Re-enable: explicit privileged operation, audited, with a mandatory reason; never automatic.

---

## 13. Observability

Metrics (distinguishable security-event class, prefixed `cyvrix.security.*`): proposals_created, policy_{allow,require_approval,deny}, approvals_{granted,rejected,expired,revoked}, executions_{started,succeeded,failed}, verifications_{passed,failed}, rollbacks_{executed,failed}, kill_switch_{on,off}, digest_mismatches, stale_state_blocks, rate_limit_hits.

Rules: security events are structured logs + metrics with a fixed schema; never log secrets, tokens, or full repo content; diff references stored by hash reference, content only in DB/audit storage.

---

## 14. Security Property Table

| Property | Enforcement layer | Test required |
|---|---|---|
| Action authorization | Policy engine (×3 eval points) | API/integration test |
| Approval binding | Action digest + approval row | Security test (golden path 4) |
| One-time authorization | Hashed token + unique constraint | Security test (replay) |
| Filesystem confinement | Sandbox + path resolver | Adversarial test (traversal/symlink/unicode) |
| Network confinement | Sandbox network policy + resolver allowlist | Integration test (egress probe) |
| Credential isolation | Token injection design + env separation | Security test (secret scan of sandbox env) |
| Scope immutability | Digest + structured operations | Adversarial test (proposal mutation) |
| Stale-state protection | base_commit_sha ×2 checks | Security test (golden path 5) |
| Rollback | Rollback controller + snapshot | Failure test (rollback of rollback) |
| Auditability | Hash-chained audit_events | Integrity test (tamper detection) |
| Rate limiting | Redis buckets + DB constraints | Load/abuse test |
| Kill switch | 3-point fail-closed check | Failure test (DB down + switch on) |
| Double execution | Idempotency + advisory lock | Concurrency test |
| Concurrent decision races (V3.2) | Proposal row lock + in-lock re-checks + `uq_approvals_live` unique index | Genuine simultaneous-request race tests (`test_approval_races.py`, real PG, ≥10 reps/class) |
| Prompt injection resistance | Hierarchy §2 + content-as-data | Adversarial test (golden path 3) |
