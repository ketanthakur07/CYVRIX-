# CYVRIX V3 — Architecture Specification

Status: PARTIAL IMPLEMENTATION. **V3.1 (action model + policy engine) is IMPLEMENTED — see docs/v3-action-model.md. V3.2 (human approval) is IMPLEMENTED — see docs/v3-approval-model.md. V3.3 (execution authorization gate) is IMPLEMENTED — see docs/v3-execution-authorization.md. V3.4 (sandboxed LOCAL structured execution: container-per-execution, non-root, network-off, bounded, host-side scope verification; NO push, NO pull requests, NO rollback) is IMPLEMENTED — see docs/v3-execution-model.md and the V3.4 sections of docs/v3-security-model.md. V3.5 (git remediation), V3.6 (verification), V3.7 (rollback + operational controls) and V3.8 (tamper-evident audit integrity: per-tenant hash chains, signed checkpoints, append-only triggers, read-only audit API, standalone export verification — see docs/v3-audit-integrity.md) are IMPLEMENTED.**
Version: 3.0.0-draft1
Supersedes: nothing (extends V2, documented in `docs/v2-architecture.md`)
Companion docs: `v3-security-model.md`, `v3-action-policy.md`, `v3-execution-model.md`, `v3-threat-model.md`, `roadmap-v3.md`

---

## 1. Current V2 Architecture (repository-derived inventory)

Verified against the working tree on 2026-09-07.

### Stack

| Layer | Technology | Location |
|---|---|---|
| API | FastAPI, async SQLAlchemy (asyncpg) | `apps/api/app/` |
| Frontend | Next.js 14 App Router, React Query | `apps/web/` |
| Worker | RQ (Redis Queue), sync SQLAlchemy | `services/worker/` |
| Database | PostgreSQL 16 (Alembic-managed schema) | `apps/api/alembic/` |
| Queue/Cache | Redis 7 (RQ + sessions + rate limits + OAuth state) | `infra/docker-compose.yml` |
| AI | OpenAI (investigation, recommendation AI fallback) | `app/services/investigation.py`, `recommendation_engine.py` |
| Advisory data | OSV batch API, Trivy provider | `app/services/providers.py` |

### Authentication & session

- GitHub OAuth login (`/api/auth/login` → `/api/auth/github/callback`). OAuth `state` stored in Redis, 10-min TTL, single-use.
- User records keyed by `github_id`; no local passwords.
- Sessions: Redis-backed (`session:{id}`), cookie `cyvrix_session` = `session_id.HMAC-SHA256(session_id, SECRET_KEY)`, TTL 24h sliding, `httpOnly`, `SameSite=Lax`, `Secure` enforced in production by config validator. Fail closed: no valid session ⇒ 401. Revocable (logout destroys Redis entry).
- Rate limits: Redis token buckets — auth 30/min per IP, login init 10/min, scans 10/hour.

### Authorization

- Single principal chain on **every** route: `user → github_installation → repository`, enforced by SQL joins, cross-tenant access returns 404 (IDOR-safe).
- No role model exists — one user class, owner of its own installations.
- Repository `is_active` flag gates scan creation; non-terminal scan uniqueness guard (409).

### GitHub integration

- GitHub App; RS256 JWT → short-lived installation access token (`app/services/github.py`).
- Token used only for: clone URL (`x-access-token`), contents read, code search (investigation evidence). Dropped from memory after clone.
- Read-only. No webhook endpoint consumes `GITHUB_WEBHOOK_SECRET` (configured but unused). No write permissions requested.

### Scanners (all static, no execution of repo code)

- **Dependency (V1):** manifest detection (package.json, package-lock.json, requirements.txt, poetry.lock) with path/symlink validation and hard limits → OSV/Trivy providers → normalized findings, fingerprint-deduped.
- **Container (V2.1):** Dockerfile static rules (root user, unpinned images, secrets in ENV, curl-pipe-shell, ADD vs COPY, missing HEALTHCHECK…), workspace path validation.
- **Log (V2.2):** text/JSON log pattern detection (brute force, admin access, path probing), bounded correlation windows.
- **Investigation:** AI, bounded — HIGH/CRITICAL only, ≤20 LLM calls/scan, ≤3 evidence files via GitHub code search, capped prompt/output sizes, JSON schema-validated output with retry-once.
- **Risk:** deterministic pure function `calculate_risk_safe`, 0–100, versioned (`risk_version` persisted).
- **Recommendation (V2.5):** deterministic rules first; AI fallback (`generate_ai_recommendation`); trust levels SUPPORTED/LIKELY/UNCERTAIN.
- **Re-validation (V2.6):** pure function; states VALIDATED / PARTIALLY_VALIDATED / UNVERIFIED / UNSAFE.
- **Reports:** markdown/JSON, generated on demand, persisted to `reports`.

### Worker pipeline

- 3 RQ queues: `scans`, `container_scans`, `log_analysis`; scheduler enabled.
- Per-job: temp workspace `mkdtemp(0o700)` → clone via installation token → static scan → persist findings (dedup by `(repository_id, fingerprint)` unique constraint) → risk → recommendations → `COMPLETED` + AuditEvent → workspace `rmtree` in `finally` (double cleanup guard).

### Data model (findings-side)

`User → GithubInstallation → Repository → Scan → Finding (fingerprint, source_type, evidence) → Investigation (1:1) / RiskAssessment (versioned) / Recommendation (validation_state)`; `Report`; `AuditEvent(repository_id, finding_id, event_type, metadata)`.

### Audit posture (baseline for V3)

- `audit_events` exists and records scan lifecycle events, **but**: no `user_id` column, no action linkage, no immutability enforcement (rows are updatable via the ORM), no hash chain. V3 extends this (§12, security model).

### Trust-relevant V2 gaps V3 must address

1. No role/approver concept — V3 introduces one deliberately (§5).
2. Audit rows not tamper-evident; not attributed to users.
3. No webhook intake; repo sync is callback-driven.
4. SameSite=Lax is the only CSRF defense; adequate for V2's read-only + low-stakes writes, inadequate for irreversible actions — V3 approval endpoints add step-up defenses.
5. AI output enters the system as structured fields — good — but V3 must guarantee AI output can never become an executable action without crossing the policy/approval boundary.

---

## 2. V3 Objective

**V3 does NOT mean "give the AI terminal access."**

**V3 means:** a narrowly scoped, explicitly authorized security action, under human-controlled deterministic policy, inside a constrained execution environment, with mandatory verification, deterministic rollback, and complete auditability.

Preserved properties: least privilege · explicit authorization · deterministic policy · human oversight · isolation · rollback · verification · auditability · bounded execution.

V3 pipeline (every stage mandatory, no stage skippable):

```
Finding → Investigation → Risk → Recommendation (V2)
    → Action Proposal
    → Policy Evaluation            (deterministic, authoritative)
    → Human Approval               (bound to immutable digest)
    → Action Authorization         (one-time token, pre-execution re-check)
    → Sandbox                      (ephemeral, no network, non-root)
    → Controlled Executor          (structured operations only)
    → Verification                 (per action type, mandatory)
    → Success / Failure
    → Rollback if needed           (deterministic, auditable)
    → Audit Event                  (append-only, tamper-evident)
```

---

## 3. Core Architecture

### 3.1 Components

| Component | Responsibility | Runs in |
|---|---|---|
| **ActionProposalService** | Build structured proposals from recommendations; compute digest | API process |
| **Policy Engine** | Pure function: (proposal, context) → ALLOW / REQUIRE_APPROVAL / DENY + requirements | API process (called in-route and re-invoked in worker) |
| **ApprovalService** | Approval records, digest binding, expiry, one-time authorization tokens | API process |
| **Action Orchestrator (worker)** | State machine owner; drives sandbox → executor → verification → rollback | dedicated V3 worker process/queue |
| **Sandbox Runner** | Ephemeral isolated workspace; provisions executor env | host with container-per-execution (no Docker socket inside) |
| **Controlled Executor** | Applies structured operations; no shell, no AI | sandbox container (non-root, no network) |
| **Verification Engine** | Per-type checks + before/after security comparison | sandbox (checks) + worker (comparison) |
| **Rollback Controller** | Deterministic restore from snapshot; revert commit if needed | worker |
| **AuditService** | Append-only, hash-chained audit events for every state transition | both API and worker |
| **V3.8 IntegrityChain** | Per-tenant SHA-256 hash chains (`audit_service`), HMAC-signed checkpoints (key outside the DB), DB-level append-only triggers, read-only `/api/audit` surface, deterministic NDJSON export + standalone no-DB verifier | both API and worker |

### 3.2 Dataflow principles

- **AI proposes, policy decides, executor obeys.** The model has no channel to: shell, filesystem, git, GitHub API, database, Redis, credentials, or deployment. Its only output surface is a structured `ActionProposal` JSON which is validated, policy-checked, and human-approved before anything executes.
- **Repository content is untrusted data** at every stage (§ security model). It can never redefine authorization.
- **Policy engine is deterministic and versioned.** Same inputs ⇒ same decision, forever; decision recorded with policy version.
- **Default deny everywhere.** Unknown action type, unknown field, out-of-scope path, expired proposal, expired approval, changed repository state ⇒ deny.

### 3.3 Extension points in V2 (documented, not modified)

- `Recommendation.validation_state` feeds policy: `UNSAFE` recommendations can never be proposed.
- `Finding`/`RiskAssessment` provide the risk inputs the policy engine consumes.
- `AuditEvent` is extended (additive migration) with actor/action/digest fields.
- `services/worker/main.py` gains a dedicated `actions` queue and worker image; existing queues untouched.

---

## 4. Action Model (`ActionProposal`)

Conceptual entity — no migration yet (§19).

### 4.1 Fields

| Field | Type | Notes |
|---|---|---|
| `id` | UUID | |
| `finding_id` | UUID → findings | |
| `recommendation_id` | UUID → recommendations | must reference a recommendation with `validation_state ≠ UNSAFE` |
| `action_type` | enum | allowlist §5 of action policy doc |
| `repository_id` | UUID → repositories | |
| `base_commit_sha` | text | repository state pinned at proposal time (TOCTOU defense) |
| `target_branch` | text | |
| `intended_files` | list[PathSpec] | validated against per-type allowlist |
| `intended_changes` | list[StructuredChange] | per-type schema; no free-form |
| `reason` | text | bounded |
| `evidence` | JSONB | pointers to finding evidence; no raw repo blobs needed |
| `risk_impact` | {before, expected_after, factors} | |
| `estimated_scope` | {files_changed, insertions, deletions} | caps enforced |
| `validation_requirements` | list[CheckName] | per action type |
| `policy_requirements` | JSONB | filled by policy engine: required approval level, expiry, etc. |
| `digest` | text | SHA-256 of canonical serialization (§ execution model) |
| `created_by` | UUID → users | |
| `created_at`, `expires_at` | timestamptz | default expiry 24h |
| `status` | state machine | §7 |

### 4.2 Statuses

Canonical state machine (execution model doc §5) supersedes the simpler §6 list; mapping:

```
PROPOSED            → PROPOSED / POLICY_CHECKED
PENDING_APPROVAL    → PENDING_APPROVAL
APPROVED            → APPROVED
—                   → AUTHORIZED  (added: one-time token issued & verified)
EXECUTING           → EXECUTING / VERIFYING
SUCCEEDED           → SUCCEEDED
FAILED              → FAILED / ROLLBACK_PENDING / ROLLBACK_FAILED
ROLLED_BACK         → ROLLED_BACK
REJECTED, EXPIRED, REVOKED → terminal deny states
```

### 4.3 Proposal construction rules

1. Only from a recommendation with `status=COMPLETED` and `validation_state ∈ {VALIDATED, PARTIALLY_VALIDATED}`. `UNVERIFIED` requires explicit policy-level exception; `UNSAFE` is never proposable.
2. All fields machine-generated from recommendation + finding + risk data. The AI may draft `intended_changes` **content**, but the **envelope** (files, branch, type, validation plan) is constrained by the action-type schema.
3. Any proposal that fails schema validation is rejected with an audit event; it never becomes an approval candidate.

---

## 5. Action Types (allowlist)

Full specification in `docs/v3-action-policy.md`. Summary:

| Action type | Allowed files | Risk class | V3.0 |
|---|---|---|---|
| `DEPENDENCY_UPGRADE` | manifest + lockfile only | MEDIUM | yes |
| `DOCKERFILE_UPDATE` | Dockerfile(s) named in finding evidence | MEDIUM | yes |
| `CONFIGURATION_UPDATE` | config files allowlisted per rule | MEDIUM–HIGH | limited |
| `DOCUMENTED_SECURITY_FIX` | docs/comments only, no code semantics | LOW | yes |

Explicitly not permitted in V3.0: `FILE_EDIT` (arbitrary), `SHELL_COMMAND`, `SCRIPT_EXECUTION`, workflow/CI changes, auth-adjacent files, binary files, secrets files. Each action type carries: schema, allowed files, allowed operations, validation requirements, risk classification, authorization policy.

---

## 6. Policy Engine

- **Pure, deterministic, versioned** (`POLICY_VERSION` persisted with every decision). Inputs: action type, finding severity, risk score/level, recommendation trust + validation state, target files, target branch, environment, blast radius (files count), user role, system flags (kill switch).
- Outputs exactly one of: **ALLOW** (auto-execute not granted in V3.0 — ALLOW still records an audit event and, for V3.0, all executing actions require approval; ALLOW is reserved for future low-risk classes), **REQUIRE_APPROVAL (level)**, **DENY (reason codes)**.
- Decision table with explicit rules and a **default-deny fallthrough**. AI output never reaches the policy engine as policy input beyond the already-validated proposal fields.
- Evaluated **three times**: at proposal (gate), at authorization (pre-execution), inside the worker immediately before execution (defense in depth — the worker does not trust the API).

---

## 7. Approval Model

Full specification in security model doc §6. Essentials:

- Approval is **bound to the proposal `digest`** (SHA-256 over canonical serialization), the `base_commit_sha`, and the approver identity. An approval for "fix vulnerability" in the abstract cannot authorize a different action.
- One-time **authorization token**: random 256-bit, stored hashed, single-use, consumed at execution start; bound to proposal id + digest + expiry.
- Expiry: proposals default 24h; approvals default 1h, capped at proposal expiry.
- Self-approval policy (§9 security model): LOW class — permitted with step-up authentication; MEDIUM — permitted with step-up + justification; HIGH/CRITICAL — require a second principal; in single-user installations HIGH/CRITICAL action classes are **out of scope for V3.0** (policy denies with `SECOND_APPROVER_REQUIRED`).
- Replay-proof, revocable, rate-limited, CSRF- and session-bound (SameSite + step-up auth + token re-verification at execution).

---

## 8. Sandbox & Execution

Full specification in `docs/v3-execution-model.md`. Essentials:

- Ephemeral container-per-execution, non-root user, read-only root filesystem except a single writable workspace, **no Docker socket**, **no network by default**, CPU/memory/PID/disk/timeout limits, seccomp-restricted, no host mounts, guaranteed teardown.
- Workspace cloned at the **pinned `base_commit_sha`** — never a mutable branch head.
- Repository state re-verified at authorization and at execution: if HEAD ≠ pinned SHA (or pinned SHA no longer reachable from target branch), authorization is invalidated and a new proposal is required (stale-state golden path).
- Executor applies structured operations only (e.g., `SetDependencyVersion`, `ReplaceDockerfileLine`) — no shell, no interpreter, no arbitrary file writes.

---

## 9. Verification

Mandatory per action type (§ execution model §7):

- `DEPENDENCY_UPGRADE`: lockfile parses, dependency resolution succeeds in sandbox, install with lifecycle scripts disabled, test suite runs, re-run dependency scan, before/after comparison.
- `DOCKERFILE_UPDATE`: parse, security rule re-evaluation, optional build validation (gated, separate profile), image scan if build enabled.
- `CONFIGURATION_UPDATE`: syntax, targeted tests, policy lint.
- Regression gate: an action that fixes one finding but introduces any new finding at or above the configured threshold **fails** verification.

---

## 10. Rollback

- Deterministic restore of the pre-execution snapshot (byte-level) inside the sandbox before any push; for pushed changes, a generated `revert` changeset applied through the same controlled pipeline.
- No arbitrary rollback commands. Rollback itself is a first-class, audited operation with its own state (`ROLLBACK_PENDING → ROLLED_BACK | ROLLBACK_FAILED`). `ROLLBACK_FAILED` requires human intervention and disables further actions on that repository until cleared.

---

## 11. Database Design (future entities — no migrations yet)

Conceptual tables and links:

```
action_proposals   (id, finding_id →, recommendation_id →, repository_id →, action_type,
                    base_commit_sha, target_branch, intended_files, intended_changes,
                    risk_impact, scope, policy_decision, policy_version, digest,
                    status, created_by →, created_at, expires_at)
   indexes: (repository_id, status), (status, expires_at), unique(digest) per active set

approvals          (id, proposal_id →, approver_id → users, decision,
                    proposal_digest, base_commit_sha, auth_token_hash,
                    granted_at, expires_at, consumed_at, revoked_at, reason)
   indexes: (proposal_id), (approver_id); constraint: ≤1 unconsumed approval per proposal

action_executions  (id, proposal_id →, approval_id →, started_at, finished_at,
                    sandbox_id, worker_version, execution_log_ref, result)
   constraint: unique(proposal_id) where result in (executing…terminal)  — idempotency

verification_results (id, execution_id →, check_name, passed, details, before_ref, after_ref)

rollback_events    (id, execution_id →, mechanism, status, details)

audit_events (extended)  + actor_user_id, action_proposal_id, digest,
                         prev_hash, entry_hash  (hash chain)
```

Ownership: every action record carries `repository_id` and is reachable only through the V2 ownership chain. All state transitions recorded in the hash-chained audit trail.

---

## 12. Audit Trail (V3 requirements)

Every transition emits an audit event: `WHO (actor) · WHAT (action_type, digest) · WHEN · WHY (finding/recommendation refs) · WHERE (repo/branch/base_sha) · WITH WHAT APPROVAL (approval_id, digest) · WITH WHAT VERSION (policy_version, worker_version, executor_version) · WITH WHAT DIFF (ref) · WITH WHAT RESULT`.

- Append-only enforced at DB level (insert-only grants/trigger), hash-chained (`prev_hash`).
- Security events (policy DENY, approval anomalies, kill-switch toggles) are a distinct event class from operational telemetry. Never log secrets.

---

## 13. API Design (future — not implemented)

| Endpoint | Auth | Notes |
|---|---|---|
| `GET /api/actions` | owner chain, filters | list proposals (own repos only) |
| `POST /api/actions` | owner + active repo + rate limit | create proposal from recommendation; runs policy gate; input schema-validated |
| `GET /api/actions/{id}` | owner | proposal + status + digest |
| `POST /api/actions/{id}/approve` | approver policy + step-up auth | binds digest; issues approval; rate-limited |
| `POST /api/actions/{id}/reject` | owner or approver | terminal state + audit |
| `POST /api/actions/{id}/cancel` | creator, pre-AUTHORIZED | |
| `GET /api/actions/{id}/execution` | owner | execution record + log ref |
| `GET /api/actions/{id}/verification` | owner | verification results + before/after |

All: same ownership-chain authorization as V2 (404 for cross-tenant), strict input validation, per-endpoint rate limits, audit events on every mutation. No endpoint may skip the policy gate. No "approve all" endpoint exists.

---

## 14. Frontend Design

- **Proposal view** (from a recommendation): exact files, exact changes (diff preview), risk before → expected after, validation plan, blast radius, approval requirement, expiry, warnings. Nothing dangerous hidden behind collapsed sections (UX security requirement — security model §9).
- **Approval screen:** full diff visible without scrolling tricks; explicit "WHAT WILL CHANGE / WHERE / WHY / RISK / WHAT WILL BE EXECUTED / WHAT WILL NOT BE TOUCHED" panel; single-step `[APPROVE]` / `[REJECT]`; step-up auth prompt; countdown to expiry.
- **Execution/verification view:** live state machine status, verification checklist, failure and rollback states surfaced with equal prominence (no silent success).
- No batch-approve UI in V3.0.

---

## 15. Concurrency, Idempotency, Limits

- Idempotency key = proposal `digest`; unique active-execution constraint per proposal; per-repository execution lock (DB advisory lock) prevents concurrent conflicting remediations; duplicate API calls return the existing record (409 otherwise).
- Rate limits: proposals ≤ 20/h/user, approvals ≤ 30/h/user, executions ≤ 10/h/repo, verification retries ≤ 2. Compromised account cannot flood remediations (security model §8).
- Blast radius: one action → one repository → one branch → limited files (≤10) → one approved changeset. No batch modifications in V3.0.
- **V3.2 (implemented):** approval-layer races are serialized end-to-end — every approval decision (approve/reject/revoke/consume) takes the proposal row lock, re-checks decision inputs inside the lock, and recovers from commit conflicts by surfacing the winner's state; the `uq_approvals_live` partial unique index is the final DB backstop. Deterministic outcomes are documented in `v3-approval-model.md` §7 and verified by genuine simultaneous-request tests (`tests/test_approval_races.py`, real PostgreSQL, ≥10 repetitions per race class).

---

## 16. Failure Modes & Emergency Stop

- Default behavior on any dependency failure (policy engine, DB, Redis, worker, GitHub, sandbox, verification): **stop safely, fail closed.** Explicit per-failure table in security model §10.
- **Kill switch:** global `execution_disabled` flag (DB + replicated to cache), checked at proposal, authorization, and pre-execution. Fails closed; all three checks must pass; toggling is audited and requires privileged re-enable. Existing queued actions are cancelled, not drained.

---

## 17. Environment Separation

- Policies are parameterized by `environment` (development / staging / production). Production demands stricter approval levels and lower caps; dev credentials can never satisfy production policy (policy input includes environment; rules per env in action policy doc §8).

---

## 18. Security Invariants

The 15 invariants in `docs/v3-security-model.md` §5 are binding requirements of this architecture; each maps to an enforcement layer and a required test (security property table, same doc §7).

---

## 19. Golden Paths

1. **Success path:** Finding → Recommendation(VALIDATED) → `POST /api/actions` → policy: REQUIRE_APPROVAL(MEDIUM) → approval digest-bound → AUTHORIZED (token) → worker re-checks policy + kill switch + repo state → sandbox → executor → verification passes → risk recalc shows resolution + no regressions → SUCCEEDED → audit chain complete.
2. **Failure path:** verification FAILS → deterministic rollback → ROLLED_BACK → audit → human notification. No silent success; failure states are first-class UI citizens.
3. **Malicious repository path:** injected instructions in repo content → proposal contains out-of-scope operation → schema validation or policy detects forbidden operation → DENY → nothing executes → security audit event. **Mandatory regression test.**
4. **Approval attack path:** Action A approved → payload mutated to Action B → digest mismatch → execution denied. **Mandatory regression test.**
5. **Stale repository path:** proposal @ commit X → approved → repository advances to Y → execution blocked → new proposal required. **Mandatory regression test.**

---

## 20. Implementation Phases

V3.1 Action model + policy engine → V3.2 Approval workflow → V3.3 Digest + authorization → V3.4 Sandbox infrastructure → V3.5 Controlled git operations → V3.6 Verification pipeline → V3.7 Rollback → V3.8 Audit trail → V3.9 UI → V3.10 Full security/E2E validation. Detail in `docs/roadmap-v3.md`.

> **V3.3 implementation status:** the digest + authorization phase is implemented as the **execution-authorization gate** (ADR-009, `docs/v3-execution-authorization.md`): deterministic re-validation of digest/policy/freshness/expiry/kill-switch, a server-owned fail-closed `system_controls` kill switch (POL-007 now live on re-evaluation paths), one-time atomic consumption, and an immutable, non-executable execution-authorization contract. Still no execution capability of any kind; the sandbox (V3.4) remains unbuilt.

---

## 21. Non-Goals (initial V3)

Unrestricted shell agent · unrestricted internet · autonomous production deployment · arbitrary file editing · automatic merge · organization-wide remediation · batch repository modifications · attack simulation · self-authorization by AI · approval bypass "for convenience".

---

## 22. Acceptance Gates

All 27 gates in `docs/roadmap-v3.md` §Acceptance must be checked before implementation is recommended; the final gate is "no V3 execution code added" (satisfied: this design adds documentation only).
