# CYVRIX V3 — Roadmap & Architecture Decision Records

Status: DESIGN (no implementation)

---

## 1. Implementation Phases

Each phase ships with its tests before the next begins. Nothing in any phase grants autonomous write access ahead of its own phase's controls.

| Phase | Scope | Exit criteria |
|---|---|---|
| **V3.1** | ActionProposal model + deterministic policy engine | Schema tests, decision-table unit tests, default-deny test, IDOR tests |
| **V3.2** | Approval workflow (records, expiry, step-up auth, self-approval policy) | Approval unit + security tests (unauthorized approver, duplicate, expiry) |
| **V3.3** | Digest (canonical serialization) + one-time authorization tokens — **IMPLEMENTED as the execution-authorization gate (ADR-009, docs/v3-execution-authorization.md): immutable digest-bound contract, fail-closed kill switch, one-time atomic consumption, genuine race tests; still zero execution capability** | Digest immutability tests, replay tests, golden path 4 regression — verified: 74 unit/API tests + 63×3 concurrent race tests on real PostgreSQL + migration 006 fresh & in-place |
| **V3.4** | Sandbox infrastructure (container-per-execution, limits, teardown) — **IMPLEMENTED as sandboxed LOCAL structured execution (docs/v3-execution-model.md, docs/v3-sandbox.md): container-per-run, non-root uid 10001, cap_drop ALL, no-new-privileges, pinned seccomp, network_mode none, read-only rootfs, frozen resource limits, credential-free sandbox, host-side BEFORE/AFTER scope verification, atomic exactly-once admission consuming the V3.3 authorization; NO push, NO pull requests, NO rollback — those remain V3.5–V3.7** | Adversarial confinement tests, egress probe test, resource-limit tests — verified: engine/API unit suites + SQLite race suites green; real-container suite (`RUN_SANDBOX_TESTS=1`) and real-PG race suite (`RUN_INTEGRATION_TESTS=1`) are the environment-gated release gates |
| **V3.5** | Controlled git operations (structured commit/push/PR, hooks neutralized) | Git safety tests, argv-array/injection tests, stale-state (golden path 5) |
| **V3.6** | Verification pipeline (per-type checks, before/after comparison) | Verification-failure tests, regression-gate tests (fix-one-break-three) |
| **V3.7** | Rollback (snapshot restore, revert changeset, ROLLBACK_FAILED handling) | Rollback tests incl. rollback-of-rollback, failure golden path |
| **V3.8** | Audit trail (actor/action/digest fields, hash chain, append-only enforcement) — **IMPLEMENTED as tamper-evident integrity chains (docs/v3-audit-integrity.md): per-tenant SHA-256 hash chains over the full lifecycle, deterministic canonicalization, closed-world event registry with centralized secret redaction, same-transaction SECURITY-CRITICAL events, HMAC-signed checkpoints (key outside the DB) for tail-truncation detection, DB-level append-only triggers, read-only capability-gated audit API, deterministic NDJSON export with a standalone no-DB verifier. TAMPER-EVIDENT, not physically immutable — residual trust documented** | Integrity/tamper-detection tests — verified: 41 canon/digest/verifier/export unit tests, 39 real-PG race + direct-DB red-team tests (concurrent append 0-duplication ×10 reps; modify/delete/insert/reorder/forge/truncate all detected; append-only trigger proven), 9 audit-API security tests, 7/7 export certification (offline verify + 4 tamper classes), migration 011 in-place on real PostgreSQL, full regression 1101 passed |
| **V3.9** | UI (proposal view, approval screen with full scope, execution/verification states) — **IMPLEMENTED as the security workflow console (docs/v3.9-console.md): API-first console over the existing V3.1–V3.8 lifecycle (action hub with authorization/execution/remediation/verification/rollback, execution/remediation/verification/rollback detail views, tamper-evident audit console, capability-gated operations console), a shared UI primitive set, one read-only `GET /api/ops/capabilities` identity view, structured error reason codes, and no new authority layer. The browser displays server state and requests transitions only — it never authorizes, executes, verifies, or rolls back** | XSS tests (V2 pattern), UX-security review checklist — verified: 109 Jest tests (types/API contracts/error reason codes/workflow presentation/XSS/static security source scan), `tsc --noEmit` clean, `next build` clean; Playwright real-stack spec `e2e/v39-workflow-console.spec.ts` (lifecycle rendering, no-authority-control assertions, capability denial, IDOR) added as the environment-gated gate |
| **V3.10** | Full security/E2E validation | E2E browser→proposal→approval→execution→verification→audit; adversarial suite (malicious repo, escalation attempts); acceptance gates all checked |
| **V4.0** | Multi-tenant platform foundation — **IMPLEMENTED (docs/v4-architecture.md, docs/v4-multitenancy.md, docs/v4-rbac.md, docs/v4-api.md, docs/v4-security.md, docs/v4-threat-model.md): organizations/memberships/invitations, roles→capabilities with last-owner protection, versioned per-org policy revisions, hashed+scoped+revocable API keys, org-scoped rate limits, a versioned read-only `/api/v1`, and an org-context console (`/orgs`, members, API keys, settings, invitation accept). Migration 012 is additive and backfills a personal organization per existing user. V4 EXTENDS the V3 chain — a capability invokes a gate and never removes one** | Tenancy/IDOR tests, concurrency races, migration certification on real PostgreSQL, org rate-limit isolation on real Redis, RBAC fail-closed client tests — verified: V4 platform 71 passed, V4 races 99 passed, org rate limits 7 passed (real Redis), migration 012 certified fresh + V3→V4 backfill + downgrade/re-upgrade on real PG, gated V3 suites green (`test_git_remediation_races.py` 53 passed; `test_sandbox_real_container.py` 12 passed on real Linux containers), Jest 169 passed, `tsc --noEmit` clean, `next build` clean |

### V4.1 — Public API + CI/CD integration: **IMPLEMENTED (external boundary complete)**

Delivered (increment 1 — "external API foundation"):

- public error contract for `/api/v1` (`detail` preserved; `code`,
  `message`, `request_id` added) — `docs/v4-public-api.md` §7
- honest scope registry: unbacked scopes moved to `PLANNED_API_SCOPES` and
  refused at issuance; no `admin:*`
- API-key **rotation** (old key dies immediately; successor preserves
  scopes and expiry; deterministic under concurrency)
- shared **idempotency / replay primitive** (migration 013,
  `api_idempotency_keys`) with same-key/same-request replay,
  same-key/different-request conflict, and tenant-scoped records
- bounded **cursor pagination** + allowlisted filters + rate-limit headers
- 11 new public read endpoints and one idempotent `POST /api/v1/scans`
  (202, request-only — never executes)
- OpenAPI: `ApiKeyBearer` declared on every public operation

Delivered (increment 2 — "external integration boundary"):

- inbound **GitHub webhooks** (`docs/v4-webhooks.md`): `POST
  /api/webhooks/github` — HMAC-SHA-256 signature verification
  (constant-time, fail-closed on unconfigured secret), delivery-id replay
  protection on the 013 primitive, event allowlist
  (push/pull_request/installation/installation_repositories), installation
  → organization → repository binding resolved ONLY from trusted DB state,
  bounded intake (10 MiB, per-IP + per-org flood control), structured
  payload-free delivery records
- **CI/CD integration** (`docs/v4-cicd.md`): thin GitHub Action (least
  privilege `contents: read`, scoped key only), commit-bound scan
  submission, polling of SERVER-computed results, fail-closed on
  unavailability — CI can never declare its own security outcome
- **commit binding**: `POST /api/v1/scans` accepts an optional full-hex
  `commit_sha`; the WORKER verifies it against the actual clone and fails
  the scan with `COMMIT_MISMATCH` before any analysis — stale CI/webhook
  events are never silently attributed to the wrong commit
- **async job status**: `GET /api/v1/scans/{scan_id}/status` with
  server-computed `result` (PASS/FAIL/null/INCONCLUSIVE) and
  `commit_binding` states (`docs/v4-async-jobs.md`)
- **audit integration**: API-key lifecycle (created/rotated fail-closed,
  revoked witnessed) + webhook lifecycle + scan requests chained into V3.8
  via new per-ORGANIZATION chains (key-only tenants now have verifiable
  history); tamper evidence inherited and tested
- **quotas** (`docs/v4-quotas.md`): atomic Redis counters, GLOBAL →
  ORGANIZATION precedence, compensated refusals, fail-closed, verified
  with 12-way concurrency on real Redis
- **metrics** (`docs/v4-metrics.md`): closed-world counter/gauge/summary
  registry with bounded content-free labels, Prometheus exposition on the
  capability-gated `GET /api/ops/metrics`
- failure-injection suite (Redis/queue/audit failures — all fail closed),
  boundary race suite (quota × concurrency, webhook × replay, audit ×
  concurrency, all real PostgreSQL + Redis), V4.1 Playwright spec
  (`e2e/v41-external-boundary.spec.ts`)

Remaining (explicit, not claimed):

- outbound webhooks (signing, delivery, retry, dead-letter)
- dedicated CI-event intake with `CI_EVENT_*` audit events (CI integrates
  today via commit-bound scan submission)
- request-only endpoints for `actions:create`, `executions:create`,
  `rollback:create`, `integrations:manage`, `audit:export` (scopes stay
  unissuable until then)
- worker-side export of `queue_depth`/`active_jobs` gauges
- bounded load-test harness at platform scale

---

Order rationale: authorization-critical primitives (model, policy, approval, digest) precede any infrastructure capable of side effects; sandbox precedes git; verification precedes rollback usage; audit hardening precedes UI trust surfaces.

---

## 2. Architecture Decision Records

### ADR-001 — AI does not directly execute actions

- **Decision:** The model's only output surface is a structured ActionProposal. It has no shell, filesystem, git, GitHub, DB, Redis, deployment, or credential access.
- **Context:** CYVRIX's core value is AI-driven security intelligence; V3 adds action. Unconstrained agent execution would multiply the attack surface (D, G, N threats) beyond acceptable residual risk.
- **Consequences:** All autonomy flows through validate→policy→approve→authorize→execute; slower but auditable; enables the rest of the model.

### ADR-002 — Human approval binds to an immutable action digest

- **Decision:** Approval records the SHA-256 of the canonical proposal serialization; execution requires digest equality at two points.
- **Context:** "Approve the fix" must never authorize "a different fix" (TOCTOU/approval confusion).
- **Consequences:** Proposals are effectively immutable post-approval; changes require a new proposal; digest-mismatch is a mandatory security regression.

### ADR-003 — Execution occurs inside an isolated sandbox

- **Decision:** Container-per-execution, non-root, read-only rootfs, no Docker socket, no network by default, hard resource caps, guaranteed teardown; gVisor/Firecracker hardening path behind the same interface.
- **Context:** Even structured, digest-bound operations run against hostile repository content.
- **Consequences:** Operational cost per execution; strong containment for N/P/Q/S threats.

### ADR-004 — Policy engine is deterministic and authoritative

- **Decision:** Pure, versioned decision function; AI output never constitutes policy input beyond validated proposal fields; evaluated at three independent points.
- **Context:** Non-deterministic authorization would make the system unauditable and gameable.
- **Consequences:** Policy changes are explicit version bumps with audit trail; default-deny guarantees unknown cases fail closed.

### ADR-005 — Verification required before success

- **Decision:** The state machine cannot reach SUCCEEDED without all per-type verification checks passing, including before/after security comparison with a no-new-findings regression gate.
- **Context:** V2's scanners become the acceptance criteria for V3's actions.
- **Consequences:** Some legitimate fixes may fail verification and need iteration; no silent regressions.

### ADR-006 — Rollback is mandatory for supported action classes

- **Decision:** Every execution carries a pre-execution snapshot and a deterministic revert path; failure paths end in ROLLED_BACK or ROLLBACK_FAILED (human intervention + repo lock).
- **Context:** Partial/failed remediation must never persist silently.
- **Consequences:** Rollback is first-class, audited, and itself constrained (no arbitrary commands).

### ADR-007 — Repository content is untrusted

- **Decision:** All repo content is data: parsed by static scanners, bounded in size, never executed, never a policy input except as bounded finding fields; instructions in content are treated as injection evidence.
- **Context:** V2 already treats repo content this way; V3 extends the discipline to proposal generation.
- **Consequences:** Golden path 3 (malicious repo) is a mandatory regression; UI must render content as inert text.

---

## 3. Acceptance Gates

- [ ] V2 architecture fully understood (inventory in v3-architecture.md §1)
- [ ] Trust boundaries documented (v3-security-model.md §1)
- [ ] Action model defined (v3-architecture.md §4)
- [ ] Action allowlist defined (v3-action-policy.md §2)
- [ ] Policy engine defined (v3-action-policy.md §1)
- [ ] Approval model defined (v3-security-model.md §6)
- [ ] Approval binding defined (v3-architecture.md §7, execution model §3)
- [ ] Digest/immutability defined (execution model §3)
- [ ] Stale-state protection defined (execution model §4)
- [ ] Sandbox defined (execution model §2)
- [ ] Network policy defined (security model §7)
- [ ] Credential isolation defined (security model §4)
- [ ] GitHub permission model defined (security model §4.1; Contents:write + PRs:write, short-lived, repo-scoped — no admin/workflow/secrets)
- [ ] Verification defined (execution model §7)
- [ ] Rollback defined (execution model §8)
- [ ] Audit model defined (security model §12, architecture §12)
- [ ] Failure states defined (security model §10, execution model §5/§10)
- [ ] Emergency stop defined (security model §12)
- [ ] Concurrency/idempotency defined (execution model §6)
- [ ] Resource limits defined (security model §8, execution model §2)
- [ ] Threat model completed (v3-threat-model.md)
- [ ] Red-team review completed (v3-threat-model.md §2, incl. one accepted residual risk: Threat G)
- [ ] Test architecture defined (security property table + per-phase exit criteria)
- [ ] Golden paths defined (architecture §19; success, failure, malicious repo, approval attack, stale repo)
- [ ] Non-goals documented (architecture §21)
- [ ] Implementation order documented (§1 above)
- [ ] **No V3 execution code added** — satisfied: this design cycle produced documentation only; all V2 behavior untouched.

---

## 4. Test Architecture (V3 pyramid)

Every new security boundary requires a negative test. Distribution:

- **UNIT:** action schema validation (unknown fields, out-of-scope files, arbitrary commands/URLs, expired proposals) · policy engine decision table incl. default-deny fallthrough · state machine transitions (no skips, no ambiguity) · digest canonicalization (stability + sensitivity) · approval rules (who/when/self-approval/expiry) · scope validation · rollback rules.
- **SECURITY:** IDOR on every new endpoint · approval bypass · replay · stale approval · scope expansion attempts · path traversal (`../`, absolute, unicode, symlink chains, separators) · command injection surfaces · SSRF probes · prompt injection fixtures · secret leakage scans of sandbox env · sandbox escape attempts.
- **INTEGRATION:** policy→approval→queue→worker→DB→GitHub flows · token mint/consume lifecycle · advisory-lock concurrency.
- **E2E:** browser → proposal → approval → execution → verification → audit, plus the failure golden path surfaced correctly in UI.
- **ADVERSARIAL:** malicious repository fixtures (injection in README/Dockerfile/log/package metadata) → attempted action escalation → must end in policy DENY with audit event, nothing executed. Golden paths 3–5 (malicious repo, approval attack, stale repository) are **mandatory regression tests** that ship with their enabling phase (V3.3/V3.5).

CI ordering: unit+security gate every PR; integration on merge; adversarial suite nightly and blocking V3.10 exit.

## 5. Open Items Carried Into Implementation

1. Threat-G hardening: external authorizer service signing per-action push credentials (target ≤ V3.4). V3.3 shrank the surface: authorization is now a separately auditable, digest-bound artifact consumed through one audited gate, but the decision still lives in the worker's trust domain until the external authorizer lands.
2. Role model details (owner/approver) and second-principal UX for org installations.
3. Webhook intake (currently unused `GITHUB_WEBHOOK_SECRET`) for push-based stale-state detection.
4. Build-validation profile for DOCKERFILE_UPDATE (builds are costly and risky; deferred behind explicit enablement).
5. Two-person rule for policy version changes (insider risk J).
