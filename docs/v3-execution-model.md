# CYVRIX V3 — Execution Model

Status: DESIGN (no implementation)
Companion: `v3-architecture.md`, `v3-security-model.md`, `v3-action-policy.md`, `v3-threat-model.md`

---

## 1. Execution Principle

The executor is a deterministic application of an approved, digest-bound operation list inside an isolated sandbox. It contains no AI, no shell, no interpreter for repository content, and no capability that was not named in the approved proposal.

```
APPROVED proposal (digest D, base SHA S)
  → worker claims job (advisory lock on repository)
  → re-checks: kill switch, policy, approval validity, repo state, digest
  → mints scoped installation token
  → provisions sandbox at commit S
  → executor applies structured operations
  → verification pipeline
  → push phase (scoped token, GitHub endpoint only) — only after verification passes
  → post-action security validation (V2 scanners before/after)
  → SUCCEEDED | FAILED → ROLLBACK
```

---

## 2. Sandbox Architecture

Treated as hostile. Chosen mechanism: **container-per-execution without Docker socket**, on a dedicated runner host; hardening path to gVisor/Firecracker-class isolation behind the same interface.

| Control | Requirement |
|---|---|
| Workspace | Ephemeral, per-execution, mounted only into this sandbox |
| User | Non-root (dedicated UID/GID per runner) |
| Root filesystem | Read-only image; writable only the workspace path |
| Host access | None; no host mounts except workspace (noexec,nodev,nosuid) |
| Docker socket | Never mounted |
| Network | Default none (security model §7); push phase is a separate minimal sidecar step |
| CPU / memory | Hard cgroup limits (e.g. 2 CPU, 2 GB) |
| Processes | pids limit (e.g. 64); no new namespaces/privileged syscalls (seccomp default-deny allowlist) |
| Time | Total execution timeout (e.g. 15 min) enforced by orchestrator AND sandbox |
| Disk | Workspace size cap (e.g. 1 GB), tmpfs caps |
| Children | Executor forbids spawning interpreters; ops library runs in-process |
| Cleanup | Guaranteed teardown + workspace shredding in `finally` (V2 worker pattern), plus runner-side reaper for crashed jobs |
| Logging | Executor emits structured events; never logs secrets or full file content |

The sandbox must never be a source of trust: verification of its outputs is done by the worker (outside), not by the sandbox (inside).

---

## 3. Digest / Canonical Serialization

```
canonical(proposal):
  JSON object, UTF-8, keys recursively sorted, no whitespace,
  timestamps = UTC ISO-8601, UUIDs lowercase, numbers plain decimal
digest = hex( SHA-256( canonical_bytes ) )
```

- Computed at proposal creation. Stored on proposal, approval, authorization token, execution, and every audit event for the action.
- Executor re-derives the digest twice: (a) from the DB proposal record, (b) from the materialized operation list it is about to apply. Both must equal the approval's digest.
- **Any change to the proposal after approval ⇒ digest mismatch ⇒ execution denied** (TOCTOU/approval-confusion defense; mandatory regression test).
- Digest covers: type, files, operations, expected diff refs, validation plan, base SHA, branch name — the complete executable semantics.

---

## 4. TOCTOU / Repository State Protection

Threat: approve at state X, repository changes, execute different content.

Protections, all mandatory:

1. `base_commit_sha` pinned at proposal creation (from the latest completed scan).
2. Authorization step verifies the pinned SHA is still the head of `target_branch`'s history (or an ancestor — rebase-tolerant) via GitHub API.
3. Pre-execution re-verification (worker-side, immediately before sandbox creation).
4. Sandbox checks out the **pinned SHA** — never a moving ref.
5. Workspace snapshot (byte-level) captured before operations for deterministic rollback.
6. Push phase verifies remote branch ref equals the executor's produced commit parent; a moved ref ⇒ abort push, mark execution FAILED(reason=REBASE_REQUIRED), propose a new action.

---

## 5. Execution State Machine

```
PROPOSED ──policy──► POLICY_CHECKED ──► PENDING_APPROVAL
PENDING_APPROVAL ──approve──► APPROVED ──token──► AUTHORIZED
AUTHORIZED ──worker claim──► EXECUTING ──ops applied──► VERIFYING
VERIFYING ──all pass──► SUCCEEDED
VERIFYING / EXECUTING ──failure──► FAILED ──rollback started──► ROLLBACK_PENDING
ROLLBACK_PENDING ──ok──► ROLLED_BACK        ──failed──► ROLLBACK_FAILED
PENDING_APPROVAL ──reject──► REJECTED
PENDING_APPROVAL / APPROVED ──expire──► EXPIRED
APPROVED / AUTHORIZED ──revoke──► REVOKED
```

Rules: transitions are single-direction (except APPROVED→REVOKED, PENDING→EXPIRED); every transition writes an audit event; no ambiguous states; SUCCEEDED requires ≥1 passing `verification_results` row per required check; the worker owns transitions from AUTHORIZED onward (API cannot mark success). `ROLLBACK_FAILED` requires human intervention and locks the repository against new executions until cleared.

---

## 6. Concurrency & Idempotency

- Idempotency key: proposal digest. One execution per proposal (unique partial index on `action_executions.proposal_id` where state is active/terminal).
- Per-repository execution lock (PostgreSQL advisory lock) held for the duration of EXECUTING→VERIFYING.
- Duplicate job delivery (RQ at-least-once): worker re-claims idempotently — a proposal in EXECUTING with a live lock is skipped, not re-executed.
- Frontend button disabling is never relied upon; the server is authoritative (V2 pattern: 409 on duplicate scan).

---

## 7. Verification Pipeline

Per action type, all mandatory checks must pass:

| Action type | Checks |
|---|---|
| `DEPENDENCY_UPGRADE` | lockfile parses · resolution succeeds (offline cache) · install with scripts disabled · test suite passes · dependency re-scan · before/after comparison |
| `DOCKERFILE_UPDATE` | Dockerfile parses · container rules re-evaluate: targeted rule cleared, zero new rule hits · optional build+scan profile if enabled |
| `CONFIGURATION_UPDATE` | schema-valid · targeted tests · security policy lint (no weakenings) |
| `DOCUMENTED_SECURITY_FIX` | semantic no-op verified · docs lint |

**Post-action security validation (before/after):** re-run relevant V2 scanners on the changed workspace; compare findings: `resolved ≥ 1`, `introduced = 0` above the configured severity threshold, risk_score after ≤ before, diff scope ⊆ approved files. Fix-one-break-three ⇒ verification FAILED.

Regression gate inputs come from V2 components unchanged: scanner, risk engine (versioned), recommendation engine.

---

## 8. Rollback Design

- Primary mechanism: restore the pre-execution workspace snapshot (deterministic, byte-level) and discard the sandbox; the remote branch was never touched yet at that point.
- If the push already happened: generate a `revert` changeset for exactly the approved diff and apply it through the same controlled pipeline (sandbox, digest-bound revert proposal, same scoped-token push). No arbitrary `git revert -` commands, no shell.
- Git hooks: created/executed never (`core.hooksPath` pointed at an empty dir, hooks ignored); no credential helpers; clone/fetch/checkout/push only, with argv arrays (no shell interpolation).
- Rollback is auditable: `rollback_events` records mechanism, diff refs, outcome.
- `ROLLBACK_FAILED`: repository execution-locked, on-call notification, manual remediation playbook referenced in the audit event.
- Rollback itself can make things worse only if non-deterministic — hence snapshot-restore and exact-diff revert only.

---

## 9. Git Safety

Allowed future operations (structured): `checkout <pinned-sha>`, `switch -c <remediation-branch> <pinned-sha>`, apply structured changes, `commit -m <template>`, `push <refspec>`, PR creation via API.
Never: arbitrary hooks, config changes (`core.*`), credential helpers, shell command strings, `force push`, merge operations. Git runs on argv arrays in the sandbox; all git failures ⇒ FAILED + audit, never partial silent states.

---

## 10. Failure Golden Paths

1. **Verification failure:** EXECUTING→VERIFYING→FAILED→ROLLBACK_PENDING→ROLLED_BACK→audit→notification. No silent success: UI shows failure with equal prominence; finding remains OPEN; a follow-up proposal is possible.
2. **Push-time conflict:** remote moved ⇒ abort, FAILED(REBASE_REQUIRED), no force push, new proposal required (stale-state discipline).
3. **Worker crash mid-execution:** lock expires, execution row stuck in EXECUTING ⇒ janitor marks FAILED(STALE_EXECUTION), snapshot discarded, audit event; repository lock released only by janitor after timeout.
