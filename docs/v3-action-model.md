# CYVRIX V3.1 — Action Model Implementation

Status: **IMPLEMENTED** (V3.1 — side-effect free)
Scope: ActionProposal domain model + deterministic policy engine. **No execution capability.**
Code: `apps/api/app/services/action_model.py`, `action_digest.py`, `policy_engine.py`, `app/routes/actions.py`, `app/models.py` (`ActionProposal`), migration `004`.

---

## 1. Non-Execution Guarantee

V3.1 can: understand an action → validate it → hash it → evaluate it → persist DENY / REQUIRE_APPROVAL / ALLOW decisions — and **nothing else**.

Verified by automated regression (`tests/test_actions_api.py::TestNoExecutionBoundary`):
- Behavioral: `subprocess.Popen/run/call`, `os.system`, all `enqueue_*` worker functions, and all GitHub write methods are rigged to raise during a full proposal-creation flow — none fire.
- Static (AST): no V3.1 module imports `subprocess`, `socket`, `httpx`, `requests`, `urllib`, `shutil`, `ctypes`, `multiprocessing`, `docker`, `git`, and no bare call to `eval`, `exec`, `compile`, `system`, `popen`, `Popen`, `rmtree`, `enqueue`, `create_pull_request`. Docstrings/comments are excluded from the check (only real code counts).

There is no approval workflow (V3.2), no authorization tokens (V3.3), no sandbox (V3.4), no git operations (V3.5), no verification (V3.6), no rollback (V3.7), no audit hardening (V3.8).

---

## 2. ActionProposal

Persisted entity (`action_proposals`, migration 004, additive only). Identity: **(recommendation_id, base_commit_sha, action_digest)** — unique constraint `uq_proposal_identity`; duplicate submissions return the existing proposal with HTTP 200.

| Field group | Fields | Trust role |
|---|---|---|
| Bindings | `repository_id`, `base_commit_sha` (full 40-hex SHA required), `target_branch` (strictly validated) | An action can never drift to another repository, commit, or branch |
| Content | `action_type` (allowlist), `files` (canonical paths), `operations` (typed schemas), `expected_diff`, `rationale` | The complete executable semantics; digest input |
| Security context snapshot | `risk_score`, `risk_level`, `recommendation_trust`, `validation_state` | Server-derived at creation; policy re-reads live values at evaluation |
| Policy result | `policy_version`, `policy_decision`, `policy_reason_code`, `policy_matched_rule`, `policy_explanation` | Deterministic, versioned, auditable |
| Lifecycle | `status`, `expires_at` (server-derived = created_at + 24h, client cannot set), `created_at`, `created_by` | Expiry enforced at evaluation and reconciled on read (V2 scan-timeout precedent) |

Statuses in V3.1: `PROPOSED` (transient), `POLICY_CHECKED` (decision = REQUIRE_APPROVAL; ALLOW unused in V3.1), `REJECTED` (DENY — persisted for audit), `EXPIRED` (on-read reconciliation), `STALE` (reserved; helper API defined, consumed by V3.2+).

Exclusions from digest (documented in `action_digest.py`): `id`, `created_at`, `created_by`, `status`, expiry, policy fields — the digest represents executable semantics only.

## 3. Action Types & Operations

Allowlists (unknown ⇒ invalid, no fallback):

| Action type | Files | Operations |
|---|---|---|
| `DEPENDENCY_UPGRADE` | ecosystem manifest/lockfile basenames (package.json, package-lock.json, requirements.txt, poetry.lock, pyproject.toml) | `UPDATE_DEPENDENCY_VERSION` (exact pins only, no ranges, no new packages) |
| `DOCKERFILE_UPDATE` | `Dockerfile`, `*.Dockerfile` | `UPDATE/APPEND/REMOVE_DOCKERFILE_INSTRUCTION` (curl-pipe-shell patterns rejected) |
| `CONFIGURATION_UPDATE` | **empty by design** — nothing is proposable without a shipped rule | `UPDATE_CONFIGURATION_VALUE` |
| `DOCUMENTED_SECURITY_FIX` | `*.md` | `REPLACE_TEXT` |

Every operation is an exact-key schema: unknown fields, missing fields, wrong types, out-of-range line numbers, and oversize values are all rejections. No command, script, or free-form instruction field exists anywhere.

Evidence narrowing: when finding evidence carries file paths (keys `dockerfile`, `file`, `manifest_path`, `path`, `files`), declared files must be a subset of them — stricter than basename rules. Evidence mismatch is a policy-level DENY (`OUT_OF_SCOPE_FILE`), persisted for audit.

## 4. Path Security

`normalize_and_validate_path`: rejects absolute/POSIX, Windows drives, UNC, backslash separators, `..`/`.` segments, `~`, percent-encoding, control chars, over-length, empty segments, and non-ASCII paths outside a conservative ASCII allowlist (homoglyph policy). NFC normalization is applied; normalization-changing paths are rejected as ambiguous.

Protected-path denylist (11 categories incl. CI workflows, auth, secrets, deployment, policy definitions, audit integrity, binaries) matches top-level and nested paths via a slash-prefixed probe. **Documented limitation:** this classifies *declared* paths; filename matching cannot prove what a path resolves to at execution time — the sandbox executor (V3.4+) must re-resolve real paths. Policy is authoritative; per-type allowlists default to deny.

## 5. Policy Engine

Pure function `evaluate(PolicyContext, now) -> PolicyDecision` — no DB, no network, no clock access (`now` is injected), no randomness (AST-enforced by tests). Decision model: exactly `ALLOW | REQUIRE_APPROVAL | DENY` with `policy_version`, `reason_code`, `matched_rule`, `explanation`, `approval_level`.

- `POLICY_VERSION = "3.1"` persisted with every decision.
- **All rules are evaluated; DENY > REQUIRE_APPROVAL > ALLOW; ties broken by lowest rule id (deterministic).** No rule emits ALLOW in V3.1 — approval is always required; ALLOW is reserved for future low-risk classes.
- 28 rules, POL-001 (unknown action type) → POL-028 (default-deny fallthrough). Full table in `v3-action-policy.md` and in code (`policy_engine.py::RULES`).
- Inputs are classified: trusted server-derived (validation state, trust, risk, finding status, repo active, environment, role, kill switch) vs pre-validated proposal content (files, operations, bindings). Malformed values (negative diff lines, non-int/bool risk scores, unknown enums) ⇒ DENY, never fallback-allow.

Stable reason codes: `UNKNOWN_ACTION_TYPE`, `REPOSITORY_INACTIVE`, `UNSAFE_RECOMMENDATION`, `UNVALIDATED_RECOMMENDATION`, `MISSING_VALIDATION_STATE`, `EXPIRED_PROPOSAL`, `EXECUTION_DISABLED`, `INVALID_COMMIT`, `INVALID_BRANCH`, `INVALID_PATH`, `PROTECTED_PATH`, `OUT_OF_SCOPE_FILE`, `INVALID_OPERATION`, `EXCESSIVE_FILE_COUNT`, `EXCESSIVE_OPERATION_COUNT`, `EXCESSIVE_DIFF_SIZE`, `MISSING_RISK_ASSESSMENT`, `MALFORMED_RISK`, `FINDING_NOT_ACTIONABLE`, `UNKNOWN_ENVIRONMENT`, `UNKNOWN_ROLE`, `UNKNOWN_TRUST_LEVEL`, `CRITICAL_RISK_REQUIRES_APPROVAL`, `HIGH_RISK_REQUIRES_APPROVAL`, `MAJOR_VERSION_REQUIRES_APPROVAL`, `LOW_RISK_REQUIRES_APPROVAL`, `MEDIUM_RISK_REQUIRES_APPROVAL`, `NO_MATCHING_RULE`.

## 6. Canonicalization & Digest

`action_digest.py`: UTF-8 JSON, recursively sorted keys, compact separators, NFC-normalized strings, `files` sorted (order irrelevant), `operations` order preserved (order is semantic), floats rejected. `SHA-256` over the extracted `DIGEST_FIELDS`. Determinism verified over 1000 evaluations; sensitivity verified for every semantic field (file, operation, versions, base commit, repository, branch, type, diff — including diff whitespace, which is content).

Future approvals (V3.2) bind to `action_digest` — never to titles, summaries, or human-readable text.

## 7. API

- `POST /api/actions` — validates → policy-evaluates → persists. 201 created / 200 idempotent existing / 404 cross-tenant / 422 schema failure / 429 rate-limited (20/h/user, Redis-backed, fails closed). **No execution of any kind.**
- `GET /api/actions` — own proposals only (ownership chain join), optional status/type filters.
- `GET /api/actions/{id}` — ownership-enforced (404 on cross-tenant), on-read expiry reconciliation.

Audit: every creation writes `ACTION_PROPOSAL_CREATED` with proposer, digest, policy version/decision/reason/rule, recommendation and base commit references.

## 8. AI Boundary

AI recommendations are untrusted inputs: they must already exist as validated `Recommendation` rows (`validation_state ∈ {VALIDATED, PARTIALLY_VALIDATED}`; `UNVERIFIED` ⇒ DENY; `UNSAFE` ⇒ DENY). The AI has no channel to call the policy engine, create proposals outside the schema, or influence policy inputs beyond those validated rows. `files_match_type` failures and protected-path hits are decided by policy, not by the AI.

## 9. Database / Migration

Migration `004` (revises `003`), additive only. Verified against **real PostgreSQL 16**: upgrade 001→004, insert through the ownership chain, `uq_proposal_identity` duplicate rejection, `downgrade 003` + re-upgrade round trip. V1/V2 tables and rows untouched.

## 10. Discrepancies Found During Implementation (docs vs code)

1. Docs (v3-action-policy.md §2) specify evidence-scoped file allowlists; V1/V2 findings evidence shape varies per scanner — V3.1 implements evidence narrowing over the documented evidence keys with a basename-rule fallback. Conservative behavior preserved.
2. Docs' state machine includes V3.2+ states (APPROVED, AUTHORIZED, EXECUTING…); V3.1 implements the subset above — no ambiguous states introduced.
3. `docs/v3-security-model.md` kill switch: the flag is defined but meaningful only once execution exists; V3.1 wires the policy rule (POL-007) and passes `kill_switch=False` until V3.4.
4. Docs' approval TTL (1h) is a V3.2 concern; V3.1 implements proposal TTL (24h) only.

## 11. Known Limitations

- `base_commit_sha` is format-validated but not verified against GitHub (no network in V3.1); semantic verification happens at authorization (V3.3) and pre-execution (V3.5).
- No `STALE` producer yet: staleness evaluation helpers exist; the scanner/recommendation change detection lands with V3.2.
- Protected-path matching is declared-path only (see §4 limitation).
- Evidence narrowing depends on evidence-shape conventions; malformed evidence paths contribute nothing (never widen scope).
- Second-principal approval for HIGH/CRITICAL: policy emits the level; enforcement arrives with the V3.2 approval workflow.

## 12. Test Inventory (V3.1)

223 V3.1 tests: `test_action_model.py` (path security, protected paths, allowlists, operation schemas, caps, bindings, expiry, purity) · `test_action_digest.py` (stability, sensitivity, scope, idempotent canonical form) · `test_policy_engine.py` (28-rule decision table, deny precedence, 100× determinism, default-deny properties, performance 1000 evals, AST purity) · `test_actions_api.py` (creation, idempotency, denial persistence, evidence narrowing, input abuse, IDOR, expiry reconciliation, serialization safety, behavioral + AST no-execution boundary) · `test_migrations.py` (+5: schema, FKs, identity constraint, ownership lifecycle).
