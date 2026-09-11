# CYVRIX V3 — Action Policy

Status: §1 policy table is **IMPLEMENTED** as executable rules POL-001…POL-028 in `apps/api/app/services/policy_engine.py` (policy_version "3.1") — see docs/v3-action-model.md. Sandbox/execution sections remain design-only.
Companion: `v3-architecture.md`, `v3-security-model.md`, `v3-execution-model.md`

---

## 1. Policy Engine

### 1.1 Contract

Pure function, no I/O, versioned:

```
evaluate(proposal, context) -> PolicyDecision
  context   = { environment, user_role, kill_switch, repo_active, repo_head_sha,
                validation_state, trust_level, risk_level, risk_score, finding_severity }
  decision  = { result: ALLOW | REQUIRE_APPROVAL | DENY,
                approval_level: LOW | MEDIUM | HIGH | CRITICAL | none,
                requirements: [EXPIRY(t), STEP_UP_AUTH, SECOND_APPROVER, ...],
                reason_codes: [...], policy_version }
```

Same inputs ⇒ same decision, always. `policy_version` stored with the proposal and every audit event. Evaluated at: proposal creation, authorization, and worker pre-execution.

### 1.2 Decision table (V3.0, production environment)

| # | Condition | Decision |
|---|---|---|
| 0 | Kill switch on / DB read fails | DENY (fail closed) |
| 1 | Repository inactive | DENY |
| 2 | Recommendation `validation_state = UNSAFE` | DENY (`UNSAFE_RECOMMENDATION`) |
| 3 | `validation_state = UNVERIFIED` | DENY (`UNVALIDATED_RECOMMENDATION`) — exception requires explicit ops config, never per-request |
| 4 | Unknown/expired/deprecated action type | DENY (`UNKNOWN_ACTION_TYPE`) |
| 5 | Any target file outside the type's file allowlist | DENY (`FILE_OUT_OF_SCOPE`) |
| 6 | Target file in denylist (auth code, `.github/workflows/*`, secrets, binaries, lockfile-of-wrong-ecosystem) | DENY (`PROTECTED_PATH`) |
| 7 | `intended_changes` fails type schema / contains disallowed operation / arbitrary command / non-allowlisted URL | DENY (`INVALID_OPERATION`) |
| 8 | Scope > 10 files or > 500 changed lines | DENY (`BLAST_RADIUS`) |
| 9 | Risk level CRITICAL on target finding | REQUIRE_APPROVAL level CRITICAL (second approver; out of scope for single-user installs) |
| 10 | `DOCUMENTED_SECURITY_FIX` (docs only, no semantic change) | REQUIRE_APPROVAL LOW |
| 11 | `DEPENDENCY_UPGRADE` patch/minor, trust SUPPORTED, risk ≤ HIGH | REQUIRE_APPROVAL MEDIUM |
| 12 | `DEPENDENCY_UPGRADE` major version bump | REQUIRE_APPROVAL MEDIUM + typed justification + explicit regression plan |
| 13 | `DOCKERFILE_UPDATE` / `CONFIGURATION_UPDATE` | REQUIRE_APPROVAL MEDIUM (HIGH if file touched production config class) |
| 14 | CI security control files (even if a rule would allow) | REQUIRE_APPROVAL HIGH — future; V3.0 denylist denies outright |
| 15 | Attempt to modify authentication code | DENY (never approvable) |
| 16 | Attempt to execute shell/script/arbitrary command | DENY (never approvable) |
| 17 | Branch is default/protected AND push-to-branch mode | DENY — V3.0 only executes onto **new remediation branches** |
| 18 | Default fallthrough (no rule matched) | DENY (`NO_MATCHING_RULE`) |

Development/staging environments may relax only levels 11–13 (never the DENY rows). Production is the table above.

**AI never decides authorization.** The model can populate proposal fields; the engine above alone decides.

---

## 2. Action Type Allowlist

Each type defines: schema, allowed files, allowed operations, validation requirements, risk class, authorization policy. Unknown types are denied by rule 4.

### 2.1 `DEPENDENCY_UPGRADE` — risk class MEDIUM

- **Allowed files:** the manifest(s) and lockfile(s) from the finding's evidence, same ecosystem only — e.g. `package.json` + `package-lock.json`, or `requirements.txt` (+ generated lock diff), or `pyproject.toml`/`poetry.lock`.
- **Allowed operations (structured):**
  - `SetDependencyVersion {name, ecosystem, from_version, to_version, file}`
  - `UpdateLockfile {file, resolved_entries[]}` (produced by resolution stage, never hand-written)
- **Forbidden:** adding new dependencies (dependency explosion attack surface), changing registries, `postinstall`-adjacent fields, version ranges (`^`/`~`/`*` — exact pins only), touching other packages "while we're in there".
- **Validation:** lockfile parses; resolution succeeds in sandbox; install with lifecycle scripts disabled; tests; re-scan; before/after risk comparison.
- **Authorization:** REQUIRE_APPROVAL MEDIUM (see table 11–12).

### 2.2 `DOCKERFILE_UPDATE` — risk class MEDIUM

- **Allowed files:** only Dockerfile paths present in the finding's evidence (`Dockerfile`, `*.Dockerfile`).
- **Allowed operations:** `ReplaceInstructionLine {line_no, from, to}`, `AppendInstruction {after_line, instruction}`, `RemoveInstructionLine {line_no}` — validated against the container scanner's grammar; final file must re-parse and improve the rule result.
- **Forbidden:** new `RUN` instructions executing scripts, network fetches, secrets, `--privileged`, multi-stage rewrites (out of scope for structured ops).
- **Validation:** parser accepts result; container security rules re-evaluate with the targeted rule cleared and zero new rule hits; build validation only if the build profile is explicitly enabled (separate sandbox profile, network-restricted).

### 2.3 `CONFIGURATION_UPDATE` — risk class MEDIUM–HIGH

- **Allowed files:** per-rule allowlist (e.g. specific config path named in evidence). Default allowlist is empty ⇒ nothing is configurable without a shipped rule, by design.
- **Allowed operations:** `SetConfigKey {path, key, value}` on typed schemas (JSON/YAML/TOML with schema validation), no shell, no templating.
- **Forbidden:** anything under auth/, secrets/, TLS material, service definitions; production config class escalates approval to HIGH.
- **Validation:** schema-valid, targeted tests, security policy lint (e.g. no weakenings: debug off, TLS on).

### 2.4 `DOCUMENTED_SECURITY_FIX` — risk class LOW

- **Allowed files:** documentation/comments only (README sections, `SECURITY.md`, code comments in files named by the finding).
- **Allowed operations:** `ReplaceTextSpan` bounded spans; result must not alter code semantics (verified: no AST/bytecode diff outside comments).
- **Validation:** semantic-diff check, docs lint.
- **Authorization:** REQUIRE_APPROVAL LOW (self-approval allowed with step-up).

### 2.5 Explicitly NOT permitted (V3.0)

`FILE_EDIT` (arbitrary), `SHELL_COMMAND`, `SCRIPT_EXECUTION`, workflow/CI edits, git hooks, binary files, env/secret files, `package.json` scripts section, dependency *addition* or *removal* (upgrade only).

---

## 3. Action Scope

Every proposal enumerates: repository, branch (always a **new** remediation branch derived from `base_commit_sha`), files, allowed operations, expected diff (bounded, digest-covered), expected result (rule resolved, risk delta).

Scope escape prevention: the executor's operation set is closed-world; each operation's file target is checked against the proposal's `intended_files` **and** the type allowlist **and** the denylist, then resolved and confined (§4). Any operation not in the approved set ⇒ deny + audit. The approved changeset cannot grow at execution time.

---

## 4. Path Security

Defenses required of the executor's path resolver (adversarial test suite mandatory):

- Reject absolute paths; reject `..` segments after normalization; reject NUL, control chars, Windows separators, trailing dots/spaces.
- **Unicode normalization** (NFC) applied before checks; reject mixed-lookalike forms (homoglyph policy: allow only NFC forms present in `intended_files`).
- Resolve symlinks (including nested chains) with `realpath` and verify containment inside the sandbox workspace **after** resolution; reject hardlinks escaping the workspace; mount-point detection (reject paths crossing from workspace into other mounts).
- Re-validate every path at open time (TOCTOU within the executor too) — never trust the earlier check, never trust the path merely because it came from an approved action.
- Depth/length caps; per-file size caps; file-count caps.

---

## 5. Supply Chain Checks (applies to `DEPENDENCY_UPGRADE`)

The resolution stage and policy must check the target version, not assume "upgrade = safe":

- Registry provenance: target version must exist in the canonical registry named by the ecosystem; reject versions resolvable only from unfamiliar registries.
- Typosquat/lookalike screening against the known package name (edit distance + explicit registry `name` match).
- Publish-age heuristic: flag (require justification) versions published < 48h; deny versions published < 24h.
- New-dependency detection: resolution result introducing packages not in the current lock ⇒ deny (rule: upgrade only).
- Dependency-explosion cap: resolution may not grow the tree by more than a configured factor.
- Advisory cross-check: target version must have no known OSV advisories at its own version (don't trade one CVE for another).
- Lockfile diff review: every resolved entry change appears in the approval diff; unexplained lock churn ⇒ deny.

---

## 6. Package Lifecycle Script Safety

Default V3.0 position: **do not execute untrusted lifecycle scripts.**

- `npm install --ignore-scripts` (or equivalents: `pip install --no-deps` + pre-resolved wheels, `poetry install --no-root` semantics) inside the verification sandbox; scripts neither run nor needed for lockfile validity.
- Tradeoffs documented: `--ignore-scripts` can break packages with build steps — acceptable for V3.0 because verification is install+tests, not full builds; a future opt-in "scripts allowed" profile would require: explicit approval line-item, network-restricted script stage, syscall monitoring, and per-package reputation data. Out of scope now.
- Verification of install correctness uses the resolved tree + lockfile invariants + import/smoke tests, not postinstall artifacts.

---

## 7. Diff Guarantees

- Expected diff is part of the digest. Executor computes actual diff and compares file set + operation set (content may vary only within operation-defined bounds, e.g. lockfile resolved entries must equal the resolution stage output exactly).
- Any actual-vs-expected delta ⇒ deny execution, fail closed, audit.

---

## 8. Environment Policy Matrix

| | development | staging | production |
|---|---|---|---|
| DENY rows 0–9, 15–18 | enforced | enforced | enforced |
| Approval TTL | 8h | 4h | 1h |
| Proposal TTL | 72h | 48h | 24h |
| HIGH/CRITICAL classes | second approver required | second approver required | second approver required |
| Rate caps | highest | medium | lowest |
| Kill switch | honored | honored | honored (and checked first) |

Development policy can never silently grant production authority: environment is server-derived, and each environment's engine instance carries its own `policy_version` and rule set.
