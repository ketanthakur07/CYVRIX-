# CYVRIX V3 — Threat Model (Red Team)

Status: DESIGN (no implementation)
Method: STRIDE-flavored adversary enumeration against the V3 design in `v3-architecture.md` / `v3-security-model.md` / `v3-action-policy.md` / `v3-execution-model.md`.
Residual risk ratings assume all listed mitigations are implemented and tested.

---

## 1. Threat Matrix

### A. Malicious repository author

| | |
|---|---|
| Attack path | Hostile content in repo (Dockerfile, manifest, logs, README) influences proposal generation toward a broader action than the finding warrants |
| Impact | Out-of-scope file modification on push |
| Mitigation | Content is data (hierarchy §2); proposal envelope constrained by action-type schema; file allowlist + denylist; digest-bound scope; policy DENY rows 5–7; executor closed-world ops |
| Residual risk | LOW — a validly-scoped bad *change within* approved files remains possible; caught by verification gate + human diff review |
| Detection | Policy DENY audit events; schema-validation rejections |
| Recovery | Nothing executed on DENY; new proposal possible |

### B. Compromised GitHub account (CYVRIX user)

| | |
|---|---|
| Attack path | Attacker with a valid session floods proposals/executions on the victim's repos |
| Impact | Remediation spam, wasted resources, noisy PRs; no privilege expansion |
| Mitigation | Rate limits (§8 security model); blast radius 1-action/1-repo; approval expiry; kill switch; scoped installation tokens ≤10 min; attacker gains no credentials |
| Residual risk | MEDIUM — a compromised owner can still approve own LOW/MEDIUM actions; step-up auth raises the bar but session theft with step-up bypass (phishing) remains |
| Detection | Rate-limit metrics, step-up auth failures, unusual proposal volume |
| Recovery | Kill switch; revoke sessions (`destroy_user_sessions`); rotate app credentials |

### C. Malicious contributor (repo committer, no CYVRIX account)

| | |
|---|---|
| Attack path | Push content that changes scan results post-approval (stale-state exploitation) |
| Impact | Executor applies change against unexpected state |
| Mitigation | base_commit_sha pinning ×2 checks (authorization + pre-execution); push-phase parent verification; sandbox checks out pinned SHA only |
| Residual risk | LOW |
| Detection | Stale-state block metric; REBASE_REQUIRED failures |
| Recovery | Execution blocked; new proposal required |

### D. Prompt injection

| | |
|---|---|
| Attack path | "Ignore previous instructions…" in README/Dockerfile/log/package metadata → AI drafts a dangerous proposal |
| Impact | Only as far as schema/policy/approval allow — target is the human, via a poisoned approval diff |
| Mitigation | Content-as-data hierarchy; AI output only populates proposal fields passing TB-1/TB-2; policy denylist; **human sees exact diff with WHAT-WILL-NOT-BE-TOUCHED panel**; injection-flag warnings on proposal UI |
| Residual risk | MEDIUM — social-engineering the human approver via a plausible diff is the irreducible core; mitigated by scope caps (≤10 files) and verification gate |
| Detection | Injection-pattern flags on repo content (audited); approval of proposals with injection warnings |
| Recovery | Rollback; deny persists in audit |

### E. Compromised AI provider

| | |
|---|---|
| Attack path | Provider returns malicious proposal content or wrong evidence |
| Impact | Bad recommendations/proposals |
| Mitigation | Deterministic-first recommendation (AI is fallback); re-validation (UNSAFE never proposable); schema validation; policy gate; human approval on exact diff |
| Residual risk | LOW |
| Detection | validation_state downgrades; trust-level inconsistency checks |
| Recovery | Proposal rejected; provider isolated behind provider interface (V2 pattern) |

### F. Malicious recommendation (bad deterministic rule or AI hallucination)

| | |
|---|---|
| Attack path | Recommendation suggests an upgrade that breaks or a change that harms |
| Impact | Failed verification at minimum; human harm only if approved |
| Mitigation | Verification pipeline mandatory; regression gate (fix-one-break-three fails); before/after scanner comparison |
| Residual risk | LOW |
| Detection | verification_results failures |
| Recovery | Deterministic rollback |

### G. Compromised worker

| | |
|---|---|
| Attack path | Worker host compromised → executes unapproved actions |
| Impact | Highest single-point impact |
| Mitigation | Worker holds no standing write credentials (tokens minted per execution, ≤10 min); worker cannot forge approvals (DB constraints + digest chain + audit hash chain); audit chain tamper-evidence; worker is the only git-capable component but is policy-gated *inside itself* by design |
| Residual risk | MEDIUM — a fully compromised worker bypasses in-process gates; compensating controls: GitHub-side branch protection, audit chain anomaly alerts, per-repo lock, token scoping, short TTLs. Documented as accepted residual risk requiring host hardening roadmap |
| Detection | Audit chain integrity checks; execution without matching approval row (DB constraint violation) |
| Recovery | Kill switch; revoke GitHub App; rotate secrets |

### H. Queue poisoning

| | |
|---|---|
| Attack path | Crafted job payloads injected into RQ |
| Impact | Worker executes unexpected task |
| Mitigation | V2 pattern: payload is a scan/action id only; worker re-validates all state from DB; Redis in private network; no client-controlled data in payloads |
| Residual risk | LOW |
| Detection | Job id vs DB state mismatch logs |
| Recovery | Drain queue; kill switch |

### I. Stolen session

| | |
|---|---|
| Attack path | Cookie theft → act as user |
| Impact | See B |
| Mitigation | httpOnly + Secure + SameSite=Lax; HMAC-signed session id; 24h sliding TTL; step-up auth on approval; execution-time re-verification |
| Residual risk | MEDIUM (phishing/step-up bypass) |
| Detection | Session anomaly logging; step-up failures |
| Recovery | Logout-all (existing `destroy_user_sessions`) |

### J. Insider abuse

| | |
|---|---|
| Attack path | Operator toggles policy/kills/exports data |
| Impact | Bounded by audit chain |
| Mitigation | Hash-chained audit; privileged actions (kill switch, re-enable, policy change) audited with actor+reason; no silent mutation |
| Residual risk | LOW-MEDIUM (two-person rule for policy changes recommended, not in V3.0) |
| Detection | Audit review; policy_version change alerts |
| Recovery | Revert policy version; audit forensics |

### K. Approval bypass

| | |
|---|---|
| Attack path | Execute without approval via API manipulation |
| Impact | Unauthorized change |
| Mitigation | Worker-side re-check of approval row + digest + token; state machine ownership (API cannot mark success); DB constraint: execution requires approval_id with unconsumed valid token |
| Residual risk | LOW |
| Detection | Authorization-failure audit events |
| Recovery | Deny; nothing executed |

### L. Replay attack

| | |
|---|---|
| Attack path | Reuse captured approval/token |
| Impact | Second execution of same action |
| Mitigation | One-time token (hashed, unique partial index, consumed atomically); proposal digests unique per active set; expiry ×2 |
| Residual risk | LOW |
| Detection | Duplicate-approval 409s audited |
| Recovery | Deny |

### M. TOCTOU

| | |
|---|---|
| Attack path | Approval→execution gap exploited (repo or proposal mutation) |
| Impact | Different content executed |
| Mitigation | Digest on proposal; base SHA ×2; push-phase parent check; workspace snapshot |
| Residual risk | LOW |
| Detection | Digest-mismatch and stale-state security events |
| Recovery | Execution denied |

### N. Sandbox escape

| | |
|---|---|
| Attack path | Malicious repo content exploits container runtime |
| Impact | Host compromise |
| Mitigation | No repo code execution by design (structured ops only — nothing to exploit); no network; non-root; seccomp; read-only rootfs; no socket; gVisor/Firecracker hardening path |
| Residual risk | LOW in V3.0 (no untrusted code runs); rises if lifecycle-script profile is ever enabled — gated separately |
| Detection | Runtime seccomp audit logs; anomalous syscall metrics |
| Recovery | Runner isolation limits blast radius; rebuild runner |

### O. Dependency confusion

| | |
|---|---|
| Attack path | Upgrade resolution pulls a higher-version package from a public registry over an internal one |
| Impact | Malicious dependency introduced |
| Mitigation | Registry allowlist + name-exact match; no new dependencies allowed (upgrade only); publish-age heuristics; lockfile diff review |
| Residual risk | LOW |
| Detection | Resolution anomalies audited |
| Recovery | Verification scan; deny |

### P. Malicious package lifecycle script

| | |
|---|---|
| Attack path | `postinstall` exfiltrates or corrupts during verification install |
| Impact | Secret/flag theft from sandbox |
| Mitigation | Scripts disabled by default (action policy §6); sandbox network-less so exfil impossible even if run; no secrets in sandbox |
| Residual risk | LOW |
| Detection | Script-run attempt detection (future profile) |
| Recovery | n/a — never executed |

### Q. Git hook abuse

| | |
|---|---|
| Attack path | Repo ships hooks that execute on git operations in workspace |
| Impact | Arbitrary code in sandbox |
| Mitigation | `core.hooksPath` neutralized; hooks ignored; argv-array git; no shell |
| Residual risk | LOW |
| Detection | Config drift logs |
| Recovery | n/a |

### R. SSRF

| | |
|---|---|
| Attack path | Crafted advisory/registry response redirects internal fetch; or log/Dockerfile URLs fed to fetchers |
| Impact | Internal service access |
| Mitigation | V2 scanners are offline (no URL fetching); V3 resolver egress allowlist + private-IP/metadata denial + redirect re-validation + response caps |
| Residual risk | LOW |
| Detection | Egress denials logged |
| Recovery | Deny |

### S. Secret exfiltration

| | |
|---|---|
| Attack path | Sandbox or repo content harvests credentials |
| Impact | Credential compromise |
| Mitigation | Credential isolation (security model §4): sandbox holds only a short-lived scoped installation token during push phase; no DB/Redis/LLM keys; network-less executor; secrets never logged |
| Residual risk | LOW — installation token theft window ≤10 min and repo-scoped |
| Detection | Token scope/age in audit; anomalous GitHub API usage |
| Recovery | Token expires; revoke installation |

### T. Resource exhaustion

| | |
|---|---|
| Attack path | Flood of proposals/executions/verifications |
| Impact | DoS of platform |
| Mitigation | Rate limits per user/repo; blast-radius caps; sandbox cgroup/pids/timeout/disk caps; V2's existing scan limits; queue concurrency caps |
| Residual risk | LOW |
| Detection | Rate-limit metrics; queue depth alerts |
| Recovery | Kill switch; janitor cleanup |

---

## 2. Adversarial Self-Review (section 57 questions)

| Question | Answer | Basis |
|---|---|---|
| Can prompt injection cause an action? | No action without schema→policy→approval→token→digest chain; injection can at most shape a proposal a human approves within a ≤10-file scope | Hierarchy, policy rows 5–7 |
| Can an approved action be modified? | No — digest binding recomputed twice by executor | Execution model §3 |
| Can a user approve another user's action? | No — ownership chain + approver role checks; cross-tenant 404 | Security model §6 |
| Can the executor escape the workspace? | Path resolver + realpath containment + re-open-time checks; no repo code runs | Action policy §4 |
| Can it access secrets? | Only a per-execution, ≤10-min, repo-scoped installation token in the push phase; all other credentials absent from sandbox | Security model §4 |
| Can it reach internal services? | Executor is network-less; push phase egresses only to GitHub | Security model §7 |
| Can it modify files outside scope? | Closed-world structured ops + triple file checks + diff guarantee | Action policy §3, execution model §3 |
| Can it run arbitrary code? | No shell, no interpreter, structured ops only; scripts disabled | Action policy §2/§6 |
| Can it execute twice? | Unique partial index + advisory lock + idempotent claim | Execution model §6 |
| Can it operate after approval expires? | Expiry checked at authorization and pre-execution | Invariant 13 |
| Can it execute after repository state changes? | base SHA ×2 + push parent verification | Execution model §4 |
| Can verification be bypassed? | State machine cannot reach SUCCEEDED without verification rows; comparison performed outside sandbox | Execution model §7 |
| Can rollback make things worse? | Snapshot-restore + exact-diff revert only; no arbitrary commands | Execution model §8 |
| Can an attacker forge audit events? | Append-only + hash chain; application writes via single audited service | Security model §12 |
| Can a compromised worker execute an unauthorized action? | In-process gates are bypassable by a fully compromised worker — **yes, this is the accepted residual risk**; compensations: no standing credentials, DB/audit constraints, GitHub branch protection, chain-integrity alerts, host hardening on roadmap | Threat G |

The last row is the one honest "yes". Redesign option if unacceptable: move authorization into an external, minimal authorizer service that signs per-action push credentials, so even a compromised worker cannot mint them. Recommended for V3.4+ (see roadmap).

---

## 3. Verdict

With the compensating controls in Threat G and the mandatory regression tests (golden paths 3–5), the design meets its stated invariants. **APPROVED FOR V3 IMPLEMENTATION** contingent on: (1) Threat-G compensations implemented as specified, (2) golden-path regressions shipping with their phases, (3) the authorizer-service hardening scheduled no later than V3.4.
