# CYVRIX V1 — Threat Model

## Scope

This document identifies threats against the CYVRIX V1 system, their attack paths, existing mitigations, and residual risks.

---

### 1. Authentication Compromise

**Threat:** Attacker gains access to a legitimate user's session.

| Attack Path | Mitigation | Residual Risk |
|-------------|------------|---------------|
| Session cookie theft (XSS) | httpOnly cookies, React escaping, no dangerouslySetInnerHTML | Low — residual XSS risk if new component bypasses React |
| Session cookie theft (network) | SameSite=Lax, Secure in production | Low — requires MITM on HTTPS |
| Brute-force session ID | 64-char hex token (256 bits of entropy) | Negligible — computationally infeasible |
| Session fixation | New session created on login | Low — old session not explicitly invalidated on password change (no password auth in V1) |

---

### 2. Authorization Bypass (IDOR)

**Threat:** User A accesses User B's repositories, scans, or findings.

| Attack Path | Mitigation | Residual Risk |
|-------------|------------|---------------|
| Direct UUID access | Ownership chain verified at query level | Low — JOIN through installation table |
| API endpoint without auth check | `get_current_user` dependency on all protected routes | Low — dependency injection ensures consistent enforcement |
| Indirect access via nested resources | `get_user_repository` verifies full chain | Low — repository → installation → user verified |

---

### 3. CSRF Attacks

**Threat:** Attacker tricks authenticated user into performing unintended actions.

| Attack Path | Mitigation | Residual Risk |
|-------------|------------|---------------|
| Cross-origin form submission | SameSite=Lax blocks cross-origin cookies | Low — Lax allows GET redirects but blocks POST/PUT/DELETE |
| OAuth flow CSRF | State parameter stored in Redis with TTL | Low — state is cryptographically random |

---

### 4. XSS Attacks

**Threat:** Attacker injects malicious scripts into the dashboard.

| Attack Path | Mitigation | Residual Risk |
|-------------|------------|---------------|
| Stored XSS via finding title | React default escaping | Low — all dynamic content rendered via JSX |
| DOM-based XSS | No dangerouslySetInnerHTML in codebase | Low — verified by XSS test suite |
| Reflected XSS | React escaping handles all rendering | Low |

---

### 5. Repository Connection

**Threat:** Attacker manipulates GitHub integration to access unauthorized repositories.

| Attack Path | Mitigation | Residual Risk |
|-------------|------------|---------------|
| Stale installation tokens | Tokens generated on-demand, 1hr TTL, never persisted | Low |
| OAuth token leakage | Token used server-side only, never returned to browser | Low |
| Revoked GitHub access | Next API call fails → session rejected | Low — user sees "Session expired" |
| Duplicate installation | `installation_id` UNIQUE constraint → upsert | Negligible |

---

### 6. Repository Clone

**Threat:** Malicious repository causes harm during scanning.

| Attack Path | Mitigation | Residual Risk |
|-------------|------------|---------------|
| Symlink escape | `_is_symlink_safe` checks target stays in workspace | Low |
| Path traversal | `_validate_path_in_workspace` checks resolved paths | Low |
| Submodule bomb | `--depth 1 --recurse-submodules=no` | Low |
| Huge repository | 500MB max repo size | Low — timeout as backstop |
| Credential exposure in clone URL | URL sanitized before logging | Low |
| Workspace persistence | `tempfile.mkdtemp` + `finally` block cleanup | Low |

---

### 7. Dependency Manifest Attacks

**Threat:** Malicious manifest files compromise the scanner.

| Attack Path | Mitigation | Residual Risk |
|-------------|------------|---------------|
| Path traversal in manifest path | Workspace boundary validation | Low |
| Symlink manifest | Symlinks rejected during detection | Low |
| Huge manifest | 10MB file size limit, 50K line limit | Low |
| Too many manifests | 50 manifest limit | Low |
| Too many dependencies | 10,000 dependency limit | Low |
| Malformed JSON | Per-file exception handling, skip and continue | Low |

---

### 8. OSV API Attacks

**Threat:** Malicious or compromised OSV responses compromise findings.

| Attack Path | Mitigation | Residual Risk |
|-------------|------------|---------------|
| Malformed response | Response structure validation before processing | Low |
| Malformed vulnerability entry | Individual vuln validation | Low |
| Rate limiting (429) | Exponential backoff with retry | Low |
| Server error (5xx) | Retry with backoff, then fail scan | Low |
| Missing entries | Treated as "no known vulnerability" | Low — logged for observability |

---

### 9. AI Prompt Injection

**Threat:** Malicious repository content manipulates the LLM investigation.

| Attack Path | Mitigation | Residual Risk |
|-------------|------------|---------------|
| "Ignore previous instructions" in source code | System prompt states untrusted content rule; content wrapped in `<UNTRUSTED>` tags | Medium — defense-in-depth, not foolproof |
| Model instructed to execute commands | Model has no tools (no shell, filesystem, network) | Low — eliminated by design |
| Model instructed to modify database | Model output is Pydantic-validated; cannot issue DB commands | Low — eliminated by design |
| Model instructed to access other repos | Evidence gathered by worker code, not model | Low — eliminated by design |
| Model returns malicious recommendation | Recommendation is informational only; risk engine is independent | Low — AI does not determine risk score |

---

### 10. AI Output Manipulation

**Threat:** LLM returns invalid or manipulated investigation results.

| Attack Path | Mitigation | Residual Risk |
|-------------|------------|---------------|
| Non-JSON response | Code fence stripping + JSON parse + regex extraction | Low |
| Invalid schema | Pydantic validation rejects and retries once | Low |
| Fabricated evidence | Cross-validation against supplied file list | Low |
| Fabricated line numbers | Line number range validation | Low |
| Extreme confidence manipulation | Confidence clamped to [0, 1] | Low |

---

### 11. Database Attacks

**Threat:** SQL injection or data corruption.

| Attack Path | Mitigation | Residual Risk |
|-------------|------------|---------------|
| SQL injection | SQLAlchemy ORM with parameterized queries | Negligible |
| Unauthorized data access | Ownership chain enforced at query level | Low |
| Data corruption | Foreign key constraints, unique constraints | Low |
| Migration safety | No shell, no network, no credentials in migrations | Low |

---

### 12. Redis Attacks

**Threat:** Session hijacking or data corruption via Redis.

| Attack Path | Mitigation | Residual Risk |
|-------------|------------|---------------|
| Session tampering | HMAC-SHA256 signature on session ID | Negligible |
| Redis injection | Session keys use fixed prefix + session ID | Low |
| Redis downtime | Fail-closed: no Redis = no sessions = 401 | Acceptable |
| Session fixation | New session on login | Low |

---

### 13. Worker / Queue Attacks

**Threat:** Malicious or malformed scan jobs compromise the worker.

| Attack Path | Mitigation | Residual Risk |
|-------------|------------|---------------|
| Malformed job payload | Scan ID validated against DB | Low |
| Infinite scan | 10-minute timeout per scan | Low |
| Resource exhaustion | Temp workspace with cleanup, dependency limits | Low |
| Worker crash | Worker is separate process; API unaffected | Low |
| Job retry storms | Idempotent execution, fingerprint dedup | Low |

---

### 14. Frontend Attacks

**Threat:** Attacks against the Next.js frontend.

| Attack Path | Mitigation | Residual Risk |
|-------------|------------|---------------|
| XSS via dynamic content | React default escaping | Low |
| Secret leakage in bundle | No secrets in frontend code | Negligible |
| Open redirect | Redirects only to configured `app_url` | Low |
| Insecure error display | API errors show safe messages only | Low |

---

### 15. Cross-User Data Access

**Threat:** User A sees User B's data.

| Attack Path | Mitigation | Residual Risk |
|-------------|------------|---------------|
| Direct resource access | Ownership chain verification | Low |
| API without auth | `get_current_user` dependency | Low |
| Dashboard data leakage | All queries filtered by ownership | Low |
| E2E test verification | IDOR test suite confirms isolation | Verified |

---

## Residual Risk Summary

| Risk Level | Count | Description |
|------------|-------|-------------|
| Medium | 1 | Prompt injection defense relies on system prompt + untrusted labeling (defense-in-depth, not cryptographically enforced) |
| Low | ~18 | Various defense-in-depth gaps documented above |
| Negligible | 3 | SQL injection (ORM), session ID entropy, secret leakage |

## Risk Acceptance

The single MEDIUM risk (prompt injection) is accepted for V1 because:
1. The model has no tools — even if injection succeeds, no harmful action is possible
2. Evidence cross-validation catches fabricated output
3. Risk scoring is independent of AI output
4. The system is designed to fail gracefully (AI failure ≠ scan failure)
