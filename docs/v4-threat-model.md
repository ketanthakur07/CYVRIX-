# CYVRIX V4 — Threat Model Extension (Red Team)

Status: IMPLEMENTED (this document) — extends `v3-threat-model.md`
Method: STRIDE-flavored adversary enumeration against the V4 design in
`v4-architecture.md` / `v4-multitenancy.md` / `v4-rbac.md` / `v4-api.md` /
`v4-security.md`. Residual risk ratings assume the listed mitigations are
implemented **and tested**. V4 threats are additive: the V3 matrix remains in
force unchanged for everything inside the chain.

---

## 1. Threat Matrix (V4-specific)

### A. Cross-tenant access via client-supplied organization

| | |
|---|---|
| Attack path | Caller sends an `organization_id` for a tenant they are not a member of (in a body, or as a path segment for another org) and expects the server to trust it |
| Impact | Read or modify another organization's repositories, findings, actions, members |
| Mitigation | The organization is a **selector**, resolved against the caller's membership in one query (`org_auth._load_membership`); non-member → `404 ORGANIZATION_NOT_FOUND`; capability checked only after membership; `/api/v1` derives the org from the key; client request builders are tested to never send `organization_id` at all |
| Residual risk | LOW — no route reads an organization from a body; the residual is a future route introducing one, which is what the tenancy-invariant test exists to catch |
| Detection | `404`/`403` rate spikes; per-org request volume anomalies |
| Recovery | No data changed on refusal; access already confined by membership |

### B. Privilege escalation through membership change

| | |
|---|---|
| Attack path | A non-admin attempts to change roles; an admin attempts to self-promote to owner; a member attempts to remove the last owner and then be re-invited as owner |
| Impact | Unauthorized administrative control |
| Mitigation | `MANAGE_MEMBERS` required for any change; granting **or** revoking `ORG_OWNER` requires the actor to already be an owner; `LAST_OWNER_PROTECTED` prevents demotion/removal/suspension of the last ACTIVE owner; the rule is enforced transactionally so two concurrent changes cannot both observe `active_owner_count == 2` |
| Residual risk | LOW |
| Detection | Membership-change audit events; `LAST_OWNER_PROTECTED` / `OWNER_CHANGE_REQUIRES_OWNER` reason codes |
| Recovery | Change refused; no state change |

### C. Invitation token theft, replay or redirect

| | |
|---|---|
| Attack path | Attacker obtains an invitation link and joins an organization they were not invited to (replay), or repurposes the token for a different tenant (redirect) |
| Impact | Unauthorized membership |
| Mitigation | Hash-only at rest; single use (`accepted_at`, second acceptance → `INVITATION_ALREADY_ACCEPTED`); 72-hour expiry; bound to one organization; optional email binding compared against the accepting user; revocable (`revoked_at` terminal); **explicit accept click**, so a prefetched or shared link cannot silently join anyone; default role `VIEWER` |
| Residual risk | MEDIUM — a link forwarded to the wrong person before acceptance is a valid grant, bounded by the email binding when one was supplied and by the invitation's expiry and role |
| Detection | Acceptance audit events; invitations accepted by unexpected emails |
| Recovery | Revoke the invitation; remove the membership; audit the granted role |

### D. API key leakage

| | |
|---|---|
| Attack path | A key exfiltrated from CI logs, a repo, or a shell history is used against `/api/v1` |
| Impact | Read of that organization's repositories, findings and actions |
| Mitigation | Only a SHA-256 hash is stored (a DB read yields nothing usable); the secret is shown once; expiry supported and checked on every authentication; immediate revocation; bearer-key lookups leak no distinction between invalid/revoked/expired (`401 API_KEY_INVALID` for all) |
| Residual risk | MEDIUM — an unexpired key that is not revoked remains valid; this is inherent to bearer credentials. Bounded by read-only scope, per-org rate limits, and `last_used_at` visibility |
| Detection | Unexpected `last_used_at`; `401` spikes |
| Recovery | Revoke the key; issue a replacement |

### E. API-key scope escalation

| | |
|---|---|
| Attack path | Issue a key whose scopes exceed what the caller's role permits, especially `actions:create` or `audit:export` |
| Impact | A machine credential performing high-impact actions |
| Mitigation | Scopes are a closed world validated at issuance (`INVALID_API_KEY_SCOPES`); **high-impact scopes require at least `ORG_ADMIN` standing** (`HIGH_IMPACT_SCOPE_REQUIRES_ADMIN`), enforced server-side; no scope can manage members/policy/operations or transfer/delete an organization; the console warns before issue |
| Residual risk | LOW |
| Detection | Key-creation audit events with high-impact scopes |
| Recovery | Revoke the key |

### F. Confused deputy — API key used for administration

| | |
|---|---|
| Attack path | A valid API key is presented to an administration route (`/api/orgs/...`) expecting the platform to accept the key as a session |
| Impact | Machine-driven administration of an organization |
| Mitigation | `/api/orgs` requires a session cookie and a capability; API keys authenticate only `/api/v1` (`api_key_auth` is used exclusively by `api_v1.py`); `/api/v1` deliberately does not re-export mutation routes |
| Residual risk | LOW |
| Detection | `401` on console routes with a bearer token |
| Recovery | — |

### G. Cross-tenant data leakage in the browser cache

| | |
|---|---|
| Attack path | Caller belongs to two organizations, switches tenant, and stale cached responses render organization A's data under organization B |
| Impact | Information disclosure to a member of both tenants (and misattribution of decisions) |
| Mitigation | `switchOrg` **removes every cached query except the caller's own organization list**; the selector is memory-only (no `localStorage`), so nothing tenant-related survives reload/logout; capability payloads are re-fetched per organization |
| Residual risk | LOW — a future query that is written to a tenant-independent cache root would reintroduce this; the invariant list in `lib/org.tsx` is the single place to audit |
| Detection | Client tests (`org-context.test.tsx`) assert the removal |
| Recovery | Reload; the server never used the wrong tenant, so no server-side effect |

### H. Suspended member retains access

| | |
|---|---|
| Attack path | A member is suspended but continues to act using a cached capability payload or an in-flight session |
| Impact | Actions by a membership that should be inert |
| Mitigation | Every request re-resolves the ACTIVE membership; `effective_capabilities` returns nothing for non-ACTIVE states; the client re-applies the same rule so no control renders; there is no capability cache server-side |
| Residual risk | LOW |
| Detection | `403 ORG_CAPABILITY_REQUIRED` from a suspended actor |
| Recovery | — |

### I. Organization enumeration (IDOR)

| | |
|---|---|
| Attack path | Probe organization ids to discover which exist, then target them |
| Impact | Tenant discovery; assists further attack |
| Mitigation | Uniform `404 ORGANIZATION_NOT_FOUND` for non-member / missing / DELETED; no response distinguishes the cases; administration routes are organization-rate-limited |
| Residual risk | LOW — organization ids are UUIDv4, and existence is never confirmed |
| Detection | `404` bursts per session |
| Recovery | — |

### J. Backfill pollution (wrong tenant on migration)

| | |
|---|---|
| Attack path | Migration binds a legacy installation to the wrong organization, silently moving history to another tenant |
| Impact | Cross-tenant exposure of existing repositories and audit chains |
| Mitigation | Backfill keys strictly on `o.created_by = gi.user_id` with `is_personal = true`; one personal org per user (slug derived from the user uuid); `github_installations.organization_id` set only `WHERE ... IS NULL`; the V3 ownership predicate stays honoured, so the backfill can only *add* a binding, never remove one |
| Residual risk | LOW |
| Detection | Real-PG certification asserts each installation's organization `created_by` equals its `user_id` |
| Recovery | Re-run backfill after correcting; no destructive DDL is involved |

### K. Policy history rewrite

| | |
|---|---|
| Attack path | An admin changes policy and the platform rewrites history, so a past decision can no longer be explained against the policy that produced it |
| Impact | Loss of accountability; an approval appears to have been made under a stricter policy than it was |
| Mitigation | Policy is validated against a closed world (unknown keys refused as `INVALID_POLICY`); writes increment `policy_version` and append an immutable `organization_policy_revisions` row with `UNIQUE(organization_id, version)`; superseding never rewrites prior rows |
| Residual risk | LOW |
| Detection | Version monotonicity checks; audit cross-reference |
| Recovery | Prior revisions are retained |

### L. Rate-limit bypass / fail-open

| | |
|---|---|
| Attack path | Make Redis unavailable (or exhaust a shared bucket) so the limiter degrades to "allow" and flood the organization |
| Impact | DoS; or cross-tenant budget theft |
| Mitigation | `check_rate_limit` **fails closed** — Redis unavailable returns `(False, 0)` → `429 ORG_RATE_LIMITED`; buckets are namespaced per organization, so one tenant cannot exhaust another's budget |
| Residual risk | LOW — fail-closed means a Redis outage degrades availability rather than control, which is the intended trade |
| Detection | Rate-limit warnings; `429` volume; per-bucket metrics |
| Recovery | Restore Redis; windows expire naturally |

### M. Organization deletion leaves a usable tenant

| | |
|---|---|
| Attack path | After a deletion request, a former member continues to use the organization because their membership row still says ACTIVE |
| Impact | Continued access to a tenant that should be gone |
| Mitigation | `state == "DELETED"` is treated as not-found even for ACTIVE members; administrator routes resolve state in the same query as the membership; the client also refuses to select a non-ACTIVE membership |
| Residual risk | LOW |
| Detection | `404` from former members |
| Recovery | — |

### N. Secret material in logs or telemetry

| | |
|---|---|
| Attack path | An invitation token or API key is logged, surfacing in log aggregation |
| Impact | Credential disclosure |
| Mitigation | Secrets are generated, hashed and returned without logging; `api_keys.prefix` is the only key-derived value intended for logs; client source scan forbids browser storage of credentials and bearer-header construction |
| Residual risk | LOW |
| Detection | Log review; uniqueness constraints surface accidental reuse |
| Recovery | Revoke the affected token or key |

### O. Capability used as a shortcut past the V3 chain

| | |
|---|---|
| Attack path | Treat an organization capability as sufficient authorization to execute, e.g. an admin assuming `MANAGE_OPERATIONS` subsumes approval and authorization |
| Impact | Execution without the V3 gates |
| Mitigation | Capabilities only permit *invoking* a gate: `START_REMEDIATION` still requires a consumed execution authorization; approval/authorization routes keep their digest binding, policy evaluation, kill switch, expiry and ownership checks; no capability is defined that skips a chain step, and no `/api/orgs` route can execute anything |
| Residual risk | LOW |
| Detection | The V3 gated regression suites run unchanged against the V4 tree |
| Recovery | — |

---

## 2. Adversarial Self-Review

| Question | Answer | Basis |
|---|---|---|
| Can a member of org A read org B's findings? | No — the org is a selector verified against membership; a non-member gets `404`; `/api/v1` derives the org from the key; client builders never send `organization_id` | Threat A; `api-v4.test.ts` |
| Can a client make itself an owner? | No — role comes from the membership row; only an owner may grant `ORG_OWNER`; the client has no field that selects a role | Threat B |
| Can the last owner be removed, locking or seizing the org? | No — `LAST_OWNER_PROTECTED`, enforced transactionally under concurrency | Threat B; `test_v4_races.py` |
| Can a suspended member still act? | No — non-ACTIVE states yield zero capabilities, re-resolved every request | Threat H |
| Can an invited-but-not-accepted user act? | No — `INVITED` is not an authorizing state | Threat C |
| Can an invitation be replayed or reused for another org? | No — single-use, hashed, expiring, org-bound, optionally email-bound, revocable | Threat C |
| Can a leaked API key administer the organization? | No — keys authenticate `/api/v1` only, and no scope can administer | Threats D, F |
| Can a key read another tenant? | No — organization is derived from the key and every query is scoped through the installation join | Threat A |
| Can an owner bypass the V3 chain with admin capability? | No — capabilities invoke gates, they never remove them; no V4 route can execute | Threat O |
| Can a stale browser cache leak another tenant's data? | No — tenant cache is dropped on switch and the selector is memory-only | Threat G |
| Can an attacker enumerate organizations? | No — uniform `404`, UUIDv4 ids, rate-limited admin routes | Threat I |
| Can a DB read yield a usable credential? | No — only SHA-256 hashes of invitations and keys are stored | Threats C, D |
| Can the limiter be made to fail open? | No — Redis failure denies with `429` | Threat L |
| Can a policy change rewrite history? | No — append-only revisions with a unique `(org, version)` | Threat K |
| Can a deleted organization stay usable? | No — `DELETED` is not-found for everyone, including ACTIVE members | Threat M |
| Can the migration move history to the wrong tenant? | No — backfill keys on `created_by = user_id` and only fills `NULL` | Threat J |

---

## 3. Residual Risk Summary

| Threat | Residual |
|---|---|
| A Cross-tenant access | LOW |
| B Membership escalation | LOW |
| C Invitation theft | **MEDIUM** |
| D API key leakage | **MEDIUM** |
| E Scope escalation | LOW |
| F Confused deputy | LOW |
| G Client cache leakage | LOW |
| H Suspended member | LOW |
| I Enumeration | LOW |
| J Backfill pollution | LOW |
| K Policy rewrite | LOW |
| L Rate-limit fail-open | LOW |
| M Deleted tenant | LOW |
| N Secret logging | LOW |
| O Chain shortcut | LOW |

The two MEDIUM entries are inherent to link- and bearer-based grants and are
bounded rather than eliminated: an invitation is single-use, expiring,
org-bound, optionally email-bound and defaults to `VIEWER`; an API key is
read-oriented, expiring, revocable and limited to one organization. Neither
can administer an organization, and neither can shorten the V3 chain.

---

## 4. Verdict

V4 adds a tenant layer and a public read API **around** the V3 chain without
weakening any V3 control. Every V4 decision point is fail-closed, tenant
selection is always server-derived, and the migration backfills tenancy
rather than assuming it. The two MEDIUM residuals are the accepted cost of
link- and bearer-based grants, and both are constrained to read-only or
expiring authority within a single organization.

**APPROVED FOR V4 RELEASE** contingent on the regression evidence in
`v4-architecture.md` §10 (V4 platform + race suites, org rate-limit isolation
on real Redis, real-PG migration certification, real-container sandbox
isolation, and the V3 gated suites remaining green).
