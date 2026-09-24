# V3.8 — Immutable Audit & Security Event Integrity

**Status:** normative for V3.8 · **Baseline:** 7bd075c · **Migration:** 011

## 1. What V3.8 provides — and what it does not

CYVRIX V3.8 makes the security history of the remediation lifecycle
(proposal → approval → authorization → execution → verification →
rollback → operational control → reconciliation) **tamper-evident**:
if stored history is modified, deleted, inserted, reordered, or
truncated, that alteration is detectable by an independent verifier.

Precision about trust boundaries (non-negotiable):

- V3.8 provides **TAMPER-EVIDENCE**, not physical immutability. Every
  row lives in PostgreSQL and a database superuser can overwrite rows.
- A database row with an application-computed hash is *detectable
  alteration*, not *impossible* alteration.
- The phrase "immutable audit" in the roadmap refers to the *intent*
  (append-only through every application path) — the precise property
  delivered is tamper-evidence, everywhere in this document and in code.

## 2. Chain model (Phase 6)

- One hash chain per tenant: `audit_chains` is 1:1 with
  `github_installations` (the tenant boundary used since V1).
- `chain_id` = `audit_chains.id` (UUID); every event binds to it and
  the chain id is INSIDE every digest.
- No global lock exists: concurrency serializes on a per-chain
  row-level lock (`SELECT … FOR UPDATE` on the chain row) taken before
  the head is read. Cross-tenant appends never contend.

## 3. Event model (Phase 2/14/35/36)

Trusted envelope fields (server-derived, canonical, hashed):

```
schema_version, event_type, event_version, actor_type, actor_id,
actor_user_id, repository_id, action_id, authorization_id,
execution_run_id, verification_id, rollback_id, reason_code, result,
payload, occurred_at, recorded_at, seq
```

- **Event identity** (seq, digest, predecessor) is server-derived. No
  request field can influence it; the audit API accepts none.
- **Actor identity** is server-derived from the authenticated session
  or service identity — never from client payload. Actor types are the
  closed set USER | ADMIN | WORKER | EXECUTOR | SYSTEM | RECONCILER |
  GITHUB_INTEGRATION.
- **Outcomes** (`result`: OK/DENIED/ISSUED/SUCCESS/…) come only from
  trusted server-side state transitions; client input can never define
  SUCCESS/APPROVED/etc.
- **Reason codes** are the authoritative "why" (e.g. POLICY_DENIED,
  KILL_SWITCH_ACTIVE); free text is untrusted metadata only.
- **Correlation ids** (action/authorization/execution/verification/
  rollback) make every event traceable across the whole lifecycle.
- `payload` is evidence: redacted (below) and never allowed to alter
  canonical security fields.

## 4. Canonicalization (Phase 3)

One serializer: `audit_service.canonical_json`

- JSON with `sort_keys=True`, separators `(",", ":")`,
  `ensure_ascii=False`, `allow_nan=False`
- floats pre-converted to `repr` strings by `redact_payload` (no
  binary-float ambiguity ever reaches the hash)
- timestamps as UTC ISO-8601 microseconds (`canonical_timestamp`);
  naive datetimes are interpreted as UTC; `None` → `""` (deterministic
  and verifier-detectable, never a crash)
- UTF-8 encoding fixed at the hash boundary
- hashing of Python `repr`, dict insertion order, locale formats:
  impossible by construction

## 5. Digest construction (Phase 4/5)

```
event_digest = SHA-256(
    b"cyvrix-audit-v1"      || 0x1f ||
    chain_id (16 bytes)     || 0x1f ||
    prev_digest (64 ASCII)  || 0x1f ||
    UTF-8(canonical_json(trusted_payload))
)
```

- **Genesis** (`seq = 1`): `prev_digest = GENESIS_PREV_DIGEST = "0"×64`
  — deterministic and recognizable; NULL is never used.
- The predecessor link is inside the hash: an event whose predecessor
  is wrong cannot validate independently.
- `chain_id` is inside the hash: events cannot be transplanted across
  chains.
- Changing the field set or serialization is an `event_version` /
  `schema_version` bump; v1 semantics are frozen.

## 6. Sequencing and concurrency (Phase 8/9/57)

- `(chain_id, seq)` is the ordering authority. Timestamps are metadata.
- The per-chain lock (`SELECT … FOR UPDATE`) is acquired before the
  head is read; the head is re-read after the lock.
- Backstop: UNIQUE `(chain_id, seq)`, UNIQUE `(chain_id, prev_digest)`,
  UNIQUE `event_digest`, UNIQUE `audit_chains.installation_id`.
- A lost race (UNIQUE violation) is retried ≤3 times and then fails
  closed — a duplicate-sequence event is never committed.
- Proven on real PostgreSQL: 6 concurrent writers × 3 events × 10 reps
  → 0 duplicates, 0 forks, chain VALID every time
  (`tests/test_audit_chain_races.py`).

## 7. Append-only enforcement (Phase 12/13/33)

Layers, in order:

1. **Application**: no code path issues UPDATE/DELETE on
   `audit_chain_events`/`audit_checkpoints`; the audit API is
   read-only (GET) — POST/PUT/PATCH/DELETE do not exist (404/405).
2. **Database trigger** (migration 011): `cyvrix_audit_append_only()`
   rejects UPDATE/DELETE on both audit tables **for any role, including
   the application role and table owner**. Proven: even
   `UPDATE … WHERE false` is rejected. Disabling the trigger requires
   superuser `ALTER TABLE … DISABLE TRIGGER` — a superuser can also
   drop it, which is why V3.8 claims tamper-EVIDENCE, not physical
   immutability (§1).
3. **Capability surface**: VIEW_AUDIT / VERIFY_AUDIT / EXPORT_AUDIT are
   ADMIN-only. There is deliberately NO EDIT_AUDIT or DELETE_AUDIT
   capability anywhere in the role matrix.

**Role separation status:** the application role currently runs DDL via
Alembic and therefore retains broad privileges. Recommended production
hardening (documented, not enforced yet): a dedicated `cyvrix_app`
role with INSERT/SELECT on audit tables only, trigger ownership moved
to a separate security role, and the verifier credential SELECT-only.

## 8. Secret redaction (Phase 15/38)

`redact_payload` runs centrally **before** canonicalization — producers
cannot forget it:

- any key matching the secret pattern (token/secret/password/
  private_key/authorization/cookie/credential/api_key/session/bearer)
  → `[REDACTED]`, regardless of value
- token-shaped strings (`ghp_`, `gho_`, `ghs_`, `ghu_`, `ghr_`,
  `github_pat_` prefixes) are redacted even under unflagged keys
- depth-bounded (6), list-bounded (20), string-bounded (2000 chars)
- hashing a secret is NOT redaction: nothing secret ever enters the
  hash input

Verified: secrets planted in payloads are stored as `[REDACTED]` and
the stored digest matches recomputation over the redacted payload.

## 9. Criticality classes and transaction semantics (Phase 10/11/31/56)

| Class | Behavior | Examples |
|---|---|---|
| SECURITY_CRITICAL | appended in the SAME transaction as the state change; if the transaction rolls back the event never existed | approvals, authorizations, execution start/complete/fail, push success/fail, verification, rollback, emergency stop, resume, breaker reset, credential issued/denied |
| OPERATIONAL | best-effort mirror; failure logged loudly, never masks the decision | JOB_RECONCILED, LEASE_EXPIRED, RATE_LIMITED, QUOTA_EXCEEDED |
| DIAGNOSTIC | may be dropped | diagnostics feeds |

- The legacy `audit_events` row remains the pre-V3.8 record of truth;
  the chain append rides the caller's transaction (no extra commit
  semantics change).
- Unknown event types are **rejected** (`AuditEventError`) — the
  registry is closed-world (§10).
- A chain write failure on a SECURITY-CRITICAL event raises into the
  caller's transaction: no security transition ever commits while its
  witness silently vanished. Proven by
  `test_audit_write_failure_does_not_false_succeed` (failure injection)
  and `test_rollback_removes_audit_event_no_false_security_state`.

## 10. Event type registry (Phase 17/18)

`EVENT_CRITICALITY` in `audit_service.py` is the closed world: ~45
types spanning ACTION_*, APPROVAL_*, AUTHORIZATION_*, EXECUTION_*,
GIT/GITHUB_*, VERIFICATION_*, ROLLBACK_*, operational control events,
and credential events. Unknown types are rejected. Legacy V1–V3.6
names map explicitly through `LEGACY_EVENT_TYPE_MAP` (each target is
asserted registered by unit test) — no silent renaming.

## 11. Verifier (Phase 19/20)

`audit_service.verify_chain_rows` (pure) / `verify_chain` (DB) return a
**structured** verdict, never a boolean blob:

- `VALID` — every link, digest, and sequence checks out
- `INVALID` — with machine-readable issues:
  `DIGEST_MISMATCH`, `PREDECESSOR_BREAK`, `SEQ_GAP`,
  `SEQ_DUPLICATE_OR_REORDER`, `TRUNCATED_TAIL`,
  `CHECKPOINT_MAC_MISMATCH`, `CHECKPOINT_HEAD_MISMATCH`
- `EMPTY` — no events (distinct from invalid)
- `UNSUPPORTED_VERSION` — event written by a newer schema version

Detects: payload tampering, actor swap, tenant/action/authorization id
tampering, outcome forging, timestamp tampering, digest field
tampering, predecessor forking, middle-event deletion, sequence
reordering, duplication, replay-with-fresh-seq, and insertion.

## 12. Truncation detection and checkpoints (Phase 21/22/24)

A plain singly-linked hash chain CANNOT detect tail truncation — the
remaining prefix is internally consistent. V3.8 therefore ships:

- **`audit_checkpoints`**: `chain_id, through_sequence, head_digest,
  event_count, payload_digest, mac, mac_key_version` — an advisory
  tail checkpoint per event when `audit_checkpoint_key` is configured.
- The MAC is **HMAC-SHA-256** under a key held in configuration,
  OUTSIDE the database (`audit_checkpoint_key`; empty disables
  checkpointing, and the limitation is then explicit).
- A MAC-valid checkpoint is an independent claim that the chain once
  reached `(through_sequence, head_digest)`. If the verifier is shown
  a chain whose head is before such a checkpoint → `TRUNCATED_TAIL`.
  If checkpoint rows themselves are rewritten → `CHECKPOINT_MAC_MISMATCH`
  (an attacker with DB write access cannot forge the MAC).
- **Key lifecycle:** the key never lives in the database; versioning
  field (`mac_key_version`) supports rotation; verification requires
  only the key material, exportable offline.

**Residual trust (say it plainly):** an attacker who compromises BOTH
the database AND the checkpoint key configuration can rewrite history
undetectably by a verifier that trusts that key. Closing this fully
requires an external anchor (offline export, WORM storage, or a second
verification key held separately). V3.8 ships the export path (§13)
to make offline anchoring operational; production deployment should
schedule it. This is the documented TAMPER EVIDENCE LEVEL.

## 13. Export and independent verification (Phase 27/28/50)

`GET /api/audit/chains/{id}/export` streams canonical NDJSON:
header line (format version, chain id, genesis constant, digest
domain), one line per event (full canonical envelope + digests), then
checkpoint lines. Export is deterministic — the same chain exports
byte-identically.

`verify_export_ndjson(text, checkpoint_key=…)` verifies the artifact
with **no database**: canonicalization, digests, predecessor links,
sequence, chain identity, and checkpoint MACs. Certified end-to-end by
`tests/cert_v38_audit.py` (7/7): export → offline VALID → tamper
(payload/actor/removal/reorder) → detected.

## 14. Audit API and admin surface (Phase 26/45)

All under `/api/audit`, all GET, all capability-gated and rate-limited:

| Route | Capability | Purpose |
|---|---|---|
| `/chains` | VIEW_AUDIT | list tenant chains |
| `/chains/{id}/events` | VIEW_AUDIT | bounded pagination (≤1000) |
| `/chains/{id}/verify` | VERIFY_AUDIT | structured integrity verdict |
| `/chains/{id}/checkpoints` | VIEW_AUDIT | checkpoint listing |
| `/chains/{id}/export` | EXPORT_AUDIT | NDJSON export |
| `/integrity/status` | VERIFY_AUDIT | per-chain counts/head coverage |

No endpoint accepts event_digest/sequence/previous as authority
(inputs are filters only); mutation verbs do not exist; malformed ids
normalize to 404 (never 500). Cross-tenant access is 404 — existence
never leaks. There is no EDIT/DELETE capability anywhere.

Frontend: intentionally none in V3.8 (V3.5–V3.7 precedent: API-first).
A future audit-timeline UI must display server verification results
only — the browser never computes trust.

## 15. Performance and growth (Phase 39/41/42)

- Indexes: `(chain_id, seq)` unique btree, `event_digest` unique,
  `event_type`, `repository_id`, `recorded_at`.
- Appends: one indexed SELECT + one row lock + one INSERT + optional
  checkpoint INSERT per event; per-chain serialization only.
- Events listing is paginated (limit ≤ 1000); export streams line-wise.
- Safe metrics names are reserved
  (`audit_events_total`, `audit_chain_verification_failures`,
  `audit_write_failures`, `audit_checkpoint_created`,
  `audit_integrity_alert`, `audit_export_total`, `audit_export_failure`)
  — contents never exposed through metrics.
- Retention (Phase 40): no deletion API exists. Any future archival
  must be EXPORTED → CHECKPOINTED → ARCHIVED with the export retained
  for independent verification; silent chain destruction is impossible
  through the product.

## 16. Security alerts (Phase 43)

Chain verification failures, checkpoint MAC mismatches, registry
misses, and mirror failures log structured events
(`audit_chain_*`) for alerting. Alert storms are bounded by the same
rate-limiting machinery as the ops surface; alerts carry no event
contents.

## 17. Proven properties (Phase 54) — where each is tested

| # | Invariant | Proof |
|---|---|---|
| 1–2 | append-only APIs; no edit/delete path | `test_no_mutation_api_exists`, trigger test |
| 3 | tenant isolation on audit | `test_cross_tenant_chain_404` |
| 4–8 | server-derived identity/sequence/predecessor | `TestNoClientAuthority`, digest tests |
| 9–10 | deterministic canonicalization/digest | `TestCanonicalization`, `TestDigest` |
| 11–16 | tamper/insert/delete/reorder detection | `TestVerifier`, red-team races |
| 17 | tail truncation detection | `test_tail_truncation_requires_checkpoint` |
| 18–19 | atomic critical events; no false state | rollback + failure-injection tests |
| 20 | secrets never enter chain | `test_secret_in_payload_never_stored`, `TestRedaction` |
| 21 | client cannot forge outcome | `test_query_params_cannot_influence_identity` |
| 22 | worker cannot forge actor | closed actor registry + server derivation |
| 23 | admin cannot edit history | no capability + DB trigger |
| 24 | export independently verifiable | `cert_v38_audit.py` |
| 25 | V3.1–V3.7 unchanged | full regression 1101 passed |
| 26 | integrity failure signals | `audit_chain_*` structured logs |

## 18. Migration (Phase 46/58)

`011_v38_audit_integrity.py` (revises 010) is additive: three tables,
unique constraints, indexes, and the append-only triggers. Verified
in-place on real PostgreSQL (`010 → 011`); fresh deployments reach 011
through the normal chain 001→…→011. Downgrade drops only V3.8 objects.
