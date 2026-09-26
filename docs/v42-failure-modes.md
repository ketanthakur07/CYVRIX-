# CYVRIX V4.2 — Failure-Mode Map and Recovery

Component → dependency → state → failure mode → recovery, per Phase 0/36.
Every row ends in a TERMINAL verdict class: RECOVERED (automatic), SAFE
FAILURE (honest refusal, caller may retry), or OPERATOR REQUIRED. No row
is permitted to end in UNKNOWN.

## API

| Dependency | Failure | Verdict | Recovery | Proof |
|---|---|---|---|---|
| PostgreSQL | connection refused / restart | SAFE FAILURE (500/503, never false success) | pre-ping recycles pool; bounded startup retries | C2 RECOVERED |
| Redis | crash / restart | SAFE FAILURE (rate limit + quota fail closed 429/503; sessions refused) | service resumes when Redis returns | C1 RECOVERED |
| Redis (enqueue) | queue unavailable | SAFE FAILURE (scan → FAILED(ENQUEUE_FAILED); 503 to caller) | row terminal; repo unblocked; reconciliation also sweeps stale QUEUED | C4 SAFE FAILURE |
| — | instance killed mid-traffic | RECOVERED (LB fails over; idempotency key replay safe) | restart instance; no state repair needed | C3 RECOVERED |
| GitHub | 429/500/timeout | SAFE FAILURE | bounded retry w/ backoff → dead-letter; reconciliation queries authoritative state | C5 RECOVERED |

## Worker

| Dependency | Failure | Verdict | Recovery | Proof |
|---|---|---|---|---|
| Redis (broker) | outage | jobs not claimed; no false progress | reclaims on reconnect (RQ) | documented |
| PostgreSQL | outage | job fails; terminal-state guards prevent corruption | bounded retry w/ backoff (TRANSIENT only) | documented |
| — | killed mid-job | at-least-once redelivery | claim guard: terminal scans skipped; artifacts converge (deps delete+reinsert, findings fingerprint-dedup, investigation reuse, recommendation 1:1) | tests/test_v41_cicd.py |
| — | deployment | DRAINING (stop claiming, finish current, exit) | /api/ops/workers/{id}/drain + /api/ops/workers fleet view | Phase 27 |

## Datastores

| Component | Failure | Verdict | Recovery | Proof |
|---|---|---|---|---|
| PostgreSQL (data loss) | disk loss / unrecoverable | OPERATOR REQUIRED | restore from backup (docs/v42-backup-restore-dr.md); audit chains verified post-restore | restore tested, chains VALID |
| Redis (data loss) | flush / unrecoverable | RECOVERED | sessions re-login; rate/quota windows reset (fail-closed semantics unchanged); worker heartbeats re-register | documented |
| Backups | tampering / truncation | OPERATOR REQUIRED | SHA-256 manifest verification refuses restore | tampered dump REFUSED |

## Explicit non-HA (documented, not claimed)

- Single-node PostgreSQL: no automated failover. RPO = backup interval,
  RTO = measured restore time (docs/v42-backup-restore-dr.md).
- Single-node Redis: no Sentinel/Cluster. Rate limiting and sessions
  FAIL CLOSED during Redis unavailability; they never degrade open.
