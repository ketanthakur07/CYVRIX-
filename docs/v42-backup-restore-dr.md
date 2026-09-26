# CYVRIX V4.2 — Backup, Restore, Disaster Recovery

All procedures below were EXECUTED against the real v42 test stack during
certification (tools/cert/backup_restore.py). Nothing here is claimed
without having been run.

## What is backed up

| Data | Mechanism | Why |
|---|---|---|
| PostgreSQL (all tenant + security state) | `pg_dump -Fc` (custom, gzip-6) inside the postgres container | single durable artifact covering organizations, memberships, repositories, scans, findings, actions/approvals/authorizations/executions, remediation, verification/rollback, audit chains + checkpoints, API keys, webhook deliveries |
| Configuration | NOT auto-backed up | secrets live in the environment/secret manager (Phase 65); config is re-deployable by design and must never be baked into dumps |

Docker volumes are explicitly NOT treated as backups.

## Backup integrity (Phase 31/66)

Every backup writes a sibling manifest: `{file}.manifest.json` with
SHA-256, size, TOC entry count, database, timestamp.

- `verify` recomputes the hash and refuses on mismatch — a tampered or
  truncated dump is DETECTED, restore is refused.
- Certification red-team result: a byte flipped at offset 50000 was
  rejected with `BACKUP TAMPERING OR CORRUPTION DETECTED`.
- The dump itself is readback-validated with `pg_restore --list` at
  BACKUP time (a corrupt archive fails backup, not disaster).
- Backups are operator-surface artifacts only: never exposed through any
  API route; `backups/` is gitignored.

## Restore (Phase 32/33/34) — measured procedure

`backup_restore.py restore --file <dump>`:

1. verifies the integrity manifest (refuses tampered files),
2. creates a THROWAWAY database `cyvrix_restore_test` (production DB is
   never touched by the tool),
3. `pg_restore --no-owner`,
4. runs row-count + orphan-FK integrity checks (organizations, users,
   repositories, scans, findings, audit_chain_events, audit_checkpoints,
   api_idempotency_keys, webhook_deliveries, orphan scan rows),
5. runs the V3.8 audit-chain verifier over EVERY restored chain,
6. drops the throwaway database.

Measured certification run (2 seeded tenants, real audit chains):

```
organizations=2 users=2 repositories=2 scans=2 findings=2
audit_chain_events=4 webhook_deliveries=2 orphan_scan_rows=0
chains checked: 2  →  audit chain: VALID
```

## RPO / RTO (Phase 35 — measured, not invented)

- RPO: bounded by backup scheduling. With the documented cron
  (`0 * * * *` hourly logical backup), RPO ≤ 1h. RPO for un-backed
  Redis state is irrelevant (fail-closed reconstructible state only).
- RTO: measured components on the certification machine:
  - restore + integrity + audit verification of the seeded dataset:
    seconds (tool prints timings; dominated by pg_restore of ~112 KB
    archive — a production-sized DB scales this; MEASURE before
    trusting any number)
  - API restart with pool re-establish: single-digit seconds (C2)
  - worker restart: single-digit seconds (RQ reclaim)
  RTO (data-loss scenario) = operator response time + restore time +
  application restart. THERE IS NO AUTOMATED FAILOVER; DR is a
  documented operator procedure.

## Disaster recovery runbook (Phase 36)

1. **Database loss**
   - Stand up replacement PostgreSQL (same major version).
   - `pg_restore` latest VERIFIED dump into it.
   - Point `DATABASE_URL`/`DATABASE_URL_SYNC` at it; start one API
     instance; run `verify` audit check; then scale API/worker fleet.
   - Expected verdict: RECOVERED (with data loss bounded by RPO).
2. **Redis loss**
   - Restart/replace Redis. No data restore required: sessions require
     re-login (fail closed), rate/quota windows reset, worker
     heartbeats re-register within one heartbeat period.
3. **Worker fleet loss**
   - Restart workers; RQ re-delivers unacknowledged jobs (at-least-once);
     application idempotency + terminal-state guards make this safe.
4. **API fleet loss**
   - Restart instances; no state repair required (stateless).
5. **Combined outage**
   - Restore order: PostgreSQL → API (one instance) → verify audit →
     Redis → workers → scale out. During recovery the platform is FAIL
     CLOSED (all security decisions refuse without their dependencies).

## Retention (Phase 68)

- Backups: retain ≥ 48 hourly + 30 daily; delete only after integrity
  verification of the newer generation. Audit data is IN the dumps and
  is never deleted early; the V3.8 append-only guarantee means audit
  rows are never operationally expired.
- Webhook deliveries / job history: bounded operational tables; audit
  chain rows are the security record and outlive them.
