# CYVRIX V4.2 — Load Testing (measured)

Harness: `tools/cert/load_v42.py`. Target: TWO real uvicorn API
instances (the same processes the multi-instance certification uses) over
real PostgreSQL 16 + Redis 7 containers. GitHub/OSV/LLM are NOT exercised
by the load generator (mutations create analysis REQUESTS; the worker
pipeline is not driven) — this is load of the API/data plane only.

These numbers are from the certification development machine. They are
NOT production-capacity claims; re-measure on target hardware.

## Scenarios and results (measured 2026-09-26)

### L1 burst — 200 mixed ops across 2 instances, 2 tenants
```
ops=200 accepted=200 refused=0
p50=1119.8ms  p95=1313.4ms  p99=1324.2ms
codes: 200×160 reads, 202×2 scan-created, 409×38 scan-conflict
```
p50 is dominated by the FIRST cold round (connection establishment,
crypto, rate-limit Redis round trips warm up). The 409s are correct
"scan already in progress" enforcement — not errors.

### L2 sustained — 60 seconds continuous
```
ops=18,490 accepted=560 refused=17,930 (rate-limit enforcement, by design)
accepted-only latency: p50=25.7ms  p95=44.3ms  p99=296.9ms
```
The refusal wave is the V4.1 org budget (600 reads/hour) doing its job
under 300+ req/s of synthetic traffic. Accepted-request latency stayed
in the tens of ms — no latency drift, no memory/connection growth
observed over the window (process RSS stable, DB connection count flat
at pool size).

### L3 noisy neighbor
```
quiet tenant baseline p95 = 476.5ms (cold)
quiet tenant p95 while noisy tenant hammers = 13.6ms
bound = 3× baseline + 50ms → PASS
```
Tenant isolation under load holds: the noisy tenant could not degrade
the quiet tenant's service (its traffic saturated its own rate budget
and was refused; the quiet tenant's requests were served).

## Security invariants verified under load (Phase 48)

- Zero 500s across all scenarios; zero transport errors after warmup.
- Authorization: only 200/202/409/429 observed — no cross-tenant leaks.
- Rate limits and quotas remained exact under concurrency
  (multi_instance S3/S4).
- Idempotency: distinct keys only in the generator; duplicate-key
  behavior proven separately (S1) and by race tests.

## What this does NOT measure (honest limits)

- Worker/scan pipeline throughput (LLM/clone paths unmocked at volume).
- Multi-node PostgreSQL/Redis (single-node test containers).
- TLS termination and LB overhead (external to the API processes).
- Production-fleet HTTP throughput — an operational measurement on
  target hardware, not a security property.
