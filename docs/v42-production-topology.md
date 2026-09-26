# CYVRIX V4.2 — Production Topology

Status: certified on a real local stack (real PostgreSQL 16, real Redis 7,
real uvicorn API processes, real RQ worker, real Docker). Numbers quoted in
docs/v42-load-testing.md are MEASURED from that stack and are NOT
production-capacity claims for other hardware.

## Topology

```
                     ┌───────────────────────────┐
        clients ───▶ │  Load Balancer (external) │   ← TLS, sticky NOT required
                     └────────────┬──────────────┘
              ┌───────────────────┼───────────────────┐
              ▼                   ▼                   ▼
        ┌──────────┐        ┌──────────┐        ┌──────────┐
        │ API #1   │        │ API #2   │  ...   │ API #N   │   uvicorn processes
        └────┬─────┘        └────┬─────┘        └────┬─────┘
             │  pool 20+10       │                   │
             └─────────┬─────────┴───────────────────┘
                       ▼
              ┌─────────────────┐        ┌───────────────┐
              │  PostgreSQL 16  │        │    Redis 7    │
              │  (single node)  │        │  (single node)│
              └─────────────────┘        └───────┬───────┘
                       ▲                         │ RQ queues (at-least-once)
                       │ sync pool 5             ▼
              ┌──────────────────────────────────────┐
              │  Worker fleet: worker#1 ... worker#N │  RQ processes
              └──────────────────────────────────────┘

  External: GitHub (API + git smart HTTP), OSV, LLM provider — each an
  independent failure domain, reached only through the worker fleet and
  a thin install/token path on the API.
```

## Trust and failure boundaries

| Boundary | Trust | Failure behavior |
|---|---|---|
| LB → API | untrusted client | API is stateless; any instance can serve any request |
| API → PostgreSQL | trusted, credentials via env | fail closed: 500/503, no false success (C2) |
| API → Redis | trusted | fail closed: rate limits/quota refuse 429/503 (C1); sessions fail closed |
| API → queue (enqueue) | trusted | fail safe: scan → FAILED(ENQUEUE_FAILED), caller 503 (C4) |
| Worker → Redis (broker) | trusted | at-least-once delivery; application idempotency converges redelivery |
| Worker → PostgreSQL | trusted | terminal-state guards make re-runs safe |
| Worker → GitHub | UNTRUSTED external | reconciliation classifies from authoritative remote state; never guessed |
| Webhooks → API | UNTRUSTED caller | HMAC fail closed; delivery-id dedup is DB-enforced (S2) |

## What is stateless, what is state

- API instances hold NO security-relevant process-local state.
  (The metrics registry is per-process and additive-only telemetry;
  worker drain flags are liveness hints; both are documented as
  non-authoritative. Certification S5 proves revocation propagates.)
- Authoritative state lives ONLY in PostgreSQL (leases, idempotency,
  approvals, audit chains, API keys) and Redis (sessions, rate/quota
  windows, worker heartbeats — all reconstructible or fail-closed).

## Multi-instance facts (measured, tools/cert/multi_instance.py)

- Idempotency-Key replayed across instances → same scan id (S1 PASS)
- Same GitHub delivery id across instances → one side effect (S2 PASS)
- Rate limit is GLOBAL across instances: 600/h shared, 601st refused (S3 PASS)
- Quota consume is exact under concurrency: 5 of 20 (S4 PASS)
- API-key revocation propagates instantly to both instances (S5 PASS)
