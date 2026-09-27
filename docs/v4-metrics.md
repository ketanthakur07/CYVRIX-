# CYVRIX V4.1 — Metrics

Status: IMPLEMENTED (this document is the contract)
Source: `apps/api/app/metrics.py`, endpoint `GET /api/ops/metrics`
Related: `v4-quotas.md`, `v4-webhooks.md`, `v4-async-jobs.md`

---

## 1. Subsystem

A dependency-free, process-local registry with three kinds:

| Kind | Semantics |
|---|---|
| counter | monotonic total (survives per process; reset on restart) |
| gauge | current value (queue depth, active jobs) |
| summary | count / sum / max of latency observations |

Exposition is Prometheus text format on `GET /api/ops/metrics` — an
OPERATOR surface: session-authenticated, `VIEW_DIAGNOSTICS` capability,
rate-limited. It is deliberately NOT on the public API, and the payload
is content-free by construction.

---

## 2. Metric catalog (closed world; Phase 34)

| Metric | Kind | Labels |
|---|---|---|
| `api_requests_total` | counter | `outcome` |
| `api_auth_failures_total` | counter | `reason` |
| `api_scope_denials_total` | counter | — |
| `api_rate_limits_total` | counter | — |
| `api_quota_rejections_total` | counter | `scope` |
| `api_request_duration` | summary | `outcome` |
| `webhooks_received_total` | counter | `event` |
| `webhooks_rejected_total` | counter | `reason` |
| `webhooks_replayed_total` | counter | — |
| `ci_events_total` | counter | `outcome` |
| `jobs_created_total` | counter | `trigger` |
| `jobs_failed_total` | counter | `reason` |
| `idempotency_conflicts_total` | counter | — |
| `github_failures_total` | counter | `kind` |
| `audit_appends_total` | counter | `outcome` |
| `queue_depth` | gauge | — |
| `active_jobs` | gauge | — |

Unknown metric names RAISE at call time (fail closed): the catalog
cannot silently drift from the code.

---

## 3. Cardinality and content security (Phase 35)

Label vocabularies are CLOSED and content-free:

- labels are allowlisted per metric at registration;
- a value outside the safe charset/length collapses to the `_other`
  sentinel — no organization names, no repository names, no branch
  names, no payload fragments can enter a label;
- unknown label keys are dropped;
- a cardinality attack (`outcome='x" label="injected'`) renders as
  `_other` and cannot break the exposition format (tested).

No secrets can enter metrics: there is no code path that passes
credential-shaped values as labels, and the redaction rule is the same
class as the audit chain's.

---

## 4. Process-local caveat (documented, not overstated)

Counters are per-process. With multiple API replicas, scraped values are
per-instance; aggregate by summing instances (standard Prometheus
practice). This is observability plumbing, not a security
control: correctness of rate limits and quotas does NOT depend on it.

**V4.2 — worker `active_jobs` gauge (shipped).** Each worker's heartbeat
(`services/worker/main.py` → `worker_runtime.heartbeat`, every 30 s) now
writes `active_jobs` (1 when the worker owns a job, 0 when idle) into its
Redis hash `cyvrix:worker:<name>`; the hash carries a 90 s TTL, so a
crashed worker's contribution expires instead of sticking. The real gauge
is exported fleet-wide by `GET /api/ops/metrics`, which sums the counts of
live workers (unparseable or absent values contribute nothing). What the
gauge does NOT count: queued-but-unstarted jobs (that is queue depth, a
different signal — still not exported, see `v4-public-api.md` §11).

**V4.2 — outbound webhook counters (shipped).**
`webhook_endpoints_total`, `webhook_deliveries_created_total`,
`webhook_deliveries_succeeded_total{event}`,
`webhook_deliveries_retried_total{event}`,
`webhook_deliveries_dead_lettered_total{event}` and
`webhook_delivery_rejected_total{reason}` are registered in the closed
world `_METRICS` catalog and incremented by the outbound delivery path
(`v4-webhooks.md` §12–15).

---

## 5. Tests

`tests/test_v41_integration.py::TestMetrics` — catalog rendering,
fail-closed on unknown names, cardinality-attack collapse, summary/gauge
exposition.
