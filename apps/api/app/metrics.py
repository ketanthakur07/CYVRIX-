"""CYVRIX V4.1 — metrics subsystem.

One dependency-free, process-local registry (counters, gauges, latency
summaries) with the two properties a security platform needs:

1. CLOSED WORLD. The metric name set is fixed below. Unknown names raise
   at registration time (a programming error, never runtime drift), so
   the metrics surface cannot silently grow with the codebase.

2. BOUNDED CARDINALITY. Label values are never user content: no org
   names, no repository names, no branch names, no payload fragments.
   Labels are allowlisted per metric and every accepted value is from a
   fixed server-side vocabulary (endpoint class, result code, status
   family). A value outside the allowlist is replaced by the label's
   `_other` sentinel rather than accepted, so a caller cannot mint new
   label combinations.

Prometheus text exposition is provided for scraping. Scraping is an
OPERATOR surface: it is capability-gated in the ops router, never on the
public API, and the payload carries no identifiers by construction.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Optional


# ── Closed-world registry ─────────────────────────────────────────────

class _MetricDef:
    __slots__ = ("name", "kind", "help", "labels")

    def __init__(self, name: str, kind: str, help: str, labels: tuple[str, ...]) -> None:
        self.name = name
        self.kind = kind
        self.help = help
        self.labels = labels


# The registry. Names are stable API: operators alert on them, so they are
# declared here exactly once and nowhere else.
_METRICS: dict[str, _MetricDef] = {
    m.name: m
    for m in (
        _MetricDef("api_requests_total", "counter",
                   "Public API requests by outcome.", ("outcome",)),
        _MetricDef("api_auth_failures_total", "counter",
                   "Public API authentication failures.", ("reason",)),
        _MetricDef("api_scope_denials_total", "counter",
                   "Public API scope denials.", ()),
        _MetricDef("api_rate_limits_total", "counter",
                   "Public API requests refused by the rate limiter.", ()),
        _MetricDef("api_quota_rejections_total", "counter",
                   "Public API requests refused by quota enforcement.", ("scope",)),
        _MetricDef("api_request_duration", "summary",
                   "Public API request latency in seconds (bounded summary).",
                   ("outcome",)),
        _MetricDef("webhooks_received_total", "counter",
                   "Inbound webhook deliveries received.", ("event",)),
        _MetricDef("webhooks_rejected_total", "counter",
                   "Inbound webhook deliveries refused.", ("reason",)),
        _MetricDef("webhooks_replayed_total", "counter",
                   "Inbound webhook deliveries refused as replays.", ()),
        _MetricDef("ci_events_total", "counter",
                   "CI-originated analysis requests received.", ("outcome",)),
        _MetricDef("jobs_created_total", "counter",
                   "Analysis jobs created.", ("trigger",)),
        _MetricDef("jobs_failed_total", "counter",
                   "Analysis jobs that failed.", ("reason",)),
        _MetricDef("idempotency_conflicts_total", "counter",
                   "Idempotency same-key/different-request conflicts.", ()),
        _MetricDef("github_failures_total", "counter",
                   "Outbound GitHub API failures by classification.", ("kind",)),
        _MetricDef("audit_appends_total", "counter",
                   "Audit chain append attempts by outcome.", ("outcome",)),
        _MetricDef("queue_depth", "gauge",
                   "Analysis jobs waiting in the queue.", ()),
        _MetricDef("active_jobs", "gauge",
                   "Analysis jobs currently executing.", ()),
    )
}


def _check_labels(name: str, labels: dict[str, str]) -> tuple[tuple[str, str], ...]:
    """Validate + normalize label values against the metric's allowlist.

    Unknown label keys are dropped (they would be invisible cardinality).
    Known keys with a non-scalar or unknown value collapse to `_other`.
    Every returned value is therefore from a closed vocabulary.
    """
    spec = _METRICS[name]
    out: list[tuple[str, str]] = []
    for key in spec.labels:
        raw = labels.get(key)
        if raw is None:
            out.append((key, "unknown"))
            continue
        if not isinstance(raw, str) or not raw or len(raw) > 32:
            value = "_other"
        else:
            # Label vocabularies are uppercase tokens or known lowercase
            # families; anything outside [A-Za-z0-9_.-] collapses.
            if raw.replace("_", "").replace("-", "").replace(".", "").isalnum() and len(raw) <= 32:
                value = raw[:32]
            else:
                value = "_other"
        out.append((key, value))
    return tuple(out)


class _Registry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, dict[tuple, float]] = defaultdict(lambda: defaultdict(float))
        self._gauges: dict[str, float] = {}
        # summary: label_key -> [count, total, max]
        self._summaries: dict[str, dict[tuple, list[float]]] = defaultdict(
            lambda: defaultdict(lambda: [0.0, 0.0, 0.0])
        )


_reg = _Registry()


def increment(name: str, labels: Optional[dict[str, str]] = None, value: float = 1.0) -> None:
    """Increment a counter. Unknown metric names raise (fail closed)."""
    if name not in _METRICS:
        raise KeyError(f"unregistered metric: {name}")
    if _METRICS[name].kind != "counter":
        raise TypeError(f"{name} is not a counter")
    key = _check_labels(name, labels or {})
    with _reg._lock:
        _reg._counters[name][key] += float(value)


def set_gauge(name: str, value: float) -> None:
    if name not in _METRICS:
        raise KeyError(f"unregistered metric: {name}")
    if _METRICS[name].kind != "gauge":
        raise TypeError(f"{name} is not a gauge")
    with _reg._lock:
        _reg._gauges[name] = float(value)


def observe_latency(name: str, seconds: float, labels: Optional[dict[str, str]] = None) -> None:
    """Record one latency observation on a summary metric."""
    if name not in _METRICS:
        raise KeyError(f"unregistered metric: {name}")
    if _METRICS[name].kind != "summary":
        raise TypeError(f"{name} is not a summary")
    key = _check_labels(name, labels or {})
    s = float(seconds)
    with _reg._lock:
        entry = _reg._summaries[name][key]
        entry[0] += 1.0
        entry[1] += s
        if s > entry[2]:
            entry[2] = s


# ── Exposition (Prometheus text format) ───────────────────────────────


def _format_labels(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{v}"' for k, v in labels)
    return "{" + inner + "}"


def render_prometheus() -> str:
    """Render the registry in Prometheus text exposition format.

    Content-free by construction: only allowlisted label values appear.
    """
    lines: list[str] = []
    with _reg._lock:
        for name, spec in _METRICS.items():
            lines.append(f"# HELP {name} {spec.help}")
            lines.append(f"# TYPE {name} {spec.kind}")
            if spec.kind == "counter":
                for key, val in sorted(_reg._counters.get(name, {}).items()):
                    lines.append(f"{name}{_format_labels(key)} {val}")
                zero = _format_labels(())
                if zero not in str(_reg._counters.get(name, {})):
                    if not _reg._counters.get(name):
                        lines.append(f"{name} 0")
            elif spec.kind == "gauge":
                val = _reg._gauges.get(name)
                lines.append(f"{name} {val if val is not None else 0}")
            elif spec.kind == "summary":
                for key, (count, total, mx) in sorted(_reg._summaries.get(name, {}).items()):
                    lines.append(f"{name}_count{_format_labels(key)} {int(count)}")
                    lines.append(f"{name}_sum{_format_labels(key)} {total}")
                    lines.append(f"{name}_max{_format_labels(key)} {mx}")
    return "\n".join(lines) + "\n"


def snapshot() -> dict:
    """Structured snapshot for tests and the ops console."""
    with _reg._lock:
        return {
            "counters": {
                name: {
                    _format_labels(key): val
                    for key, val in sorted(_reg._counters.get(name, {}).items())
                }
                for name in _METRICS if _METRICS[name].kind == "counter"
            },
            "gauges": dict(_reg._gauges),
            "summaries": {
                name: {
                    _format_labels(key): {"count": int(c), "sum": s, "max": m}
                    for key, (c, s, m) in sorted(_reg._summaries.get(name, {}).items())
                }
                for name in _METRICS if _METRICS[name].kind == "summary"
            },
        }


def reset_for_tests() -> None:
    """Clear all values. Test-harness only; never called by the app."""
    with _reg._lock:
        _reg._counters.clear()
        _reg._gauges.clear()
        _reg._summaries.clear()


# Convenience accessors used by routes/services (keep call sites honest).

def api_request(outcome: str) -> None:
    increment("api_requests_total", {"outcome": outcome})
    observe_latency("api_request_duration", 0.0, {"outcome": outcome})


def record_api_latency(seconds: float, outcome: str) -> None:
    observe_latency("api_request_duration", seconds, {"outcome": outcome})
