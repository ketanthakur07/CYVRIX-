"""CYVRIX V3.7 — worker-side operational hardening.

Bounded retries with exponential backoff + jitter for TRANSIENT
failures, dead-letter semantics for exhausted/non-recoverable jobs, and
worker identity. Security denials are NEVER retried (Phase 17): they
fail immediately and permanently.

Queue payloads contain references (scan ids), never credentials
(Phase 36) — enforced by the task signatures themselves.
"""
import logging
import os
import random
import socket
from datetime import datetime, timezone

logger = logging.getLogger("cyvrix.worker_ops")

# ── Worker identity (Phase 37) ───────────────────────────────────────
# Explicit, non-impersonatable-by-configuration identity used in logs
# and (future) lease records. It is NOT a user identity and MUST NOT
# grant API authority beyond the scan worker's own DB writes.


def worker_identity() -> str:
    return os.environ.get("CYVRIX_WORKER_ID") or f"worker-{socket.gethostname()}"


# ── Retry policy (Phase 17/18) ───────────────────────────────────────

MAX_ATTEMPTS = 3           # bounded; never unlimited
BASE_BACKOFF_SECONDS = 5   # exponential base
MAX_BACKOFF_SECONDS = 300  # hard cap (never unbounded growth)

# Security denials / data errors: never retried (fail permanently).
NON_RETRYABLE_REASON_PREFIXES = (
    "POLICY_", "DIGEST_", "SCOPE_", "SECRET_", "AUTH_", "TOKEN_",
    "UNAUTHORIZED", "FORBIDDEN", "VALIDATION_", "MALFORMED_",
)

# Clearly transient infrastructure failures: retried with backoff.
RETRYABLE_EXCEPTIONS = (
    ConnectionError, TimeoutError, OSError,
)


def is_retryable_exception(exc: Exception) -> bool:
    """Retry only clearly-transient infrastructure failures. Anything
    unknown fails permanently (fail closed for retries)."""
    return isinstance(exc, RETRYABLE_EXCEPTIONS)


def backoff_with_jitter(attempt: int) -> int:
    """Bounded exponential backoff with jitter (Phase 18). Never
    synchronized: each worker adds full jitter inside the cap."""
    attempt = max(1, min(int(attempt), 10))
    delay = min(BASE_BACKOFF_SECONDS * (2 ** (attempt - 1)), MAX_BACKOFF_SECONDS)
    return random.randint(1, max(2, delay))


def classify_failure_for_retry(exc: Exception) -> str:
    """TRANSIENT → may retry with backoff; NON_TRANSIENT → dead-letter
    immediately (no automatic retry of security denials, ever)."""
    if is_retryable_exception(exc):
        return "TRANSIENT"
    return "NON_TRANSIENT"


# ── Dead-letter handling (Phase 16) ──────────────────────────────────


def dead_letter_queue_name(queue: str) -> str:
    return f"dead:{queue}"


def move_to_dead_letter(job, queue: str, reason: str) -> str:
    """Record a permanently-failed job for operator recovery.

    Dead-lettered jobs NEVER continue automatically: they land in a
    separate queue and are retried only by an explicit operator action
    (out of band, with fresh authorization where applicable). The
    payload stored is bounded diagnostic metadata — never secrets."""
    import json

    entry = {
        "job_id": getattr(job, "id", "") or "",
        "origin": queue,
        "enqueued_at": datetime.now(timezone.utc).isoformat(),
        "worker": worker_identity(),
        "reason": str(reason)[:200],
        "args_summary": [
            (a if isinstance(a, (str, int, float)) else type(a).__name__)
            for a in (getattr(job, "args", None) or [])[:5]
        ],
    }
    logger.error(
        "job_dead_lettered job=%s queue=%s reason=%s",
        entry["job_id"][:20], queue, entry["reason"],
    )
    return json.dumps(entry)


def should_retry(attempt: int, exc: Exception) -> bool:
    """True when the failure is TRANSIENT and attempts remain."""
    if attempt >= MAX_ATTEMPTS:
        return False
    return classify_failure_for_retry(exc) == "TRANSIENT"
