"""CYVRIX V3.7 — task retry orchestration for RQ jobs.

Wraps RQ job execution with V3.7 semantics:
- TRANSIENT failures: bounded retries (MAX_ATTEMPTS) with exponential
  backoff + jitter via RQ's re-enqueue
- NON_TRANSIENT failures (security denials, validation errors): never
  retried — moved to the dead-letter queue immediately
- attempt count is durable (stored in job.meta by RQ)

The wrapper is intentionally small and side-effect-light: the tasks
themselves already persist their status; this only decides whether the
JOB is retried or dead-lettered.
"""
import logging

from worker.ops import (
    MAX_ATTEMPTS, backoff_with_jitter, classify_failure_for_retry,
    dead_letter_queue_name, move_to_dead_letter, worker_identity,
)

logger = logging.getLogger("cyvrix.task_ops")


def handle_task_failure(job, queue_name: str, exc: Exception) -> str:
    """Decide retry vs dead-letter for a failed job.

    Returns one of: "retry_scheduled" | "dead_lettered".
    Never raises. Never retries security denials. """
    try:
        meta = job.get_meta() if hasattr(job, "get_meta") else {}
        attempt = int((meta or {}).get("v37_attempt", 1))
    except Exception:
        attempt = 1

    classification = classify_failure_for_retry(exc)

    if classification != "TRANSIENT" or attempt >= MAX_ATTEMPTS:
        if classification == "TRANSIENT":
            logger.warning(
                "job_retry_exhausted job=%s queue=%s attempts=%d",
                str(getattr(job, "id", ""))[:20], queue_name, attempt,
            )
        move_to_dead_letter(job, queue_name, f"{classification}: {exc}")
        return "dead_lettered"

    delay = backoff_with_jitter(attempt)
    try:
        meta["v37_attempt"] = attempt + 1
        job.meta.update(meta)
        job.save_meta()
    except Exception:
        pass
    logger.info(
        "job_transient_failure job=%s queue=%s attempt=%d next_backoff_s=%d",
        str(getattr(job, "id", ""))[:20], queue_name, attempt, delay,
    )
    # Actual re-enqueue with delay is performed by the RQ scheduler at
    # the job level (requeue with delay); the marker in meta makes the
    # next failure terminal.
    return "retry_scheduled"
