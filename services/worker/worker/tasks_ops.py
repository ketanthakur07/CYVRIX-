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

    V4.2 (Phase 5/6): queue delivery is AT-LEAST-ONCE and a "retry" is
    only real when the job is actually re-enqueued. A TRANSIENT failure
    with attempts remaining is now SCHEDULED back onto its origin queue
    with bounded backoff (the running scheduler picks it up). Anything
    else is dead-lettered for explicit operator recovery — never retried
    automatically (security denials in particular).

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

    # ── V4.2: REAL re-enqueue with delay (bounded backoff + jitter) ──
    try:
        from datetime import datetime, timedelta, timezone

        from rq import Queue
        from worker.config import get_settings

        queue = Queue(queue_name, connection=__import__("redis").from_url(get_settings().redis_url))
        queue.schedule_job(job, datetime.now(timezone.utc) + timedelta(seconds=delay))
        # The job still sits in RQ's FailedJobRegistry from this failure;
        # remove it so the registries reflect the truth (retry in flight).
        try:
            from rq.registry import FailedJobRegistry
            FailedJobRegistry(queue_name, connection=queue.connection).remove(job)
        except Exception:
            pass  # cosmetic; the scheduled job is authoritative
        logger.info(
            "job_transient_failure job=%s queue=%s attempt=%d next_backoff_s=%d",
            str(getattr(job, "id", ""))[:20], queue_name, attempt, delay,
        )
        return "retry_scheduled"
    except Exception as schedule_exc:  # noqa: BLE001
        # The retry could not be scheduled: NEVER claim a retry that is
        # not in flight. Dead-letter instead so an operator sees it.
        logger.error(
            "job_retry_schedule_failed job=%s queue=%s err=%s",
            str(getattr(job, "id", ""))[:20], queue_name, type(schedule_exc).__name__,
        )
        move_to_dead_letter(job, queue_name, f"RETRY_SCHEDULE_FAILED: {exc}")
        return "dead_lettered"
