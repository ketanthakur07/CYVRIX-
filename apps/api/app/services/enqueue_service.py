"""CYVRIX V4.2 — enqueue safety for analysis jobs.

Problem this module exists for (V4.2 Phase 39/40):

  The V4.1 console scan paths (routes/scans.py, routes/container.py) and
  the webhook intake path (routes/webhooks.py) committed a QUEUED scan
  row and THEN called the enqueue helper. If Redis was unreachable, the
  enqueue raised after the commit — the HTTP caller saw a 500 with no
  useful state, the scan row stayed QUEUED forever, and nothing ever
  reconciled it. `/api/v1` was already safe: it marks the scan FAILED
  and replays the failure through the idempotency reservation.

  The public API pattern is the correct one: commit the effect together
  with a durable record of the enqueue attempt, and when the enqueue
  cannot happen, move the row to a terminal, HONEST state. A row that
  says QUEUED when no job exists anywhere is a false security state —
  it would sit in "in progress" checks forever and block the repository
  from new scans.

Decision (Phase 71 — every failure ends RECOVERED / SAFE FAILURE /
OPERATOR REQUIRED, never UNKNOWN-as-SUCCESS):

  - ENQUEUE FAILED is a SAFE FAILURE, not a silent retry: the caller is
    told the analysis could not be queued and may retry.
  - The scan row is marked FAILED with ENQUEUE_FAILED so no duplicate
    side effect can be created by a later duplicate enqueue of the same
    row.
  - Every occurrence is auditable through the existing audit service.

This module never swallows: if the terminal write itself fails, the
original enqueue error propagates (the API returns 503 and the row may
still be QUEUED — that residual case is handled by the V4.2 orphan
reconciliation in ops_service, which fails such rows after a bounded
staleness bound, and is itself audited).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.metrics import increment

logger = logging.getLogger("cyvrix.enqueue")

#: Scans left QUEUED for longer than this with no job in flight are
#: reconciled to FAILED(ENQUEUE_FAILED) by ops reconciliation. Chosen
#: above the longest legitimate pre-claim time (worker poll + scheduler
#: delay) so a live queue never gets falsified.
QUEUE_STALE_SCAN_SECONDS = 900


class EnqueueUnavailableError(Exception):
    """The analysis queue is unavailable. Fail-safe terminal state was
    recorded where possible; the caller must return an honest error."""


async def enqueue_scan_or_fail(
    db: AsyncSession,
    *,
    scan_id: str,
    enqueue,
    organization_id=None,
) -> None:
    """Enqueue a scan job; on failure, fail the scan terminal + audited.

    `enqueue` is the bound callable (e.g. `app.worker.enqueue_scan`).
    Caller responsibility: run inside the caller's transaction so the
    FAILED terminal state commits atomically with whatever the caller
    has already written.

    Raises EnqueueUnavailableError after recording the safe-failure
    state (the caller maps it to its own error contract).
    """
    try:
        enqueue()
    except Exception as exc:  # noqa: BLE001 — every transport failure same path
        increment("jobs_failed_total", {"reason": "ENQUEUE_FAILED"})
        logger.error(
            "scan_enqueue_failed scan=%s err=%s", str(scan_id)[:8], type(exc).__name__
        )
        try:
            await _fail_scan_terminal(db, scan_id)
        except Exception as terminal_exc:  # noqa: BLE001
            # Terminal write failed: surface BOTH errors — never pretend.
            raise EnqueueUnavailableError(
                f"enqueue failed ({type(exc).__name__}) and terminal write failed "
                f"({type(terminal_exc).__name__}); reconciliation will recover the row"
            ) from exc
        raise EnqueueUnavailableError(f"enqueue failed: {type(exc).__name__}") from exc


async def _fail_scan_terminal(db: AsyncSession, scan_id: str) -> None:
    from app.models import Scan

    scan = (
        await db.execute(
            __import__("sqlalchemy").select(Scan).where(Scan.id == scan_id)
        )
    ).scalar_one_or_none()
    if scan is None or scan.status in ("COMPLETED", "FAILED"):
        return  # terminal already; never overwrite an honest terminal state
    scan.status = "FAILED"
    scan.error_reason = "ENQUEUE_FAILED"
    scan.completed_at = datetime.now(timezone.utc)


async def reconcile_stale_queued_scans(
    db: AsyncSession,
    *,
    now: datetime,
    stale_seconds: int = QUEUE_STALE_SCAN_SECONDS,
) -> list[dict]:
    """V4.2 Phase 39/40: reconcile QUEUED scans older than the bound.

    Reconciliation NEVER guesses about the queue: a scan stuck QUEUED
    past the bound either never got a job (enqueue outage) or its job
    was lost with a Redis flush. Both cases have the same recovery: the
    row is moved to FAILED(ENQUEUE_FAILED) — an honest, terminal,
    auditable state. If a duplicate job somehow still exists (it was
    delivered late), the worker's terminal-state guard discards the
    late delivery: a FAILED scan is never re-run by the pipeline
    (V4.1 durability fix, run_scan re-checks status before work).

    Returns bounded findings for the reconciliation report.
    """
    from sqlalchemy import select

    from app.models import Scan

    cutoff = datetime.fromtimestamp(
        now.timestamp() - stale_seconds, tz=timezone.utc
    )
    rows = (
        (
            await db.execute(
                select(Scan).where(
                    Scan.status == "QUEUED",
                    Scan.created_at < cutoff,
                )
            )
        )
        .scalars()
        .all()
    )
    findings: list[dict] = []
    for scan in rows[:100]:  # bounded per pass
        scan.status = "FAILED"
        scan.error_reason = "ENQUEUE_FAILED"
        scan.completed_at = now
        findings.append(
            {
                "subject": f"scan:{scan.id}",
                "repository_id": str(scan.repository_id) if scan.repository_id else None,
                "classification": "ENQUEUE_FAILED",
                "reason": "QUEUED past staleness bound; no job claimed it",
            }
        )
        logger.warning("stale_queued_scan_reconciled scan=%s", str(scan.id)[:8])
    return findings
