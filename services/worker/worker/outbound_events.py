"""CYVRIX V4.2 completion — worker-side outbound webhook fan-out.

Sync bridge between the RQ task layer (synchronous) and the async
outbound-webhook producers. Called ONLY at real event sites: a scan
reaching a terminal state, a commit-binding mismatch, a CI event
reaching its server-computed outcome.

Failure contract: fan-out failures are logged and NEVER fail the scan
itself — observability must not take down the security operation that
caused the event. Everything here is best-effort with loud logging.
"""
import asyncio
import logging

logger = logging.getLogger("cyvrix.worker_outbound")


def _run(coro) -> None:
    try:
        asyncio.run(coro)
    except Exception as exc:  # noqa: BLE001 — loud, never fatal
        logger.warning("outbound_emit_failed err=%s", type(exc).__name__)


def _org_id_for(db, repo) -> str | None:
    """Resolve the owning organization from trusted installation state."""
    try:
        installation = repo.installation
        org_id = getattr(installation, "organization_id", None)
        return str(org_id) if org_id else None
    except Exception:  # noqa: BLE001
        return None


def notify_scan_outcome(db, repo, scan, new_findings) -> None:
    """A scan reached a terminal state (COMPLETED or FAILED).

    Emits (server-computed results only — never CI- or client-declared):
      - SCAN_COMPLETED (PASS = pipeline pass, FAIL = failed run)
      - FINDING_CREATED for each finding created by THIS run
      - CI_EVENT_PROCESSED when the scan was CI-triggered (the CI event's
        outcome is resolved from the ci_events record, never from CI)
    """
    try:
        org_id = _org_id_for(db, repo)
        if org_id is None:
            return
        from app.services.outbound_event_emitter import (
            emit_ci_event_processed,
            emit_finding_created,
            emit_scan_completed,
        )
        from app.models import CiEvent
        from sqlalchemy import select

        async def _emit():
            await emit_scan_completed(
                organization_id=org_id,
                repository_id=str(repo.id),
                scan_id=str(scan.id),
                scan_status=scan.status,
            )
            for finding in (new_findings or [])[:25]:  # bounded per run
                await emit_finding_created(
                    organization_id=org_id,
                    repository_id=str(repo.id),
                    finding_id=str(finding.id),
                    severity=finding.severity or "UNKNOWN",
                )
            if (scan.trigger or "") == "ci":
                ci_row = (
                    db.execute(
                        select(CiEvent).where(CiEvent.scan_id == scan.id)
                    )
                    .scalars()
                    .first()
                )
                if ci_row is not None:
                    await emit_ci_event_processed(
                        organization_id=org_id,
                        repository_id=str(repo.id),
                        ci_event_id=ci_row.event_id,
                        outcome=ci_row.result or ci_row.outcome or "PROCESSED",
                    )

        _run(_emit())
    except Exception as exc:  # noqa: BLE001 — loud, never fatal
        logger.warning(
            "scan_outcome_emit_failed scan=%s err=%s",
            str(getattr(scan, "id", ""))[:8], type(exc).__name__,
        )


def notify_commit_mismatch(db, repo, scan) -> None:
    """The worker refused the scan: the actual clone SHA differs from the
    REQUESTED binding (stale or fabricated commit). Subscribers learn the
    scan failed COMMIT_MISMATCH; CI-triggered scans additionally leave a
    SECURITY-CRITICAL CI_EVENT_COMMIT_MISMATCH audit witness."""
    try:
        org_id = _org_id_for(db, repo)
        if org_id is None:
            return
        from app.services.outbound_event_emitter import (
            emit_scan_completed,
            emit_ci_commit_mismatch_audit,
        )

        async def _emit():
            await emit_scan_completed(
                organization_id=org_id,
                repository_id=str(repo.id),
                scan_id=str(scan.id),
                scan_status="FAILED",
            )
            if (scan.trigger or "") == "ci":
                await emit_ci_commit_mismatch_audit(
                    organization_id=org_id,
                    repository_id=str(repo.id),
                    scan_id=str(scan.id),
                )

        _run(_emit())
    except Exception as exc:  # noqa: BLE001 — loud, never fatal
        logger.warning(
            "commit_mismatch_emit_failed scan=%s err=%s",
            str(getattr(scan, "id", ""))[:8], type(exc).__name__,
        )
