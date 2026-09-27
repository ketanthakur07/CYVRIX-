"""CYVRIX V4.2 completion — real-event → outbound-webhook producers.

Outbound webhooks deliver REAL platform events, not synthetic ones: the
functions here are called from the sites where the event genuinely
happens (API-key rotation, finding creation, scan completion, and the
V3 chain's lifecycle transitions).

CONTRACT:

    - Best-effort BY DESIGN and BY DOCUMENTATION: an observability-side
      fan-out must never take down the security operation that caused
      the event. Failures are logged loudly (never swallowed silently)
      and are visible through the webhook_deliveries_created_total /
      _rejected_total counters and delivery rows themselves.
    - Uses a SHORT-LIVED standalone session: producers often run inside
      flows that manage their own commits; the fan-out must not couple
      to the producer's transaction.
    - Payloads carry identifiers and server-computed results ONLY
      (built by outbound_webhook_service.build_payload) — never secret
      material, never repository content.
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("cyvrix.outbound_emitter")


async def emit_outbound_event(
    *,
    organization_id,
    event_type: str,
    resource_kind: str,
    resource_id: str,
    repository_id: Optional[str] = None,
    result: Optional[str] = None,
    reason: Optional[str] = None,
) -> list[str]:
    """Fan one real platform event out to subscribed endpoints.

    Returns created delivery ids (diagnostics). Never raises: an
    outbound-webhook outage must not break the event's own operation.
    """
    try:
        from sqlalchemy.ext.asyncio import (
            async_sessionmaker,
            create_async_engine,
        )

        from app.config import get_settings
        from app.services import outbound_webhook_service as ows

        settings = get_settings()
        if not settings.outbound_webhook_secret_key:
            return []  # feature disabled: zero fan-out, zero error

        engine = create_async_engine(settings.database_url, pool_pre_ping=True)
        try:
            maker = async_sessionmaker(engine, expire_on_commit=False)
            async with maker() as session:
                from app.worker import enqueue_outbound_webhook_delivery

                return await ows.create_deliveries_for_event(
                    session,
                    organization_id=organization_id,
                    event_type=event_type,
                    resource_kind=resource_kind,
                    resource_id=resource_id,
                    repository_id=repository_id,
                    result=result,
                    reason=reason,
                    enqueue=enqueue_outbound_webhook_delivery,
                )
        finally:
            await engine.dispose()
    except Exception as exc:  # noqa: BLE001 — logged loudly, never fatal
        logger.error(
            "outbound_event_emit_failed event=%s err=%s",
            event_type, type(exc).__name__,
        )
        return []


async def emit_api_key_rotated(
    *, organization_id, api_key_id: str, key_prefix: str
) -> None:
    """A credential was rotated: subscribed receivers are told THAT
    (prefix + key id only — never the new secret)."""
    await emit_outbound_event(
        organization_id=organization_id,
        event_type="API_KEY_ROTATED",
        resource_kind="api_key",
        resource_id=str(api_key_id),
        result=key_prefix,
    )


async def emit_finding_created(
    *, organization_id, repository_id, finding_id: str,
    severity: str,
) -> None:
    await emit_outbound_event(
        organization_id=organization_id,
        event_type="FINDING_CREATED",
        resource_kind="finding",
        resource_id=str(finding_id),
        repository_id=str(repository_id),
        result=str(severity)[:40],
    )


async def emit_scan_completed(
    *, organization_id, repository_id, scan_id: str,
    scan_status: str,
) -> None:
    """Server-computed scan outcome only: COMPLETED → result PASS
    (pipeline pass, NOT a clean bill — see docs/v4-public-api.md),
    FAILED → FAIL. Queued/running states are not deliverable events."""
    result = {"COMPLETED": "PASS", "FAILED": "FAIL"}.get(
        (scan_status or "").upper()
    )
    if result is None:
        return
    await emit_outbound_event(
        organization_id=organization_id,
        event_type="SCAN_COMPLETED",
        resource_kind="scan",
        resource_id=str(scan_id),
        repository_id=str(repository_id),
        result=result,
        reason=scan_status,
    )


async def emit_ci_event_processed(
    *, organization_id, repository_id, ci_event_id: str,
    outcome: str,
) -> None:
    await emit_outbound_event(
        organization_id=organization_id,
        event_type="CI_EVENT_PROCESSED",
        resource_kind="ci_event",
        resource_id=str(ci_event_id),
        repository_id=str(repository_id),
        result=str(outcome)[:40],
    )


async def emit_ci_commit_mismatch_audit(
    *, organization_id, repository_id, scan_id: str,
) -> None:
    """SECURITY-CRITICAL witness: a CI event was bound to a commit that
    the worker proved never matched the repository state. Imported lazily
    to keep this module importable from worker-side contexts."""
    import asyncio

    from app.database import async_session
    from app.services import audit_service

    def _emit_sync() -> None:
        async def _emit():
            async with async_session() as session:
                await audit_service.emit_security_event(
                    session,
                    organization_id=organization_id,
                    event_type="CI_EVENT_COMMIT_MISMATCH",
                    actor_type=audit_service.ActorType.WORKER,
                    repository_id=repository_id,
                    reason_code="COMMIT_MISMATCH",
                    payload={"scan_id": str(scan_id)[:64]},
                )
                await session.commit()

        asyncio.run(_emit())

    try:
        _emit_sync()
    except Exception as exc:  # noqa: BLE001 — logged, never fatal
        logger.error(
            "ci_commit_mismatch_audit_failed err=%s", type(exc).__name__
        )


# ── V3 chain lifecycle producers (thin wrappers for task-side calls) ──

_V3_EVENT_MAP = {
    "ACTION_PROPOSED": ("ACTION_CREATED", "action_proposal"),
    "EXECUTION_STARTED": ("EXECUTION_STARTED", "execution_run"),
    "EXECUTION_COMPLETED": ("EXECUTION_COMPLETED", "execution_run"),
    "VERIFICATION_PASSED": ("VERIFICATION_COMPLETED", "verification_run"),
    "VERIFICATION_FAILED": ("VERIFICATION_COMPLETED", "verification_run"),
    "ROLLBACK_SUCCEEDED": ("ROLLBACK_COMPLETED", "rollback_run"),
    "ROLLBACK_FAILED": ("ROLLBACK_COMPLETED", "rollback_run"),
}


async def emit_v3_chain_event(
    db,
    *,
    event_type: str,
    repository_id,
    subject_id: str,
    result: Optional[str] = None,
    reason: Optional[str] = None,
) -> None:
    """Mirror a committed V3.8 chain event to outbound subscribers.

    Called by the WORKER task layer (which already mirrors legacy audit
    events) after the chain append has COMMITTED. Resolves the owning
    organization from the repository inside the caller's session —
    read-only, no commits, no side effects on the caller's transaction.
    """
    mapped = _V3_EVENT_MAP.get(event_type)
    if mapped is None:
        return
    outbound_type, resource_kind = mapped
    try:
        from sqlalchemy import select

        from app.models import GithubInstallation, Repository

        org_id = (
            await db.execute(
                select(GithubInstallation.organization_id)
                .join(Repository, Repository.installation_id == GithubInstallation.id)
                .where(Repository.id == repository_id)
            )
        ).scalar_one_or_none()
        if org_id is None:
            return
        await emit_outbound_event(
            organization_id=org_id,
            event_type=outbound_type,
            resource_kind=resource_kind,
            resource_id=str(subject_id),
            repository_id=str(repository_id),
            result=result,
            reason=reason,
        )
    except Exception as exc:  # noqa: BLE001 — logged, never fatal
        logger.error(
            "v3_outbound_mirror_failed event=%s err=%s",
            event_type, type(exc).__name__,
        )
