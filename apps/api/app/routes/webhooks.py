"""CYVRIX V4.1 — inbound GitHub webhook endpoint (fixed route).

    POST /api/webhooks/github

This is a SERVICE-class route: its caller is GitHub, authenticated by the
webhook signature — not a session, not an API key. It is the ONLY route
in the platform that accepts unauthenticated traffic, and it is built
accordingly: bounded body, per-IP pre-auth rate limit, constant-time
signature check, replay-proof delivery ids, trusted-state binding, one
side effect (an analysis request), and a structured delivery record.

Every outcome — accept, refuse, replay — lands in the V3.8 audit chain
and the metrics subsystem. Nothing here can approve, authorize, execute
or roll back anything.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.metrics import increment as metric
from app.models import WebhookDelivery
from app.rate_limit import check_rate_limit, get_client_ip
from app.services import webhook_service as wh

logger = logging.getLogger("cyvrix.webhook_route")
settings = get_settings()

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])

_SIGNATURE_STATES = {
    wh.R_MISSING_SIGNATURE: "MISSING",
    wh.R_MALFORMED_SIGNATURE: "MALFORMED",
    wh.R_BAD_SIGNATURE: "INVALID",
    wh.R_MISSING_SECRET: "UNCONFIGURED",
}


async def _record_delivery(
    db: AsyncSession,
    *,
    organization_id,
    delivery_id: str,
    event_type: str,
    signature_state: str,
    outcome: str,
    reason_code,
    installation_pk=None,
    repository_pk=None,
    commit_sha=None,
    ref=None,
    scan_id=None,
) -> None:
    """Persist the structured delivery record (no payload content)."""
    db.add(
        WebhookDelivery(
            organization_id=organization_id,
            github_delivery_id=delivery_id,
            event_type=event_type,
            signature_state=signature_state,
            outcome=outcome,
            reason_code=reason_code,
            installation_pk=installation_pk,
            repository_pk=repository_pk,
            commit_sha=commit_sha,
            ref=ref,
            scan_id=scan_id,
        )
    )
    await db.flush()


@router.post("/github")
async def github_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Inbound GitHub webhook intake. See module docstring for the chain."""
    body: bytes = b""
    event_type = (request.headers.get("x-github-event") or "")[:64]
    raw_delivery_id = (request.headers.get("x-github-delivery") or "")[:64]
    signature = request.headers.get("x-hub-signature-256")

    # Bound BEFORE any assignment inside the try: the error handlers below
    # must never touch an unbound variable.
    organization_id = None
    repository = None
    installation_row = None
    scan = None
    result = None

    try:
        # ── Pre-authentication flood control (Phase 42) ──────────────
        # The source IP is untrusted, but a per-IP budget still binds a
        # flood before any parsing/DB work. The org-scoped limit after
        # binding is the strong one.
        ip = get_client_ip(request)
        allowed, _ = await check_rate_limit(
            f"webhook-ip:{ip}", settings.webhook_ip_rate_limit_per_hour, 3600
        )
        if not allowed:
            metric("webhooks_rejected_total", {"reason": "IP_RATE_LIMITED"})
            return Response(status_code=429)

        # ── Bounded body (Phase 43) ──────────────────────────────────
        declared = request.headers.get("content-length")
        if declared and not declared.isdigit():
            return Response(status_code=400)
        if declared and int(declared) > settings.webhook_max_payload_bytes:
            metric("webhooks_rejected_total", {"reason": wh.R_OVERSIZED})
            return Response(status_code=413)
        body = await request.body()
        if len(body) > settings.webhook_max_payload_bytes:
            metric("webhooks_rejected_total", {"reason": wh.R_OVERSIZED})
            return Response(status_code=413)

        try:
            delivery_id = wh.validate_delivery_id(raw_delivery_id)
        except wh.WebhookError:
            metric("webhooks_rejected_total", {"reason": wh.R_INVALID_DELIVERY_ID})
            return Response(status_code=400)

        # ── Signature (fail closed) ──────────────────────────────────
        try:
            wh.verify_signature(settings.github_webhook_secret, signature, body)
        except wh.WebhookError as exc:
            await _record_delivery(
                db,
                organization_id=None,
                delivery_id=delivery_id,
                event_type=event_type,
                signature_state=_SIGNATURE_STATES.get(exc.reason_code, "INVALID"),
                outcome="REJECTED",
                reason_code=exc.reason_code,
            )
            await db.commit()
            metric("webhooks_rejected_total", {"reason": exc.reason_code})
            # Signature refusals have no trusted tenant yet; the delivery
            # row above IS the record (no org chain to append to).
            return Response(status_code=exc.http_status)

        signature_state = "VALID"

        # ── Event allowlist + bounded parse ──────────────────────────
        try:
            payload = wh.parse_event(event_type or "unknown", body)
        except wh.WebhookError as exc:
            if exc.reason_code == wh.R_UNKNOWN_EVENT:
                # Documented semantics: unknown events are safely ignored.
                metric("webhooks_rejected_total", {"reason": "EVENT_NOT_ALLOWED"})
                return Response(status_code=200)
            metric("webhooks_rejected_total", {"reason": exc.reason_code})
            return Response(status_code=exc.http_status)

        if event_type != "push":
            # Accepted-but-no-op events (installation lifecycle etc.):
            # recorded, no analysis, no tenant claim from payload.
            await _record_delivery(
                db,
                organization_id=None,
                delivery_id=delivery_id,
                event_type=event_type,
                signature_state=signature_state,
                outcome="ACCEPTED",
                reason_code="NO_ACTION_FOR_EVENT",
            )
            await db.commit()
            metric("webhooks_received_total", {"event": event_type})
            return Response(status_code=202)

        # ── push: resolve trusted state, then the ONE side effect ────
        push = wh.extract_push_ref(payload)
        if push is None:
            await _record_delivery(
                db,
                organization_id=None,
                delivery_id=delivery_id,
                event_type=event_type,
                signature_state=signature_state,
                outcome="REJECTED",
                reason_code=wh.R_BAD_PAYLOAD,
            )
            await db.commit()
            metric("webhooks_rejected_total", {"reason": wh.R_BAD_PAYLOAD})
            return Response(status_code=400)

        try:
            claimed_installation = wh.extract_installation_id(payload)
            installation_row = await wh.resolve_installation(
                db, claimed_installation_id=claimed_installation
            )
            organization_id = wh.require_organization_id(installation_row)
            repo_payload = payload.get("repository")
            repo_claim = (
                repo_payload.get("id")
                if isinstance(repo_payload, dict)
                else None
            )
            repository = await wh.resolve_repository(
                db, installation_row, claimed_repo_id=repo_claim
            )

            # ── Org-scoped flood control (the strong limit) ──────────
            allowed, _ = await check_rate_limit(
                f"webhook-org:{organization_id}",
                settings.webhook_rate_limit_per_hour,
                3600,
            )
            if not allowed:
                raise wh.WebhookError(wh.R_ORG_RATE_LIMITED, 429)

            # ── Side effect: exactly one scan per delivery ───────────
            result = await wh.request_scan_for_push(
                db,
                organization_id=organization_id,
                installation=installation_row,
                repository=repository,
                push=push,
                delivery_id=delivery_id,
                event_type=event_type,
            )
            scan = result.scan

            if result.created:
                try:
                    # Late-bound import so tests (and deployments) can
                    # intercept the enqueue consistently with api_v1.
                    from app.worker import enqueue_scan

                    enqueue_scan(str(scan.id))
                except Exception:  # noqa: BLE001 — surface, never swallow
                    logger.error(
                        "webhook_enqueue_failed scan=%s", str(scan.id)[:8]
                    )
                    raise wh.WebhookError(wh.R_SCAN_IN_PROGRESS, 503) from None

        except wh.WebhookError as exc:
            is_replay = exc.reason_code == wh.R_DUPLICATE_DELIVERY
            await _record_delivery(
                db,
                organization_id=organization_id,
                delivery_id=delivery_id,
                event_type=event_type,
                signature_state=signature_state,
                outcome="REJECTED",
                reason_code=exc.reason_code,
            )
            await db.commit()
            metric("webhooks_rejected_total", {"reason": exc.reason_code})
            if is_replay:
                metric("webhooks_replayed_total")
            await wh.audit_webhook_event(
                db,
                organization_id=organization_id,
                repository_id=repository.id if repository is not None else None,
                event_type=event_type,
                outcome="REPLAY_REJECTED" if is_replay else "REJECTED",
                reason_code=exc.reason_code,
                delivery_id=delivery_id,
                signature_state=signature_state,
            )
            return Response(status_code=exc.http_status)

        # ── Accepted ─────────────────────────────────────────────────
        await _record_delivery(
            db,
            organization_id=organization_id,
            delivery_id=delivery_id,
            event_type=event_type,
            signature_state=signature_state,
            outcome="ACCEPTED",
            reason_code=None,
            installation_pk=installation_row.id,
            repository_pk=repository.id,
            commit_sha=push.head_sha,
            ref=push.ref,
            scan_id=scan.id,
        )
        await wh.audit_webhook_event(
            db,
            organization_id=organization_id,
            repository_id=repository.id,
            event_type=event_type,
            outcome="ACCEPTED",
            reason_code=None,
            delivery_id=delivery_id,
            signature_state=signature_state,
        )
        await db.commit()
        metric("webhooks_received_total", {"event": event_type})
        if result.created:
            metric("jobs_created_total", {"trigger": "webhook"})
        return Response(status_code=202)

    except Exception:  # noqa: BLE001 — intake never leaks internals
        await db.rollback()
        logger.exception("webhook_intake_failed")
        metric("webhooks_rejected_total", {"reason": "INTERNAL_ERROR"})
        return Response(status_code=500)
