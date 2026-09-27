"""CYVRIX V4.2 completion — outbound webhook management (`/api/v1/webhooks`).

Public-API surface for the outbound webhook feature. Every request:

    authentication (hashed API key)
      → organization (derived FROM THE KEY)
        → scope `webhooks:manage` (HIGH_IMPACT: issuance requires
          ORG_ADMIN standing)
          → resource ownership (the endpoint's own organization)
            → SSRF validation (creation AND update)
              → V3.8 audit (endpoint lifecycle is SECURITY-CRITICAL)

The signing secret is returned EXACTLY ONCE (creation response) and is
never derivable again — not from any endpoint, ever. Delivery bodies
carry bounded identifiers; the secret never enters a response, a log
line, an audit payload, or a metric label.

This surface configures receivers only. It can never approve, execute,
or authorize anything in the V3 chain.
"""
from __future__ import annotations

import logging
import secrets as pysecrets
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.metrics import increment as metric
from app.models import OutboundWebhookDelivery, OutboundWebhookEndpoint, utcnow
from app.services import audit_service
from app.services import outbound_webhook_service as wh
from app.services.org_auth import require_api_scope

logger = logging.getLogger("cyvrix.webhook_endpoints")
settings = get_settings()

router = APIRouter(prefix="/api/v1/webhooks", tags=["public-api-webhooks"])

# webhooks:manage is HIGH_IMPACT: adding an org-scoped receiver is an
# administrative act (it directs platform event data to an external URL).
_WEBHOOKS_MANAGE_SCOPE = "webhooks:manage"


class OutApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str,
                 details: Optional[dict] = None) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details


class WebhookEndpointCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=8, max_length=2048)
    events: list[str] = Field(min_length=1, max_length=50)
    description: Optional[str] = Field(default=None, max_length=200)

    @field_validator("events")
    @classmethod
    def _validate_events(cls, v: list[str]) -> list[str]:
        """Closed-world allowlist; bounded count; duplicates collapsed."""
        if len(set(v)) != len(v):
            raise ValueError("events must not contain duplicates")
        for item in v:
            if not wh.is_valid_outbound_event(item):
                raise ValueError(f"unsupported event type: {item[:40]}")
        if len(v) > settings.outbound_webhook_max_events_per_endpoint:
            raise ValueError(
                f"at most {settings.outbound_webhook_max_events_per_endpoint} "
                "events per endpoint"
            )
        return sorted(v)


class WebhookEndpointUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: Optional[list[str]] = None
    description: Optional[str] = Field(default=None, max_length=200)

    @field_validator("events")
    @classmethod
    def _validate_events(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v is None:
            return v
        if len(set(v)) != len(v):
            raise ValueError("events must not contain duplicates")
        for item in v:
            if not wh.is_valid_outbound_event(item):
                raise ValueError(f"unsupported event type: {item[:40]}")
        if len(v) > settings.outbound_webhook_max_events_per_endpoint:
            raise ValueError(
                f"at most {settings.outbound_webhook_max_events_per_endpoint} "
                "events per endpoint"
            )
        return sorted(v)


class WebhookEndpointOut(BaseModel):
    id: str
    url: str
    description: Optional[str] = None
    status: str
    events: list[str]
    secret_hint: str
    created_at: Optional[str] = None
    disabled_at: Optional[str] = None


class WebhookEndpointCreated(WebhookEndpointOut):
    """Creation response: the ONLY response that ever carries the secret."""
    signing_secret: str


class WebhookDeliveryOut(BaseModel):
    id: str
    endpoint_id: str
    event_type: str
    delivery_id: str
    state: str
    attempt: int
    last_http_status: Optional[int] = None
    last_error: Optional[str] = None
    created_at: Optional[str] = None
    delivered_at: Optional[str] = None
    dead_lettered_at: Optional[str] = None


def _iso(value) -> Optional[str]:
    return value.isoformat() if value else None


def _endpoint_out(e: OutboundWebhookEndpoint) -> WebhookEndpointOut:
    return WebhookEndpointOut(
        id=str(e.id),
        url=e.url,
        description=e.description,
        status=e.status,
        events=list(e.events or []),
        secret_hint=e.secret_hint,
        created_at=_iso(e.created_at),
        disabled_at=_iso(e.disabled_at),
    )


async def _owned_endpoint(
    db: AsyncSession, endpoint_id, organization_id
) -> OutboundWebhookEndpoint:
    """404 semantics: a foreign endpoint is indistinguishable from a
    missing one (existence never confirmed across tenants)."""
    row = (
        await db.execute(
            select(OutboundWebhookEndpoint).where(
                OutboundWebhookEndpoint.id == endpoint_id,
                OutboundWebhookEndpoint.organization_id == organization_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise OutApiError(
            404, "WEBHOOK_ENDPOINT_NOT_FOUND",
            "No such webhook endpoint in this organization.",
        )
    return row


@router.post("", response_model=WebhookEndpointCreated,
             status_code=status.HTTP_201_CREATED)
async def create_endpoint(
    body: WebhookEndpointCreate,
    request: Request,
    key=Depends(require_api_scope(_WEBHOOKS_MANAGE_SCOPE)),
    db: AsyncSession = Depends(get_db),
):
    """Register one HTTPS receiver for this organization's events.

    The signing secret is shown ONCE in this response and stored only
    encrypted. URLs are SSRF-validated (https, global IPs, no userinfo,
    no query) and re-validated at every delivery connection.
    """
    try:
        wh.validate_webhook_url(body.url)
    except wh.UrlValidationError as exc:
        raise OutApiError(
            422, exc.reason_code,
            "The webhook URL is not allowed.",
            {"reason": exc.reason_code},
        )
    if not settings.outbound_webhook_secret_key:
        raise OutApiError(
            503, "OUTBOUND_WEBHOOKS_DISABLED",
            "Outbound webhooks are not configured on this deployment.",
        )

    count = (
        await db.execute(
            select(OutboundWebhookEndpoint.id).where(
                OutboundWebhookEndpoint.organization_id == key.organization_id
            )
        )
    ).scalars().all()
    if len(count) >= settings.outbound_webhook_max_endpoints_per_org:
        raise OutApiError(
            409, "WEBHOOK_ENDPOINT_LIMIT_REACHED",
            "This organization has reached its webhook endpoint limit.",
        )

    secret = wh.generate_signing_secret()
    endpoint = OutboundWebhookEndpoint(
        organization_id=key.organization_id,
        url=body.url,
        description=(body.description or None),
        status="ACTIVE",
        events=body.events,
        secret_ciphertext=wh.encrypt_secret(secret),
        secret_hint=secret[:4],
        secret_key_version=1,
    )
    db.add(endpoint)
    await db.flush()

    # SECURITY-CRITICAL: chain append is atomic with the endpoint row.
    try:
        await audit_service.emit_security_event(
            db,
            organization_id=key.organization_id,
            event_type="WEBHOOK_ENDPOINT_CREATED",
            actor_type=audit_service.ActorType.SYSTEM,
            actor_id=key.prefix,
            payload={
                "endpoint_id": str(endpoint.id),
                "events": body.events,
                # The URL host is an identifier; scheme+host only — never
                # the full URL with any potential credential material.
                "url_scheme": "https",
                "secret_hint": secret[:4],
            },
        )
    except Exception as exc:  # noqa: BLE001 — fail closed with the row
        await db.rollback()
        logger.error(
            "webhook_endpoint_audit_failed err=%s", type(exc).__name__
        )
        raise OutApiError(
            503, "AUDIT_UNAVAILABLE",
            "The endpoint could not be created atomically with its audit record.",
        ) from exc
    await db.commit()
    await db.refresh(endpoint)
    metric("webhook_endpoints_total", {"outcome": "CREATED"})

    out = _endpoint_out(endpoint)
    return WebhookEndpointCreated(
        **out.model_dump(), signing_secret=secret
    )


@router.get("", response_model=list[WebhookEndpointOut])
async def list_endpoints(
    key=Depends(require_api_scope(_WEBHOOKS_MANAGE_SCOPE)),
    db: AsyncSession = Depends(get_db),
):
    rows = (
        await db.execute(
            select(OutboundWebhookEndpoint)
            .where(OutboundWebhookEndpoint.organization_id == key.organization_id)
            .order_by(OutboundWebhookEndpoint.created_at.desc())
            .limit(200)
        )
    ).scalars().all()
    return [_endpoint_out(r) for r in rows]


@router.get("/{endpoint_id}", response_model=WebhookEndpointOut)
async def get_endpoint(
    endpoint_id: UUID,
    key=Depends(require_api_scope(_WEBHOOKS_MANAGE_SCOPE)),
    db: AsyncSession = Depends(get_db),
):
    row = await _owned_endpoint(db, endpoint_id, key.organization_id)
    return _endpoint_out(row)


@router.patch("/{endpoint_id}", response_model=WebhookEndpointOut)
async def update_endpoint(
    endpoint_id: UUID,
    body: WebhookEndpointUpdate,
    key=Depends(require_api_scope(_WEBHOOKS_MANAGE_SCOPE)),
    db: AsyncSession = Depends(get_db),
):
    """Update subscribed events / description. The URL is IMMUTABLE by
    design: changing the destination of a live receiver is a rotation,
    which is done by creating a new endpoint and disabling this one
    (audited), never by in-place rewrite."""
    row = await _owned_endpoint(db, endpoint_id, key.organization_id)
    if body.events is not None:
        row.events = body.events
    if body.description is not None:
        row.description = body.description
    row.updated_at = utcnow()
    await db.flush()
    try:
        await audit_service.emit_security_event(
            db,
            organization_id=key.organization_id,
            event_type="WEBHOOK_ENDPOINT_UPDATED",
            actor_type=audit_service.ActorType.SYSTEM,
            actor_id=key.prefix,
            payload={
                "endpoint_id": str(row.id),
                "events": list(row.events or []),
            },
        )
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        raise OutApiError(
            503, "AUDIT_UNAVAILABLE",
            "The update could not be committed atomically with its audit record.",
        ) from exc
    await db.commit()
    await db.refresh(row)
    return _endpoint_out(row)


@router.post("/{endpoint_id}/disable", response_model=WebhookEndpointOut)
async def disable_endpoint(
    endpoint_id: UUID,
    key=Depends(require_api_scope(_WEBHOOKS_MANAGE_SCOPE)),
    db: AsyncSession = Depends(get_db),
):
    """Disable a receiver. New events are not fanned out to it; deliveries
    already in flight dead-letter with ENDPOINT_DISABLED (audited)."""
    row = await _owned_endpoint(db, endpoint_id, key.organization_id)
    if row.status != "DISABLED":
        row.status = "DISABLED"
        row.disabled_at = utcnow()
        row.updated_at = utcnow()
        await db.flush()
        try:
            await audit_service.emit_security_event(
                db,
                organization_id=key.organization_id,
                event_type="WEBHOOK_ENDPOINT_DISABLED",
                actor_type=audit_service.ActorType.SYSTEM,
                actor_id=key.prefix,
                payload={"endpoint_id": str(row.id)},
            )
        except Exception as exc:  # noqa: BLE001
            await db.rollback()
            raise OutApiError(
                503, "AUDIT_UNAVAILABLE",
                "The disable could not be committed atomically with its audit record.",
            ) from exc
        await db.commit()
        await db.refresh(row)
    return _endpoint_out(row)


@router.post("/{endpoint_id}/deliveries/{delivery_id}/replay",
             response_model=WebhookDeliveryOut)
async def replay_delivery(
    endpoint_id: UUID,
    delivery_id: UUID,
    key=Depends(require_api_scope(_WEBHOOKS_MANAGE_SCOPE)),
    db: AsyncSession = Depends(get_db),
):
    """Re-enqueue ONE delivery. The delivery_id is STABLE: a replay
    reuses the SAME row and the SAME wire delivery_id — it can never
    mint a duplicate logical event."""
    endpoint = await _owned_endpoint(db, endpoint_id, key.organization_id)
    row = (
        await db.execute(
            select(OutboundWebhookDelivery).where(
                OutboundWebhookDelivery.id == delivery_id,
                OutboundWebhookDelivery.organization_id == key.organization_id,
                OutboundWebhookDelivery.endpoint_id == endpoint.id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise OutApiError(
            404, "WEBHOOK_DELIVERY_NOT_FOUND",
            "No such delivery in this organization.",
        )
    if row.state not in ("DELIVERED", "DEAD_LETTER"):
        raise OutApiError(
            409, "WEBHOOK_DELIVERY_IN_FLIGHT",
            "Only terminal deliveries can be replayed.",
        )
    if endpoint.status != "ACTIVE":
        raise OutApiError(
            409, "WEBHOOK_ENDPOINT_DISABLED",
            "The endpoint is disabled; enable a new endpoint to receive events.",
        )
    row.state = "RETRYING"
    row.next_attempt_at = utcnow()
    row.updated_at = utcnow()
    await db.flush()
    try:
        from app.worker import enqueue_outbound_webhook_delivery
        enqueue_outbound_webhook_delivery(str(row.id), delay_seconds=0)
    except Exception as exc:  # noqa: BLE001 — honest state, loud log
        logger.error(
            "webhook_replay_enqueue_failed delivery=%s err=%s",
            row.delivery_id, type(exc).__name__,
        )
    await db.commit()
    await db.refresh(row)
    return _delivery_out(row)


def _delivery_out(row: OutboundWebhookDelivery) -> WebhookDeliveryOut:
    return WebhookDeliveryOut(
        id=str(row.id),
        endpoint_id=str(row.endpoint_id),
        event_type=row.event_type,
        delivery_id=row.delivery_id,
        state=row.state,
        attempt=int(row.attempt or 0),
        last_http_status=row.last_http_status,
        last_error=row.last_error,
        created_at=_iso(row.created_at),
        delivered_at=_iso(row.delivered_at),
        dead_lettered_at=_iso(row.dead_lettered_at),
    )


@router.get("/{endpoint_id}/deliveries", response_model=list[WebhookDeliveryOut])
async def list_deliveries(
    endpoint_id: UUID,
    state: Optional[str] = Query(default=None, max_length=16),
    limit: int = Query(default=50, ge=1, le=200),
    key=Depends(require_api_scope(_WEBHOOKS_MANAGE_SCOPE)),
    db: AsyncSession = Depends(get_db),
):
    await _owned_endpoint(db, endpoint_id, key.organization_id)
    q = (
        select(OutboundWebhookDelivery)
        .where(
            OutboundWebhookDelivery.organization_id == key.organization_id,
            OutboundWebhookDelivery.endpoint_id == endpoint_id,
        )
        .order_by(OutboundWebhookDelivery.created_at.desc())
        .limit(limit)
    )
    if state:
        allowed = {"PENDING", "DELIVERING", "DELIVERED", "RETRYING",
                   "FAILED", "DEAD_LETTER"}
        normalized = state.strip().upper()
        if normalized not in allowed:
            raise OutApiError(
                400, "INVALID_FILTER", "Unsupported state filter.",
                {"allowed": sorted(allowed)},
            )
        q = q.where(OutboundWebhookDelivery.state == normalized)
    rows = (await db.execute(q)).scalars().all()
    return [_delivery_out(r) for r in rows]
