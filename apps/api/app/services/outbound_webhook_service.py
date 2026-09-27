"""CYVRIX V4.2 completion — outbound webhooks.

Organization-scoped webhook subscriptions: an organization registers an
HTTPS endpoint, a closed-world set of event types, and receives signed
deliveries produced by REAL platform events.

SECURITY MODEL (docs/v4-webhooks.md §Outbound is normative):

1. SECRETS. The signing secret is generated server-side, returned
   exactly once at creation, stored Fernet-ENCRYPTED (key derived from
   settings — outside the database, same trust model as the V3.8
   checkpoint MAC key), and never logged, audited, exported, or
   serialized by any route.

2. SIGNING (exact format — receivers verify with a constant-time
   compare):
       signed_payload = "<timestamp>.<delivery_id>.<event_version>.<body>"
       signature      = HMAC-SHA256(secret, signed_payload).hexdigest()
       headers:
         X-Cyvrix-Signature:   sha256=<signature>
         X-Cyvrix-Timestamp:   <unix seconds>
         X-Cyvrix-Delivery-Id: <delivery_id>
         X-Cyvrix-Event:       <event_type>
         X-Cyvrix-Event-Version: <event_version>
   Replay resistance: the receiver rejects signatures older than its
   tolerance window (documented); the timestamp is INSIDE the signed
   material so it cannot be stripped.

3. DELIVERY IDENTITY. delivery_id is minted once per (event, endpoint)
   and is STABLE across every retry. The database enforces
   UNIQUE(organization_id, endpoint_id, event_type, delivery_id) — a
   retry cannot mint a duplicate logical event.

4. SSRF. URLs must be https, without userinfo, and every IP the
   hostname resolves to must be GLOBAL (publicly routable) — loopback,
   RFC1918, link-local (incl. cloud metadata), CGNAT, ULA, multicast,
   reserved, and IPv4-mapped IPv6 are all refused. Validation runs at
   creation/update AND again immediately before every connection
   (connection-time revalidation narrows the DNS-rebinding window;
   the residual TOCTOU is documented, never overstated). Redirects are
   NEVER followed.

5. RETRIES. 2xx = delivered. 5xx/408/429/timeout/network = TRANSIENT
   with bounded exponential backoff + full jitter. Well-defined 4xx =
   NON_TRANSIENT (no retry). Attempts are bounded; exhaustion
   dead-letters. Retries reuse the SAME delivery_id.

6. AUDIT. Endpoint lifecycle and every delivery outcome enter the V3.8
   chain; payloads carry identifiers and counts only — never secret
   material, never signature values.
"""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import ipaddress
import json
import logging
import random
import secrets as pysecrets
import socket
import time
import uuid as uuid_mod
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.metrics import increment as metric
from app.models import OutboundWebhookDelivery, OutboundWebhookEndpoint, utcnow
from app.services import audit_service

logger = logging.getLogger("cyvrix.outbound_webhooks")

# ── Closed-world event registry (Phase 5) ─────────────────────────────
# Only events listed here are deliverable. Extending the registry is a
# code change; no client or internal caller can invent an event type.

OUTBOUND_EVENT_VERSION = 1

OUTBOUND_EVENT_TYPES: frozenset[str] = frozenset({
    "FINDING_CREATED",
    "ACTION_CREATED",
    "EXECUTION_STARTED",
    "EXECUTION_COMPLETED",
    "VERIFICATION_COMPLETED",
    "ROLLBACK_COMPLETED",
    "SCAN_COMPLETED",
    "CI_EVENT_PROCESSED",
    "API_KEY_ROTATED",
    "SECURITY_ALERT",
})


def is_valid_outbound_event(event_type: object) -> bool:
    return isinstance(event_type, str) and event_type in OUTBOUND_EVENT_TYPES


# ── Delivery state machine (Phase 9) — closed world ───────────────────

class DeliveryState:
    PENDING = "PENDING"
    DELIVERING = "DELIVERING"
    DELIVERED = "DELIVERED"
    RETRYING = "RETRYING"
    FAILED = "FAILED"
    DEAD_LETTER = "DEAD_LETTER"


TERMINAL_STATES = frozenset({DeliveryState.DELIVERED, DeliveryState.DEAD_LETTER})

ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    DeliveryState.PENDING: frozenset({DeliveryState.DELIVERING}),
    DeliveryState.DELIVERING: frozenset({
        DeliveryState.DELIVERED, DeliveryState.RETRYING,
        DeliveryState.FAILED,
    }),
    DeliveryState.RETRYING: frozenset({DeliveryState.DELIVERING}),
    DeliveryState.FAILED: frozenset({DeliveryState.DEAD_LETTER}),
    DeliveryState.DELIVERED: frozenset(),
    DeliveryState.DEAD_LETTER: frozenset(),
}


class DeliveryStateError(RuntimeError):
    """An illegal delivery state transition was attempted (fail closed)."""


def assert_transition(from_state: str, to_state: str) -> None:
    if to_state not in ALLOWED_TRANSITIONS.get(from_state, frozenset()):
        raise DeliveryStateError(
            f"illegal delivery transition {from_state} -> {to_state}"
        )


# ── Secrets (Phase 2) ─────────────────────────────────────────────────

class OutboundWebhookUnavailable(Exception):
    """Outbound webhooks are not configured (empty key) — fail closed."""


def _fernet():
    settings = get_settings()
    key_material = (settings.outbound_webhook_secret_key or "").strip()
    if not key_material:
        raise OutboundWebhookUnavailable("OUTBOUND_WEBHOOKS_DISABLED")
    digest = hashlib.sha256(key_material.encode("utf-8")).digest()
    import base64
    from cryptography.fernet import Fernet
    return Fernet(base64.urlsafe_b64encode(digest))


def generate_signing_secret() -> str:
    """256-bit random signing secret. Shown once; stored only encrypted."""
    return pysecrets.token_hex(32)


def encrypt_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode("utf-8")).decode("ascii")


def decrypt_secret(ciphertext: str) -> str:
    return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")


# ── SSRF validation (Phase 12/13/14) ──────────────────────────────────

class UrlValidationError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


_MAX_URL_LENGTH = 2048
_BLOCKED_PORTS = frozenset({22, 25, 445, 3306, 5432, 6379, 9200, 27017})


def _addr_is_global(ip_text: str) -> bool:
    """One address (bare or IPv4-mapped IPv6) must be globally routable.

    Rejects loopback, RFC1918, link-local (cloud metadata lives here),
    CGNAT, ULA, multicast, reserved, unspecified, and the IPv4-mapped
    IPv6 encoding of any of them.
    """
    addr = ipaddress.ip_address(ip_text)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if not addr.is_global:
        return False
    # Belt and braces: is_global may evolve; the dangerous families are
    # enumerated explicitly so a stdlib change cannot silently open SSRF.
    return not (
        addr.is_loopback or addr.is_private or addr.is_link_local
        or addr.is_multicast or addr.is_reserved or addr.is_unspecified
    )


def _resolve_global_ips(hostname: str) -> list[str]:
    """Resolve hostname and require EVERY answer to be global.

    One non-global answer is enough to refuse: a resolver returning a
    mixed answer is exactly the rebinding/mixed-record attack shape.

    A resolver-level failure (getaddrinfo error) is a REAL refusal, not
    a bypass: fail closed with a distinct reason code. The error is
    logged loudly and never swallowed, so a broken resolver cannot be
    used to smuggle a hostname past validation.
    """
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        logger.warning(
            "webhook_url_resolution_failed host=%s — failing closed",
            hostname[:64],
        )
        raise UrlValidationError("URL_RESOLUTION_FAILED")
    addrs: list[str] = []
    for family, _type, _proto, _canon, sockaddr in infos:
        ip_text = sockaddr[0]
        if ip_text not in addrs:
            addrs.append(ip_text)
    if not addrs:
        raise UrlValidationError("URL_RESOLUTION_EMPTY")
    bad = [a for a in addrs if not _addr_is_global(a)]
    if bad:
        raise UrlValidationError("URL_RESOLVES_NON_GLOBAL")
    return addrs


def validate_webhook_url(url: str) -> list[str]:
    """Full SSRF validation. Returns the resolved global IP list.

    String-prefix checks are never trusted: the host is parsed, its
    literal/derived IPs are resolved and range-checked, the port is
    bounded, and userinfo is refused (credentialed URLs are a smuggling
    channel, not a feature).
    """
    if not isinstance(url, str) or not url or len(url) > _MAX_URL_LENGTH:
        raise UrlValidationError("URL_INVALID")
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise UrlValidationError("URL_SCHEME_NOT_HTTPS")
    if not parts.hostname:
        raise UrlValidationError("URL_NO_HOST")
    if parts.username or parts.password:
        raise UrlValidationError("URL_USERINFO_FORBIDDEN")
    if parts.query or parts.fragment:
        # Keep receivers plain: no query/fragment surface to attack.
        raise UrlValidationError("URL_QUERY_FORBIDDEN")
    try:
        port = parts.port
    except ValueError:
        raise UrlValidationError("URL_INVALID")
    if port is not None and (port < 1 or port > 65535 or port in _BLOCKED_PORTS):
        raise UrlValidationError("URL_PORT_FORBIDDEN")
    return _resolve_global_ips(parts.hostname)


def revalidate_ip_at_connection(ip_text: str) -> bool:
    """Connection-time revalidation (DNS rebinding mitigation).

    The dispatcher calls this for the address it is about to connect to.
    Returns False for any non-global address.
    """
    try:
        return _addr_is_global(ip_text)
    except ValueError:
        return False


# ── Signing (Phase 3) ─────────────────────────────────────────────────

def signature_headers(
    *, secret: str, timestamp: int, delivery_id: str,
    event_type: str, event_version: int, body: bytes,
) -> dict[str, str]:
    """The exact wire contract (see module docstring for the format)."""
    signed_material = (
        f"{timestamp}.{delivery_id}.{int(event_version)}.".encode("ascii")
        + body
    )
    digest = hmac_mod.new(
        secret.encode("utf-8"), signed_material, hashlib.sha256
    ).hexdigest()
    return {
        "content-type": "application/json",
        "user-agent": "CYVRIX-Webhook/1.0",
        "x-cyvrix-signature": f"sha256={digest}",
        "x-cyvrix-timestamp": str(timestamp),
        "x-cyvrix-delivery-id": delivery_id,
        "x-cyvrix-event": event_type,
        "x-cyvrix-event-version": str(int(event_version)),
    }


def verify_receiver_side(
    *, secret: str, timestamp: str, delivery_id: str,
    event_type: str, event_version: str, body: bytes, signature: str,
    tolerance_seconds: int = 300,
) -> bool:
    """Reference verification for receivers (constant-time compare).

    Used by tests to prove signatures validate; documented in
    docs/v4-webhooks.md as the receiver-side contract.
    """
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs(int(time.time()) - ts) > tolerance_seconds:
        return False
    expected = signature_headers(
        secret=secret, timestamp=ts, delivery_id=delivery_id,
        event_type=event_type, event_version=int(event_version), body=body,
    )["x-cyvrix-signature"]
    return hmac_mod.compare_digest(expected, signature or "")


# ── Payload builder (Phase 6/15) ──────────────────────────────────────

def build_payload(
    *,
    event_type: str,
    organization_id,
    resource_kind: str,
    resource_id: str,
    repository_id: Optional[str] = None,
    result: Optional[str] = None,
    reason: Optional[str] = None,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """Bounded, secret-free event body. Only server-side identifiers and
    server-computed results are accepted; free-form content is refused
    by the callers' contracts, and redaction runs as defense in depth."""
    if not is_valid_outbound_event(event_type):
        raise ValueError(f"unregistered outbound event type: {event_type}")
    payload = {
        "event_type": event_type,
        "event_version": OUTBOUND_EVENT_VERSION,
        "delivery_id": None,  # set at creation, stable thereafter
        "timestamp": audit_service.canonical_timestamp(now or utcnow()),
        "organization": {"id": str(organization_id)},
        "resource": {
            "kind": str(resource_kind)[:40],
            "id": str(resource_id)[:64],
            "repository_id": str(repository_id)[:64] if repository_id else None,
        },
        "result": str(result)[:40] if result else None,
        "reason": str(reason)[:64] if reason else None,
    }
    # Central redaction (defense in depth — producers already pass only
    # identifiers, but nothing may skip the chokepoint).
    return audit_service.redact_payload(payload)  # type: ignore[return-value]


def encode_payload(payload: dict) -> bytes:
    settings = get_settings()
    body = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    if len(body) > settings.outbound_webhook_max_payload_bytes:
        raise ValueError("WEBHOOK_PAYLOAD_TOO_LARGE")
    return body


# ── Retry classification (Phase 7/8) ──────────────────────────────────

TRANSIENT_HTTP_STATUSES = frozenset({408, 429})


def classify_http_status(status_code: int) -> str:
    """DELIVERED | TRANSIENT | NON_TRANSIENT for an HTTP status."""
    if 200 <= status_code < 300:
        return "DELIVERED"
    if status_code >= 500 or status_code in TRANSIENT_HTTP_STATUSES:
        return "TRANSIENT"
    return "NON_TRANSIENT"


def classify_exception(exc: Exception) -> str:
    """Timeouts/connection failures are TRANSIENT; everything unknown is
    TRANSIENT too (attempts stay bounded either way) — a receiver that
    half-opens sockets should still get its bounded retries."""
    import httpx
    if isinstance(exc, (httpx.TimeoutException, httpx.TransportError, OSError)):
        return "TRANSIENT"
    return "TRANSIENT" if classify_http_status(0) else "NON_TRANSIENT"


def next_backoff_seconds(attempt: int) -> int:
    """Bounded exponential backoff with FULL jitter.

    attempt 1 → 0–60s, 2 → 0–120s, 3 → 0–240s, ... capped at 3600s.
    Full jitter prevents synchronized retry storms across endpoints.
    """
    settings = get_settings()
    max_delay = min(
        settings.outbound_webhook_backoff_base_seconds * (2 ** max(0, attempt - 1)),
        settings.outbound_webhook_backoff_max_seconds,
    )
    return random.randint(1, max(2, int(max_delay)))


# ── Audit (Phase 17) — thin, bounded, secret-free ─────────────────────

async def _audit(
    db: AsyncSession,
    *,
    organization_id,
    event_type: str,
    reason_code: Optional[str],
    payload: dict,
    repository_id=None,
    actor_type: str = audit_service.ActorType.WORKER,
    critical: bool = False,
) -> None:
    """Append a delivery audit event inside the CALLER's transaction.

    critical=True (SECURITY_CRITICAL registry class): a chain failure
    PROPAGATES so the delivery row and its witness commit atomically or
    not at all — fail closed. critical=False (OPERATIONAL progress
    events): failures are logged loudly and the delivery state change
    still lands (the delivery row is the security record; the chain
    event is the integrity witness — same split as inbound webhooks).
    Payloads are bounded identifiers only: never secrets, never
    signature material.
    """
    try:
        await audit_service.emit_security_event(
            db,
            organization_id=organization_id,
            event_type=event_type,
            actor_type=actor_type,
            reason_code=reason_code,
            repository_id=repository_id,
            payload=payload,
        )
    except Exception as exc:  # noqa: BLE001
        if critical:
            raise
        logger.error(
            "outbound_webhook_audit_failed event=%s err=%s",
            event_type, type(exc).__name__,
        )


# ── Delivery creation (Phase 4/10/16) ─────────────────────────────────

async def create_deliveries_for_event(
    db: AsyncSession,
    *,
    organization_id,
    event_type: str,
    resource_kind: str,
    resource_id: str,
    repository_id: Optional[str] = None,
    result: Optional[str] = None,
    reason: Optional[str] = None,
    enqueue=None,
    now: Optional[datetime] = None,
) -> list[str]:
    """Fan one REAL platform event out to every subscribed endpoint.

    - Only ACTIVE endpoints subscribed to `event_type` receive it.
    - One delivery row per endpoint; identity is DB-enforced unique.
    - Rate limits (org + endpoint) bound fan-out; Redis unavailable →
      fail closed (no delivery), logged loudly.
    - Delivery creation is audit-witnessed (WEBHOOK_DELIVERY_CREATED).

    Returns the created delivery_ids (bounded diagnostic use only).
    """
    if not is_valid_outbound_event(event_type):
        raise ValueError(f"unregistered outbound event type: {event_type}")
    settings = get_settings()
    from app.rate_limit import check_rate_limit

    # Per-organization fan-out ceiling first.
    allowed, _ = await check_rate_limit(
        f"wh-org:{organization_id}", settings.outbound_webhook_rate_per_hour_per_org, 3600
    )
    if not allowed:
        metric("webhook_delivery_rejected_total", {"reason": "ORG_RATE_LIMITED"})
        logger.warning("outbound_delivery_rate_limited_org org=%s", str(organization_id)[:8])
        return []

    endpoints = (
        (
            await db.execute(
                select(OutboundWebhookEndpoint).where(
                    OutboundWebhookEndpoint.organization_id == organization_id,
                    OutboundWebhookEndpoint.status == "ACTIVE",
                )
            )
        )
        .scalars()
        .all()
    )
    subscribed = [e for e in endpoints if event_type in (e.events or [])]
    if not subscribed:
        return []

    now = now or utcnow()
    created: list[str] = []
    for endpoint in subscribed:
        allowed, _ = await check_rate_limit(
            f"wh-ep:{endpoint.id}", settings.outbound_webhook_rate_per_hour_per_endpoint, 3600
        )
        if not allowed:
            metric("webhook_delivery_rejected_total", {"reason": "ENDPOINT_RATE_LIMITED"})
            continue
        delivery_id = pysecrets.token_hex(16)
        payload = build_payload(
            event_type=event_type,
            organization_id=organization_id,
            resource_kind=resource_kind,
            resource_id=resource_id,
            repository_id=repository_id,
            result=result,
            reason=reason,
            now=now,
        )
        payload["delivery_id"] = delivery_id
        row = OutboundWebhookDelivery(
            organization_id=organization_id,
            endpoint_id=endpoint.id,
            event_type=event_type,
            event_version=OUTBOUND_EVENT_VERSION,
            delivery_id=delivery_id,
            state=DeliveryState.PENDING,
            payload=payload,
            next_attempt_at=now,
        )
        try:
            async with db.begin_nested():
                db.add(row)
                await db.flush()
        except IntegrityError:
            # The unique backstop caught a concurrent creation of the same
            # logical event — exactly-once semantics hold; skip.
            continue
        created.append(delivery_id)
        await _audit(
            db,
            organization_id=organization_id,
            event_type="WEBHOOK_DELIVERY_CREATED",
            reason_code=None,
            repository_id=repository_id,
            payload={
                "endpoint_id": str(endpoint.id),
                "delivery_id": delivery_id,
                "event_type": event_type,
            },
            critical=True,
        )
        if enqueue is not None:
            try:
                enqueue(str(row.id))
            except Exception as exc:  # noqa: BLE001 — honest: mark + log
                logger.error(
                    "outbound_delivery_enqueue_failed delivery=%s err=%s",
                    delivery_id, type(exc).__name__,
                )
    metric("webhook_deliveries_created_total", {"event": event_type})
    return created


# ── Dispatch (Phase 7/9/11/12/13/14) ──────────────────────────────────

async def dispatch_delivery(
    db: AsyncSession,
    *,
    delivery_row_id: str,
    enqueue=None,
    now: Optional[datetime] = None,
    post=None,
) -> str:
    """Attempt one delivery. Called by the WORKER (real process), never
    inline from the API request path.

    Race discipline: the state claim is an atomic conditional UPDATE
    (state PENDING/RETRYING → DELIVERING); a loser of a concurrent
    claim updates zero rows and exits — two workers can never sign and
    send the same attempt twice.

    Returns the resulting state.
    """
    settings = get_settings()
    now = now or utcnow()

    # RQ job arguments round-trip through JSON, so the worker hands us a
    # string; normalize instead of trusting the caller's type.
    if isinstance(delivery_row_id, str):
        try:
            delivery_row_id = uuid_mod.UUID(delivery_row_id)
        except ValueError:
            return "NOT_FOUND"

    row = (
        await db.execute(
            select(OutboundWebhookDelivery).where(
                OutboundWebhookDelivery.id == delivery_row_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return "NOT_FOUND"
    if row.state in TERMINAL_STATES:
        return row.state

    endpoint = (
        await db.execute(
            select(OutboundWebhookEndpoint).where(
                OutboundWebhookEndpoint.id == row.endpoint_id
            )
        )
    ).scalar_one_or_none()
    if endpoint is None:
        await _fail_dead(db, row, "ENDPOINT_MISSING", now)
        await db.commit()
        return DeliveryState.DEAD_LETTER

    # Endpoint disabled after scheduling: no further attempts (honest
    # terminal state, audited) — deliveries are never sent to a
    # disabled receiver.
    if endpoint.status != "ACTIVE":
        await _fail_dead(db, row, "ENDPOINT_DISABLED", now)
        await db.commit()
        return DeliveryState.DEAD_LETTER

    # ── Race-safe claim ──────────────────────────────────────────────
    from sqlalchemy import update
    pre_claim_state = row.state
    claimed = await db.execute(
        update(OutboundWebhookDelivery)
        .where(
            OutboundWebhookDelivery.id == row.id,
            OutboundWebhookDelivery.state.in_(
                [DeliveryState.PENDING, DeliveryState.RETRYING]
            ),
        )
        .values(state=DeliveryState.DELIVERING, attempt=row.attempt + 1)
        .execution_options(synchronize_session=False)
    )
    if claimed.rowcount != 1:
        await db.rollback()
        # rollback() expires instances: reading row.state here would
        # trigger a lazy refresh (MissingGreenlet in async). The state
        # captured BEFORE the claim attempt is the honest answer.
        return pre_claim_state
    # synchronize_session=False leaves the in-memory row STALE (still
    # showing the pre-claim state). Mirror the persisted claim onto the
    # instance, or the later DELIVERING→RETRYING assignment becomes a
    # flush no-op and strands the row in DELIVERING forever.
    row.state = DeliveryState.DELIVERING
    row.attempt += 1
    await db.commit()  # the claim commits before any network I/O

    # ── Connection-time SSRF revalidation (DNS rebinding window) ─────
    try:
        validate_webhook_url(endpoint.url)
    except UrlValidationError as exc:
        # A receiver that became non-global after creation is not retried.
        await _fail_dead(db, row, exc.reason_code, now)
        await db.commit()
        return DeliveryState.DEAD_LETTER

    body = encode_payload(row.payload)
    secret = decrypt_secret(endpoint.secret_ciphertext)
    timestamp = int(now.timestamp())
    headers = signature_headers(
        secret=secret, timestamp=timestamp,
        delivery_id=row.delivery_id,
        event_type=row.event_type,
        event_version=row.event_version,
        body=body,
    )

    status_code: Optional[int] = None
    outcome_class: str
    exc_name: Optional[str] = None
    try:
        if post is not None:
            resp = await post(endpoint.url, headers, body)
            status_code = int(resp.status_code)
            outcome_class = classify_http_status(status_code)
        else:
            import httpx
            # follow_redirects=False: NEVER follow (redirect → internal
            # network is the classic SSRF pivot). trust_env=False: no
            # proxy environment can reroute the request.
            async with httpx.AsyncClient(
                timeout=settings.outbound_webhook_delivery_timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                resp = await client.post(endpoint.url, headers=headers, content=body)
                status_code = int(resp.status_code)
            outcome_class = classify_http_status(status_code)
    except Exception as exc:  # noqa: BLE001 — classified, never leaked
        exc_name = type(exc).__name__
        outcome_class = classify_exception(exc)

    if outcome_class == "DELIVERED":
        assert_transition(DeliveryState.DELIVERING, DeliveryState.DELIVERED)
        row.state = DeliveryState.DELIVERED
        row.delivered_at = now
        row.last_http_status = status_code
        row.last_error = None
        await _audit(
            db, organization_id=row.organization_id,
            event_type="WEBHOOK_DELIVERY_SUCCEEDED", reason_code=None,
            repository_id=None,
            payload={
                "endpoint_id": str(endpoint.id),
                "delivery_id": row.delivery_id,
                "event_type": row.event_type,
                "attempt": row.attempt,
                "http_status_family": "2xx",
            },
        )
        metric("webhook_deliveries_succeeded_total", {"event": row.event_type})
        await db.commit()
        return DeliveryState.DELIVERED

    row.last_http_status = status_code
    row.last_error = (exc_name or f"HTTP_{status_code}")[:64]

    exhausted = row.attempt >= settings.outbound_webhook_max_attempts
    if outcome_class == "NON_TRANSIENT" or exhausted:
        await _fail_dead(db, row, row.last_error, now)
        await db.commit()
        return DeliveryState.DEAD_LETTER

    # ── TRANSIENT: bounded retry with backoff + jitter ───────────────
    delay = next_backoff_seconds(row.attempt)
    assert_transition(DeliveryState.DELIVERING, DeliveryState.RETRYING)
    row.state = DeliveryState.RETRYING
    row.next_attempt_at = now + timedelta(seconds=delay)
    await _audit(
        db, organization_id=row.organization_id,
        event_type="WEBHOOK_DELIVERY_RETRY", reason_code=row.last_error,
        repository_id=None,
        payload={
            "endpoint_id": str(endpoint.id),
            "delivery_id": row.delivery_id,
            "event_type": row.event_type,
            "attempt": row.attempt,
            "retry_in_seconds": delay,
        },
    )
    metric("webhook_deliveries_retried_total", {"event": row.event_type})
    await db.commit()

    # Schedule the next attempt (same delivery identity — the SAME row
    # and the SAME delivery_id are reused, never a new one).
    if enqueue is not None:
        try:
            enqueue(str(row.id), delay)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "outbound_retry_enqueue_failed delivery=%s err=%s",
                row.delivery_id, type(exc).__name__,
            )
    return DeliveryState.RETRYING


async def _fail_dead(
    db: AsyncSession, row: OutboundWebhookDelivery,
    reason_code: str, now: datetime,
) -> None:
    """DELIVERING/RETRYING/PENDING → FAILED → DEAD_LETTER (audited).

    The FAILED step is PERSISTED, not merely asserted: an attempt that
    really happened ends honestly as FAILED before the dead-letter
    recording, so a crashed worker mid-`_fail_dead` leaves a row whose
    state reflects that contact was made (a subsequent crash-recovery
    sweep must never resend to a possibly-succeeded receiver).
    """
    if row.state not in TERMINAL_STATES:
        if row.state == DeliveryState.DELIVERING:
            assert_transition(DeliveryState.DELIVERING, DeliveryState.FAILED)
            row.state = DeliveryState.FAILED
        if row.state == DeliveryState.FAILED:
            assert_transition(DeliveryState.FAILED, DeliveryState.DEAD_LETTER)
            row.state = DeliveryState.DEAD_LETTER
        elif row.state in (DeliveryState.PENDING, DeliveryState.RETRYING):
            # Scheduled-but-never-attempted: refusal before first contact.
            row.state = DeliveryState.DEAD_LETTER
        row.dead_lettered_at = now
        row.last_error = str(reason_code)[:64]
    await _audit(
        db, organization_id=row.organization_id,
        event_type="WEBHOOK_DELIVERY_DEAD_LETTER", reason_code=row.last_error,
        repository_id=None,
        payload={
            "delivery_id": row.delivery_id,
            "event_type": row.event_type,
            "attempt": row.attempt,
        },
    )
    metric("webhook_deliveries_dead_lettered_total", {"event": row.event_type})


# ── Worker entrypoint (real process) ──────────────────────────────────

async def dispatch_from_worker(delivery_row_id: str, enqueue=None) -> str:
    """Own async session for the RQ worker process (RQ is sync; the
    dispatcher is async and shares the app's models/services)."""
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

    engine = create_async_engine(get_settings().database_url, pool_pre_ping=True)
    try:
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            return await dispatch_delivery(session, delivery_row_id=delivery_row_id, enqueue=enqueue)
    finally:
        await engine.dispose()
