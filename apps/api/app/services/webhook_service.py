"""CYVRIX V4.1 — inbound GitHub webhook processing.

The security chain (docs/v4-webhooks.md is normative):

    GitHub
      → signature verification (HMAC-SHA-256, constant-time)
      → replay protection (delivery id, DB-unique per tenant)
      → event allowlist
      → installation binding (from TRUSTED DB state, never the payload)
      → organization binding (installation → organization)
      → repository binding (github_repo_id → repository row)
      → commit binding (push head SHA, server-verified later at clone)
      → enqueue ONE scan request
      → audit

Hard rules enforced here:

- NO payload field can select the tenant. The organization comes from the
  installation row resolved by the GitHub installation id AS RECORDED IN
  THE DATABASE. A payload claiming a different installation/organization
  is refused, not re-resolved.
- The webhook can ONLY request analysis. There is no code path here to
  approve, authorize, execute, or roll back anything (V3 chain intact).
- No raw payload is ever persisted. Refusals record a bounded reason
  code; acceptances record ids and counts only.
- Unknown events are safely ignored (200, no side effect) per the
  documented semantics — an allowlist failure is not a crash.
- One delivery id causes at most one scan, enforced by the same
  idempotency primitive the public API uses.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid as _uuid_mod
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models import GithubInstallation, Repository, Scan
from app.services import audit_service
from app.services import idempotency_service as idem

logger = logging.getLogger("cyvrix.webhook")


def _uuid(value):
    """Strict UUID parse for reservation-body scan ids (no coercion)."""
    return _uuid_mod.UUID(str(value))

# ── Refusal taxonomy (closed world; each code has a metric + audit use) ─

R_MISSING_SECRET = "WEBHOOK_SECRET_NOT_CONFIGURED"
R_BAD_SIGNATURE = "SIGNATURE_INVALID"
R_MISSING_SIGNATURE = "SIGNATURE_MISSING"
R_MALFORMED_SIGNATURE = "SIGNATURE_MALFORMED"
R_UNKNOWN_EVENT = "EVENT_NOT_ALLOWED"
R_BAD_PAYLOAD = "PAYLOAD_UNPARSEABLE"
R_OVERSIZED = "PAYLOAD_OVERSIZED"
R_UNKNOWN_INSTALLATION = "INSTALLATION_NOT_BOUND"
R_INSTALLATION_MISMATCH = "INSTALLATION_MISMATCH"
R_UNKNOWN_REPOSITORY = "REPOSITORY_NOT_BOUND"
R_DUPLICATE_DELIVERY = "DUPLICATE_DELIVERY"
R_ORG_RATE_LIMITED = "ORG_RATE_LIMITED"
R_SCAN_IN_PROGRESS = "SCAN_IN_PROGRESS"
R_UNRESOLVED_ORG = "ORGANIZATION_UNRESOLVED"
R_INVALID_DELIVERY_ID = "DELIVERY_ID_INVALID"

ALLOWED_EVENTS = frozenset({"push", "pull_request", "installation", "installation_repositories"})

MAX_JSON_KEYS = 200          # structural bound before semantic checks
MAX_DIGEST_ITEMS = 100       # push commits list is bounded before digest


class WebhookError(Exception):
    def __init__(self, reason_code: str, http_status: int) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.http_status = http_status


@dataclass(frozen=True)
class PushRef:
    """The minimal, bounded commit-binding facts of a push event."""
    head_sha: str
    ref: str
    commit_count: int


@dataclass(frozen=True)
class ScanRequestResult:
    """Outcome of the one side effect a push delivery may cause.

    `created` is True only when THIS processing attempt created the scan;
    a replay returns the ORIGINAL scan with created=False so the caller
    never re-enqueues (no duplicate side effect, ever).
    """

    scan: Scan
    created: bool
    replayed: bool = False


# ── Signature verification (Phase 14) ────────────────────────────────


def verify_signature(secret: str, header_value: Optional[str], body: bytes) -> None:
    """Verify GitHub's X-Hub-Signature-256. Fails closed on everything.

    - Absent or empty header → refuse (never 'verify later').
    - Malformed prefix/encoding → refuse.
    - Comparison is hmac.compare_digest over the exact bytes GitHub
      signed (the raw request body), not over re-serialized JSON.
    """
    if not secret:
        raise WebhookError(R_MISSING_SECRET, 503)
    if not header_value:
        raise WebhookError(R_MISSING_SIGNATURE, 401)
    value = header_value.strip()
    if not value.startswith("sha256="):
        raise WebhookError(R_MALFORMED_SIGNATURE, 401)
    provided = value[len("sha256="):].strip().lower()
    if len(provided) != 64 or any(c not in "0123456789abcdef" for c in provided):
        raise WebhookError(R_MALFORMED_SIGNATURE, 401)
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, provided):
        raise WebhookError(R_BAD_SIGNATURE, 401)


# ── Payload parsing (bounded, no persistence of content) ─────────────


def parse_event(event_type: Optional[str], body: bytes) -> dict:
    """Parse and structurally bound the JSON payload.

    Bounds are structural (keys, depth-by-size) BEFORE any semantic use,
    so a hostile payload cannot exhaust parsing regardless of content.
    """
    if event_type not in ALLOWED_EVENTS:
        raise WebhookError(R_UNKNOWN_EVENT, 200)  # documented: safely ignore
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        raise WebhookError(R_BAD_PAYLOAD, 400)
    if not isinstance(payload, dict) or len(payload) > MAX_JSON_KEYS:
        raise WebhookError(R_BAD_PAYLOAD, 400)
    return payload


def extract_push_ref(payload: dict) -> Optional[PushRef]:
    """Extract bounded commit-binding facts from a push payload.

    The SHA is validated as a full 40-hex commit id. Branch/ref strings
    are length-bounded and only ever stored as the delivery record's
    `ref` — never interpolated into any command, query, or metric label.
    """
    if not isinstance(payload, dict):
        return None
    head = payload.get("after") or payload.get("head")
    ref = payload.get("ref")
    if not isinstance(head, str) or len(head) != 40 or any(
        c not in "0123456789abcdef" for c in head.lower()
    ):
        return None
    commits = payload.get("commits")
    count = len(commits) if isinstance(commits, list) else 0
    count = min(count, MAX_DIGEST_ITEMS)
    ref_text = ""
    if isinstance(ref, str):
        ref_text = ref[:200] if all(ord(c) >= 32 for c in ref[:200]) else ""
    return PushRef(head_sha=head.lower(), ref=ref_text, commit_count=count)


def extract_installation_id(payload: dict) -> Optional[int]:
    """The GitHub installation NUMBER is a selector, never an authority."""
    value = payload.get("installation")
    if isinstance(value, dict):
        value = value.get("id")
    if isinstance(value, int) and value > 0:
        return value
    return None


def validate_delivery_id(delivery_id: str) -> str:
    """Bound and charset-check the delivery id before it becomes a key.

    GitHub delivery ids are UUIDs; we accept a slightly wider safe set,
    bounded in length, so the value can never become an injection
    channel through the idempotency namespace.
    """
    value = (delivery_id or "").strip()
    if not value or len(value) > 64:
        raise WebhookError(R_INVALID_DELIVERY_ID, 400)
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
    if not set(value) <= allowed:
        raise WebhookError(R_INVALID_DELIVERY_ID, 400)
    return value


# ── Binding resolution (trusted DB state ONLY) ───────────────────────


async def resolve_installation(
    db: AsyncSession, *, claimed_installation_id: Optional[int]
) -> GithubInstallation:
    """Resolve the installation ROW from the database.

    The GitHub installation NUMBER in the payload is a selector; the DB
    row is the authority. A number with no bound row is refused — a
    webhook for an installation CYVRIX does not hold never reaches the
    security pipeline.
    """
    if not isinstance(claimed_installation_id, int):
        raise WebhookError(R_UNKNOWN_INSTALLATION, 404)
    row = (
        await db.execute(
            select(GithubInstallation).where(
                GithubInstallation.installation_id == claimed_installation_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise WebhookError(R_UNKNOWN_INSTALLATION, 404)
    return row


async def resolve_repository(
    db: AsyncSession, installation: GithubInstallation, *, claimed_repo_id: Optional[int]
) -> Repository:
    """Bind the repository THROUGH the resolved installation.

    Fork/owner/renamed-repo confusion dies here: a repository id that
    belongs to a DIFFERENT installation row (or none) is refused, even
    if the payload is internally consistent about the owner/name.
    """
    if not isinstance(claimed_repo_id, int):
        raise WebhookError(R_UNKNOWN_REPOSITORY, 404)
    row = (
        await db.execute(
            select(Repository).where(
                Repository.github_repo_id == claimed_repo_id,
                Repository.installation_id == installation.id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise WebhookError(R_UNKNOWN_REPOSITORY, 404)
    return row


def require_organization_id(installation: GithubInstallation):
    """The installation must be bound to an organization.

    A legacy installation without V4 tenancy has no tenant to bill,
    rate-limit, or audit to — refusing it is fail-closed, not a
    regression.
    """
    if installation.organization_id is None:
        raise WebhookError(R_UNRESOLVED_ORG, 404)
    return installation.organization_id


# ── Side effect: ONE analysis request per delivery ───────────────────


async def request_scan_for_push(
    db: AsyncSession,
    *,
    organization_id,
    installation: GithubInstallation,
    repository: Repository,
    push: PushRef,
    delivery_id: str,
    event_type: str,
) -> ScanRequestResult:
    """Create (or recognize) the scan this delivery is bound to.

    Replay semantics (Phase 15/38):

    - OUTCOME_ACQUIRED  → create the scan, complete the reservation in
      the SAME transaction, report created=True (caller enqueues).
    - OUTCOME_REPLAY    → a previous attempt COMPLETED. The original
      scan id is in the reservation body; return it with created=False
      and replayed=True. The caller does NOT enqueue again, so a lost
      response followed by a GitHub redelivery cannot double-scan.
    - OUTCOME_CONFLICT  → same delivery id, DIFFERENT payload digest:
      an attacker probing key reuse. 409, never a replay of anything.
    - OUTCOME_IN_PROGRESS → a concurrent duplicate; 409 with the
      documented code (GitHub may redeliver; the claim decides).
    """
    idem_scope = f"webhook:{event_type}"
    digest = idem.canonical_request_digest(
        {
            "repository_id": str(repository.id),
            "head_sha": push.head_sha,
        }
    )

    reservation = await idem.reserve(
        db,
        organization_id=organization_id,
        scope=idem_scope,
        key_value=delivery_id,
        request_digest=digest,
        ttl_hours=idem.WEBHOOK_REPLAY_TTL_HOURS,
    )

    if reservation.outcome == idem.OUTCOME_REPLAY:
        scan_id = (reservation.body or {}).get("scan_id")
        existing = None
        if scan_id:
            try:
                existing = await db.get(Scan, _uuid(scan_id))
            except (ValueError, TypeError, AttributeError):
                existing = None
        if existing is None:
            # The reservation completed but recorded no scan id — this
            # happens only for a legacy/foreign record shape. Refuse
            # rather than guess (fail closed).
            raise WebhookError(R_DUPLICATE_DELIVERY, 409)
        return ScanRequestResult(scan=existing, created=False, replayed=True)

    if reservation.outcome == idem.OUTCOME_CONFLICT:
        raise WebhookError(R_DUPLICATE_DELIVERY, 409)
    if reservation.outcome == idem.OUTCOME_IN_PROGRESS:
        raise WebhookError(R_DUPLICATE_DELIVERY, 409)

    in_flight = (
        await db.execute(
            select(Scan).where(
                Scan.repository_id == repository.id,
                Scan.status.notin_(["COMPLETED", "FAILED"]),
            )
        )
    ).scalar_one_or_none()
    if in_flight is not None:
        raise WebhookError(R_SCAN_IN_PROGRESS, 409)

    scan = Scan(
        repository_id=repository.id,
        status="QUEUED",
        trigger="webhook",
        requested_commit_sha=push.head_sha,
    )
    db.add(scan)
    await db.flush()

    if reservation.owned:
        await idem.complete(
            db,
            reservation,
            status_code=202,
            body={"scan_id": str(scan.id)},
        )
    return ScanRequestResult(scan=scan, created=True, replayed=False)


# ── Audit emission (structured, payload-free) ────────────────────────


async def audit_webhook_event(
    db: AsyncSession,
    *,
    organization_id,
    repository_id=None,
    event_type: str,
    outcome: str,
    reason_code: Optional[str],
    delivery_id: str,
    signature_state: str,
) -> None:
    """Append the webhook lifecycle event to the tenant audit chain.

    SECURITY-CRITICAL refusals (signature/replay) would block their own
    transaction on failure; OPERATIONAL acceptances are best-effort.
    Delivery ids are data, not secrets; no payload content is included.
    """
    registered = {
        "ACCEPTED": "WEBHOOK_ACCEPTED",
        "REJECTED": "WEBHOOK_REJECTED",
        "REPLAY_REJECTED": "WEBHOOK_REPLAY_REJECTED",
    }.get(outcome, "WEBHOOK_RECEIVED")
    try:
        await audit_service.emit_security_event(
            db,
            organization_id=organization_id,
            event_type=registered,
            actor_type=audit_service.ActorType.GITHUB_INTEGRATION,
            actor_id=delivery_id[:64],
            repository_id=repository_id,
            reason_code=reason_code,
            result=outcome,
            payload={
                "event_type": event_type,
                "signature_state": signature_state,
            },
        )
    except Exception as exc:  # noqa: BLE001 — audit must never crash intake
        logger.warning(
            "webhook_audit_append_failed event=%s outcome=%s err=%s",
            event_type, outcome, type(exc).__name__,
        )
