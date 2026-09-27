"""CYVRIX V4.2 completion — dedicated CI event intake (POST /api/ci/events).

A SERVICE-class route: its caller is a CI system, authenticated by a
scoped API key (scope `ci:ingest`) — deliberately NOT a user session and
NOT the general public-API write path. CI identity is its own actor type
in the V3.8 audit chain.

Chain on every request:

    authentication (hashed API key, scope ci:ingest)
      → organization (derived FROM THE KEY — never accepted from payload)
        → rate limit (per credential; bounded)
          → bounded body (64 KiB) + strict schema (extra=forbid)
            → repository resolution THROUGH trusted integration state
              (key org → installation → repository; a payload
               organization_id/repo identifier can never nominate a
               different tenant or repository)
              → idempotency: (organization, repository, event_id) is
                DB-unique; duplicates are REJECTED as ALREADY_PROCESSED
                (security-critical audit), never re-processed
              → commit binding: stored as a REQUESTED binding
                (requested_commit_sha, server-set) and VERIFIED by the
                worker against the actual clone — stale/fake commits
                fail COMMIT_MISMATCH, never analyzed silently
              → one side effect: an analysis REQUEST (scan row QUEUED)
                through the same quota + enqueue-failure semantics as
                the V4.1 public API
              → V3.8 audit: CI_EVENT_RECEIVED / ACCEPTED / REJECTED /
                REPLAYED / PROCESSING_* on the org chain

The response NEVER contains PASS. Possible results:
    ACCEPTED          the event is admitted and a scan was requested
    ALREADY_PROCESSED replay; the original outcome is restated
    COMMIT_MISMATCH   (surfaced later through scan status, not here)
    REJECTED          refused (validation, binding, quota, rate limit)
    FAILED            the intake could not be completed safely
    UNAVAILABLE       CYVRIX-side unavailability (fail-safe, never PASS)
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.metrics import increment as metric
from app.models import (
    CiEvent,
    GithubInstallation,
    Repository,
    Scan,
    utcnow,
)
from app.quota_service import consume_quota, limit_for
from app.rate_limit import check_rate_limit
from app.services import audit_service
from app.services import idempotency_service as idem
from app.services.org_auth import api_key_auth

logger = logging.getLogger("cyvrix.ci_events")
settings = get_settings()

router = APIRouter(prefix="/api/ci", tags=["ci-events"])

_COMMIT_HEX = set("0123456789abcdef")

# Bounded refusal taxonomy (allowlisted into the reason_code column).
_RC_PAYLOAD_TOO_LARGE = "CI_PAYLOAD_TOO_LARGE"
_RC_MALFORMED = "CI_MALFORMED"
_RC_VALIDATION = "CI_VALIDATION_FAILED"
_RC_REPO_MISMATCH = "CI_EVENT_REPOSITORY_MISMATCH"
_RC_RATE_LIMITED = "CI_RATE_LIMITED"
_RC_QUOTA = "CI_QUOTA_EXCEEDED"
_RC_UNAVAILABLE = "CI_UNAVAILABLE"
_RC_ENQUEUE_FAILED = "CI_ENQUEUE_FAILED"


def _result(status: str) -> dict:
    """Machine-readable result envelope. There is deliberately NO PASS:
    a security verdict exists only after server-side analysis produces
    it, and it is read through scan status, never from this intake."""
    return {"result": status}


def _ref_safe(ref: str) -> str:
    """Branches/refs are identifiers, not content: bounded charset."""
    import re
    ref = (ref or "").strip()
    if not ref:
        return ""
    if len(ref) > 200:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9/._\-]+", ref):
        return ""
    return ref


class CiEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=8, max_length=128)
    repository_full_name: str = Field(min_length=3, max_length=200)
    commit_sha: str = Field(min_length=40, max_length=40)
    ref: Optional[str] = Field(default=None, max_length=200)
    provider: str = Field(default="github", max_length=24)
    run_id: Optional[str] = Field(default=None, max_length=128)

    @field_validator("event_id")
    @classmethod
    def _event_id_chars(cls, v: str) -> str:
        import re
        if not re.fullmatch(r"[A-Za-z0-9._\-]{8,128}", v):
            raise ValueError("event_id must be [A-Za-z0-9._-]{8,128}")
        return v

    @field_validator("commit_sha")
    @classmethod
    def _sha_hex(cls, v: str) -> str:
        v = v.strip().lower()
        if len(v) != 40 or any(c not in _COMMIT_HEX for c in v):
            raise ValueError("commit_sha must be a full 40-character hex SHA")
        return v

    @field_validator("provider")
    @classmethod
    def _provider(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in ("github", "gitlab", "jenkins", "circleci"):
            raise ValueError("unsupported provider")
        return v


async def _audit_ci(
    db: AsyncSession,
    *,
    organization_id,
    event_type: str,
    reason_code=None,
    repository_id=None,
    payload=None,
    actor_id=None,
    critical: bool = False,
) -> None:
    """CI lifecycle events on the ORG chain. SECURITY-CRITICAL refusals
    (REJECTED/REPLAYED) propagate on failure (fail closed); progress
    events are best-effort and never block intake."""
    try:
        await audit_service.emit_security_event(
            db,
            organization_id=organization_id,
            event_type=event_type,
            actor_type=audit_service.ActorType.CI,
            actor_id=actor_id,
            repository_id=repository_id,
            reason_code=reason_code,
            payload=payload or {},
        )
    except Exception as exc:  # noqa: BLE001
        if critical:
            raise
        logger.error(
            "ci_event_audit_failed event=%s err=%s",
            event_type, type(exc).__name__,
        )


@router.post("/events")
async def receive_ci_event(
    request: Request,
    key=Depends(api_key_auth),
    db: AsyncSession = Depends(get_db),
):
    """Authenticated CI event intake. See module docstring for the chain."""
    metric("ci_events_total", {"outcome": "RECEIVED"})

    # ── Scope: the general API key path is not enough; CI keys must be
    # issued with the dedicated ci:ingest scope (HIGH_IMPACT: issuance
    # requires ORG_ADMIN standing, so a leaked dev key cannot invent CI
    # events). Checked here rather than require_api_scope so the audit
    # refusal carries the CI actor type.
    if not _key_has_scope(key, "ci:ingest"):
        await _refuse(
            db, key=key, organization_id=None, event_id="(absent)",
            reason_code="CI_SCOPE_REQUIRED", http_status=403,
        )
        return JSONResponse(status_code=403, content=_result("REJECTED"))

    # ── Rate limit (per credential; server-owned bound) ──────────────
    allowed, _ = await check_rate_limit(
        f"ci:{key.prefix}", settings.ci_event_rate_limit_per_hour, 3600
    )
    if not allowed:
        await _refuse(
            db, key=key, organization_id=key.organization_id,
            event_id="(absent)", reason_code=_RC_RATE_LIMITED, http_status=429,
        )
        return JSONResponse(status_code=429, content=_result("REJECTED"))

    # ── Bounded body ────────────────────────────────────────────────
    declared = request.headers.get("content-length")
    if declared and not declared.isdigit():
        await _refuse(db, key=key, organization_id=key.organization_id,
                      event_id="(absent)", reason_code=_RC_MALFORMED,
                      http_status=400)
        return JSONResponse(status_code=400, content=_result("REJECTED"))
    if declared and int(declared) > settings.ci_event_max_payload_bytes:
        await _refuse(db, key=key, organization_id=key.organization_id,
                      event_id="(absent)", reason_code=_RC_PAYLOAD_TOO_LARGE,
                      http_status=413)
        return JSONResponse(status_code=413, content=_result("REJECTED"))
    body_bytes = await request.body()
    if len(body_bytes) > settings.ci_event_max_payload_bytes:
        await _refuse(db, key=key, organization_id=key.organization_id,
                      event_id="(absent)", reason_code=_RC_PAYLOAD_TOO_LARGE,
                      http_status=413)
        return JSONResponse(status_code=413, content=_result("REJECTED"))

    # ── Strict parse (extra=forbid: no metadata smuggling channel) ──
    import json as _json
    try:
        raw = _json.loads(body_bytes.decode("utf-8"))
        body = CiEventRequest.model_validate(raw)
    except Exception:  # noqa: BLE001 — never echo attacker content
        await _refuse(db, key=key, organization_id=key.organization_id,
                      event_id="(absent)", reason_code=_RC_VALIDATION,
                      http_status=422)
        return JSONResponse(status_code=422, content=_result("REJECTED"))

    organization_id = key.organization_id
    ref = _ref_safe(body.ref or "")

    # ── Repository resolution THROUGH trusted state ─────────────────
    # The payload names the repository by full_name (data), never by
    # authority. The org comes from the KEY; the installation comes from
    # the org; the repository must belong to that installation.
    row = (
        await db.execute(
            select(Repository)
            .join(GithubInstallation,
                  Repository.installation_id == GithubInstallation.id)
            .where(
                GithubInstallation.organization_id == organization_id,
                Repository.owner + "/" + Repository.name
                == body.repository_full_name,
                Repository.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()
    if row is None:
        await _refuse(
            db, key=key, organization_id=organization_id,
            event_id=body.event_id, reason_code=_RC_REPO_MISMATCH,
            http_status=404,
        )
        return JSONResponse(status_code=404, content=_result("REJECTED"))
    repository = row

    # ── Idempotency (DB-unique backstop) ────────────────────────────
    # A replayed event is a SECURITY-CRITICAL refusal (an attacker
    # probing with a stolen credential and a stolen event id must leave
    # a record), while the honest retry of the SAME event id by the SAME
    # credential gets the original outcome restated.
    reservation: Optional[idem.Reservation] = None  # type: ignore[name-defined]
    try:
        reservation = await idem.reserve(
            db,
            organization_id=organization_id,
            scope="ci-event",
            key_value=f"{repository.id}:{body.event_id}",
            request_digest=idem.canonical_request_digest(body.model_dump()),
            api_key_prefix=key.prefix,
            ttl_hours=idem.WEBHOOK_REPLAY_TTL_HOURS,
        )
    except idem.IdempotencyError:
        reservation = None

    if reservation is not None and reservation.outcome == idem.OUTCOME_REPLAY:
        # The original ACCEPTED row already exists (DB-unique identity);
        # a replay adds NO second row — it restates the original outcome
        # and leaves a security-critical audit witness.
        await _audit_ci(
            db, organization_id=organization_id,
            event_type="CI_EVENT_REPLAYED",
            reason_code="DUPLICATE_EVENT_ID",
            repository_id=repository.id,
            payload={"event_id": body.event_id},
            actor_id=key.prefix,
            critical=True,
        )
        await db.commit()
        metric("ci_events_total", {"outcome": "REPLAYED"})
        return JSONResponse(
            status_code=200,
            content={
                **_result("ALREADY_PROCESSED"),
                "event_id": body.event_id,
                "repository_id": str(repository.id),
            },
        )

    if reservation is not None and reservation.outcome == idem.OUTCOME_CONFLICT:
        await _refuse(
            db, key=key, organization_id=organization_id,
            event_id=body.event_id, reason_code="CI_EVENT_REPLAY_CONFLICT",
            http_status=409, repository_id=repository.id,
        )
        return JSONResponse(status_code=409, content=_result("REJECTED"))

    if reservation is not None and reservation.outcome == idem.OUTCOME_IN_PROGRESS:
        await _refuse(
            db, key=key, organization_id=organization_id,
            event_id=body.event_id, reason_code="CI_EVENT_IN_PROGRESS",
            http_status=409, repository_id=repository.id,
        )
        return JSONResponse(status_code=409, content=_result("REJECTED"))

    # ── Persist the event record BEFORE the side effect ─────────────
    # outcome REJECTED rows (refusals before this point) have no trusted
    # repository binding, so they are recorded tenant-less by _refuse.
    ci_row = CiEvent(
        organization_id=organization_id,
        api_key_prefix=key.prefix,
        event_id=body.event_id,
        repository_id=repository.id,
        commit_sha=body.commit_sha,
        ref=ref or None,
        provider=body.provider,
        outcome="ACCEPTED",
        result="ACCEPTED",  # server-set; never CI-declared
        reason_code=None,
    )
    db.add(ci_row)
    try:
        await db.flush()
    except Exception:  # noqa: BLE001 — concurrent duplicate lost the race
        await db.rollback()
        metric("ci_events_total", {"outcome": "REPLAYED"})
        return JSONResponse(
            status_code=200,
            content={
                **_result("ALREADY_PROCESSED"),
                "event_id": body.event_id,
            },
        )

    await _audit_ci(
        db, organization_id=organization_id,
        event_type="CI_EVENT_RECEIVED",
        repository_id=repository.id,
        payload={"event_id": body.event_id, "provider": body.provider},
        actor_id=key.prefix,
    )
    await _audit_ci(
        db, organization_id=organization_id,
        event_type="CI_EVENT_ACCEPTED",
        repository_id=repository.id,
        payload={
            "event_id": body.event_id,
            "commit_binding": "REQUESTED",
            "ref": ref or None,
        },
        actor_id=key.prefix,
    )

    # ── Commit binding: REQUESTED, verified later by the worker ─────
    # The scan row carries requested_commit_sha (server-set). The worker
    # clones and VERIFIES the actual SHA; mismatch → COMMIT_MISMATCH
    # (CI_EVENT_COMMIT_MISMATCH is audited by the scan path's failure
    # semantics; the binding can never be satisfied by payload claims).

    # ── Quota (absolute daily ceiling; scans quota is the shared
    # analysis budget — CI does not get a separate, larger pool) ─────
    org_limit, global_limit = limit_for("scans")
    from app.session import get_redis
    try:
        redis = await get_redis()
    except Exception:  # noqa: BLE001
        redis = None
    decision = await consume_quota(
        redis,
        organization_id=organization_id,
        action="scans",
        org_limit=org_limit,
        global_limit=global_limit,
        period_seconds=86400,
    )
    if not decision.allowed:
        # rollback() expires ORM instances — capture the ids FIRST or this
        # refusal path itself would fail (lazy refresh outside greenlet).
        refused_repository_id = str(repository.id)
        refused_key_prefix = key.prefix
        await db.rollback()
        await _refuse(
            db, key=key, organization_id=organization_id,
            event_id=body.event_id, reason_code=_RC_QUOTA,
            http_status=429, repository_id=refused_repository_id,
            api_key_prefix=refused_key_prefix,
        )
        return JSONResponse(status_code=429, content=_result("REJECTED"))

    # ── One side effect: an analysis REQUEST ────────────────────────
    in_flight = (
        await db.execute(
            select(Scan.id).where(
                Scan.repository_id == repository.id,
                Scan.status.notin_(["COMPLETED", "FAILED"]),
            )
        )
    ).scalar_one_or_none()
    if in_flight is not None:
        # Honest: an analysis is already running; this event adds none.
        ci_row.result = "ALREADY_PROCESSED"
        ci_row.reason_code = "SCAN_ALREADY_IN_PROGRESS"
        if reservation is not None and reservation.owned:
            await idem.complete(
                db, reservation, status_code=200,
                body={
                    **_result("ALREADY_PROCESSED"),
                    "event_id": body.event_id,
                    "scan_id": str(in_flight),
                },
            )
        await _audit_ci(
            db, organization_id=organization_id,
            event_type="CI_EVENT_PROCESSING_COMPLETED",
            reason_code="SCAN_ALREADY_IN_PROGRESS",
            repository_id=repository.id,
            payload={"event_id": body.event_id},
            actor_id=key.prefix,
        )
        await db.commit()
        metric("ci_events_total", {"outcome": "ALREADY_PROCESSED"})
        return JSONResponse(
            status_code=200,
            content={
                **_result("ALREADY_PROCESSED"),
                "event_id": body.event_id,
                "scan_id": str(in_flight),
            },
        )

    scan = Scan(
        repository_id=repository.id,
        status="QUEUED",
        trigger="ci",
        requested_commit_sha=body.commit_sha,
    )
    db.add(scan)
    await db.flush()
    ci_row.scan_id = scan.id

    await _audit_ci(
        db, organization_id=organization_id,
        event_type="CI_EVENT_PROCESSING_STARTED",
        repository_id=repository.id,
        payload={"event_id": body.event_id, "scan_id": str(scan.id)},
        actor_id=key.prefix,
    )

    # ── Enqueue (fail-safe: the scan row is marked FAILED/ENQUEUE_FAILED
    # exactly like the V4.1 public path; the caller gets UNAVAILABLE and
    # may retry — never a fabricated success) ────────────────────────
    try:
        from app.worker import enqueue_scan
        enqueue_scan(str(scan.id))
    except Exception as exc:  # noqa: BLE001 — surface, never swallow
        logger.error(
            "ci_scan_enqueue_failed scan=%s err=%s",
            str(scan.id)[:8], type(exc).__name__,
        )
        scan.status = "FAILED"
        scan.error_reason = "ENQUEUE_FAILED"
        scan.completed_at = utcnow()
        ci_row.outcome = "REJECTED"
        ci_row.result = "FAILED"
        ci_row.reason_code = _RC_ENQUEUE_FAILED
        await _audit_ci(
            db, organization_id=organization_id,
            event_type="CI_EVENT_PROCESSING_FAILED",
            reason_code=_RC_ENQUEUE_FAILED,
            repository_id=repository.id,
            payload={"event_id": body.event_id},
            actor_id=key.prefix,
        )
        if reservation is not None and reservation.owned:
            await idem.complete(
                db, reservation, status_code=503,
                body={**_result("UNAVAILABLE"), "event_id": body.event_id},
            )
        await db.commit()
        metric("ci_events_total", {"outcome": "FAILED"})
        return JSONResponse(status_code=503, content=_result("UNAVAILABLE"))

    if reservation is not None and reservation.owned:
        await idem.complete(
            db, reservation, status_code=202,
            body={
                **_result("ACCEPTED"),
                "event_id": body.event_id,
                "scan_id": str(scan.id),
                "commit_binding": "REQUESTED",
            },
        )
    await _audit_ci(
        db, organization_id=organization_id,
        event_type="CI_EVENT_PROCESSING_COMPLETED",
        repository_id=repository.id,
        payload={"event_id": body.event_id, "scan_id": str(scan.id)},
        actor_id=key.prefix,
    )
    await db.commit()
    metric("ci_events_total", {"outcome": "ACCEPTED"})
    return JSONResponse(
        status_code=202,
        content={
            **_result("ACCEPTED"),
            "event_id": body.event_id,
            "scan_id": str(scan.id),
            "commit_binding": "REQUESTED",
        },
    )


async def _refuse(
    db: AsyncSession,
    *,
    key,
    organization_id,
    event_id: str,
    reason_code: str,
    http_status: int,
    repository_id=None,
    api_key_prefix=None,
) -> None:
    """Record + audit a refusal atomically (SECURITY_CRITICAL): the
    refusal row and its chain witness commit together or not at all —
    a refusal that cannot be witnessed fails the request (fail closed).
    Refused events carry no trusted repository binding, so the CiEvent
    row is stored tenant-less (organization_id NULL) exactly like
    refused inbound webhooks.

    `api_key_prefix`: pre-captured prefix for call sites that have
    already rolled the session back (rollback expires the key row, so
    reading key.prefix afterwards would lazy-refresh and fail)."""
    effective_prefix = (
        api_key_prefix if api_key_prefix is not None else key.prefix
    )
    db.add(
        CiEvent(
            organization_id=None,
            api_key_prefix=effective_prefix,
            event_id=(event_id or "(absent)")[:128],
            repository_id=None,
            outcome="REJECTED",
            result="REJECTED",
            reason_code=reason_code,
        )
    )
    if organization_id is not None:
        await _audit_ci(
            db, organization_id=organization_id,
            event_type="CI_EVENT_REJECTED",
            reason_code=reason_code,
            repository_id=repository_id,
            payload={"event_id": event_id},
            actor_id=effective_prefix,
            critical=True,
        )
    await db.commit()
    metric("ci_events_total", {"outcome": "REJECTED"})


def _key_has_scope(key, scope: str) -> bool:
    from app.services import api_key_service
    return api_key_service.key_has_scope(key, scope)
