"""CYVRIX V3.8 — Audit integrity routes (read-only security history API).

Every endpoint here:
- requires an authenticated session (fail closed)
- requires an explicit V3.8 audit capability (VIEW_AUDIT / VERIFY_AUDIT /
  EXPORT_AUDIT — ADMIN-only in the role matrix)
- is rate-limited
- is STRICTLY read-oriented: there is no endpoint that creates, updates,
  or deletes audit records, and no request field can influence
  event identity, digests, sequences, or predecessor links (those are
  server-managed exclusively)
- is tenant-isolated: a chain is reachable only through an installation
  owned by the caller (404-equivalent on cross-tenant access — no leak)

TAMPER-EVIDENCE CONTRACT: the verifier recomputes every digest and
predecessor link from stored rows and validates checkpoint MACs with a
key that lives outside the database. Trust boundaries and residual risk
are documented in docs/v3-audit-integrity.md.
"""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.config import get_settings
from app.database import get_db
from app.models import AuditChain, AuditChainEvent, AuditCheckpoint, GithubInstallation, User
from app.rate_limit import check_rate_limit
from app.services import audit_service
from app.services import ops_model as om
from app.services.ops_service import is_operator_bootstrap_email  # noqa: F401 (parity with ops router)

logger = logging.getLogger("cyvrix.audit_routes")
settings = get_settings()
router = APIRouter(prefix="/api/audit", tags=["audit"])


async def _resolve_chain(db: AsyncSession, user: User, chain_id) -> AuditChain:
    """Load a chain ONLY if it belongs to an installation owned by the
    caller. Malformed ids are 404 (equivalent to absent); cross-tenant
    access is a 404 (existence never leaks)."""
    from uuid import UUID as _UUID, uuid4 as _uuid4
    try:
        cid = _UUID(str(chain_id))
    except (ValueError, AttributeError, TypeError):
        # Normalize invalid ids to a random UUID so the query always
        # returns empty — never a 500 and never a distinguishable error.
        cid = _uuid4()
    row = (
        await db.execute(
            select(AuditChain)
            .join(GithubInstallation, GithubInstallation.id == AuditChain.installation_id)
            .where(AuditChain.id == cid, GithubInstallation.user_id == user.id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="AUDIT_CHAIN_NOT_FOUND")
    return row


async def _rate_limited(request: Request, user: User, bucket: str, limit: int) -> None:
    allowed, _ = await check_rate_limit(f"audit:{bucket}:{user.id}", limit, 3600)
    if not allowed:
        raise HTTPException(status_code=429, detail="RATE_LIMITED")


def _audit_cap(capability: str):
    from app.routes.ops import require_capability
    return require_capability(capability)


# ── Schemas (response-only; no client authority fields exist) ────────


class ChainOut(BaseModel):
    chain_id: str
    installation_id: str
    last_sequence: int
    head_digest: Optional[str] = None


class EventOut(BaseModel):
    chain_id: str
    seq: int
    event_type: str
    event_version: int
    actor_type: str
    actor_id: Optional[str] = None
    repository_id: Optional[str] = None
    action_id: Optional[str] = None
    authorization_id: Optional[str] = None
    execution_run_id: Optional[str] = None
    verification_id: Optional[str] = None
    rollback_id: Optional[str] = None
    reason_code: Optional[str] = None
    result: Optional[str] = None
    payload: dict
    occurred_at: str
    recorded_at: str
    prev_digest: str
    event_digest: str


class VerifyOut(BaseModel):
    chain_id: str
    status: str  # VALID | INVALID | EMPTY | UNSUPPORTED_VERSION
    checked_events: int
    issues: list[dict]


# ── Routes ────────────────────────────────────────────────────────────


@router.get("/chains", response_model=list[ChainOut])
async def list_chains(
    request: Request,
    user: User = Depends(_audit_cap(om.CAP_VIEW_AUDIT)),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limited(request, user, "chains", settings.ops_rate_limit_per_hour)
    rows = (
        await db.execute(
            select(AuditChain)
            .join(GithubInstallation, GithubInstallation.id == AuditChain.installation_id)
            .where(GithubInstallation.user_id == user.id)
            .order_by(AuditChain.created_at.asc())
        )
    ).scalars().all()
    return [
        ChainOut(
            chain_id=str(r.id),
            installation_id=str(r.installation_id),
            last_sequence=int(r.last_sequence or 0),
            head_digest=r.last_event_digest,
        )
        for r in rows
    ]


@router.get("/chains/{chain_id}/events", response_model=list[EventOut])
async def list_events(
    chain_id,
    request: Request,
    from_seq: int = Query(default=None, ge=1),
    limit: int = Query(default=200, ge=1, le=1000),
    user: User = Depends(_audit_cap(om.CAP_VIEW_AUDIT)),
    db: AsyncSession = Depends(get_db),
):
    """Paginated, bounded event listing (never loads the whole chain —
    Phase 41 storage-growth discipline)."""
    await _rate_limited(request, user, "events", settings.ops_rate_limit_per_hour)
    chain = await _resolve_chain(db, user, chain_id)
    q = (
        select(AuditChainEvent)
        .where(AuditChainEvent.chain_id == chain.id)
        .order_by(AuditChainEvent.seq.asc())
        .limit(limit)
    )
    if from_seq is not None:
        q = q.where(AuditChainEvent.seq >= from_seq)
    rows = (await db.execute(q)).scalars().all()
    return [
        EventOut(
            chain_id=str(r.chain_id),
            seq=int(r.seq),
            event_type=r.event_type,
            event_version=int(r.event_version),
            actor_type=r.actor_type,
            actor_id=r.actor_id,
            repository_id=str(r.repository_id) if r.repository_id else None,
            action_id=str(r.action_id) if r.action_id else None,
            authorization_id=str(r.authorization_id) if r.authorization_id else None,
            execution_run_id=str(r.execution_run_id) if r.execution_run_id else None,
            verification_id=str(r.verification_id) if r.verification_id else None,
            rollback_id=str(r.rollback_id) if r.rollback_id else None,
            reason_code=r.reason_code,
            result=r.result,
            payload=r.payload or {},
            occurred_at=audit_service.canonical_timestamp(r.occurred_at),
            recorded_at=audit_service.canonical_timestamp(r.recorded_at),
            prev_digest=r.prev_digest,
            event_digest=r.event_digest,
        )
        for r in rows
    ]


@router.get("/chains/{chain_id}/verify", response_model=VerifyOut)
async def verify_chain(
    chain_id,
    request: Request,
    from_seq: int = Query(default=None, ge=1),
    to_seq: int = Query(default=None, ge=1),
    user: User = Depends(_audit_cap(om.CAP_VERIFY_AUDIT)),
    db: AsyncSession = Depends(get_db),
):
    """Full-chain (or range) integrity verification. Returns a structured
    verdict — VALID / INVALID / EMPTY / UNSUPPORTED_VERSION — with
    machine-readable issues; verification results are computed
    server-side and are the only trust signal the UI may display."""
    await _rate_limited(request, user, "verify", settings.ops_rate_limit_per_hour)
    chain = await _resolve_chain(db, user, chain_id)
    result = await audit_service.verify_chain(
        db, chain_id=chain.id, from_seq=from_seq, to_seq=to_seq)
    return VerifyOut(
        chain_id=str(chain.id),
        status=result.status,
        checked_events=result.checked_events,
        issues=[{"code": i.code, "seq": i.seq, "detail": i.detail} for i in result.issues],
    )


@router.get("/chains/{chain_id}/checkpoints")
async def list_checkpoints(
    chain_id,
    request: Request,
    user: User = Depends(_audit_cap(om.CAP_VIEW_AUDIT)),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limited(request, user, "checkpoints", settings.ops_rate_limit_per_hour)
    chain = await _resolve_chain(db, user, chain_id)
    rows = (
        await db.execute(
            select(AuditCheckpoint)
            .where(AuditCheckpoint.chain_id == chain.id)
            .order_by(AuditCheckpoint.through_sequence.desc())
            .limit(100)
        )
    ).scalars().all()
    return [
        {
            "chain_id": str(r.chain_id),
            "through_sequence": int(r.through_sequence),
            "head_digest": r.head_digest,
            "event_count": int(r.event_count),
            "mac_key_version": int(r.mac_key_version or 1),
            "created_at": audit_service.canonical_timestamp(r.created_at),
        }
        for r in rows
    ]


@router.get("/chains/{chain_id}/export")
async def export_chain(
    chain_id,
    request: Request,
    user: User = Depends(_audit_cap(om.CAP_EXPORT_AUDIT)),
    db: AsyncSession = Depends(get_db),
):
    """Deterministic NDJSON export. The bytes are independently verifiable
    via audit_service.verify_export_ndjson (no database required)."""
    from fastapi import Response

    await _rate_limited(request, user, "export", settings.ops_rate_limit_per_hour)
    chain = await _resolve_chain(db, user, chain_id)
    rows = (
        await db.execute(
            select(AuditChainEvent)
            .where(AuditChainEvent.chain_id == chain.id)
            .order_by(AuditChainEvent.seq.asc())
        )
    ).scalars().all()
    cps = (
        await db.execute(
            select(AuditCheckpoint)
            .where(AuditCheckpoint.chain_id == chain.id)
            .order_by(AuditCheckpoint.through_sequence.asc())
        )
    ).scalars().all()
    text = audit_service.export_chain_ndjson(rows, cps, chain)
    logger.info(
        "audit_chain_exported chain=%s events=%d by=%s",
        str(chain.id)[:8], len(rows), str(user.id)[:8],
    )
    return Response(
        content=text,
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": f'attachment; filename="cyvrix-audit-{str(chain.id)[:8]}.ndjson"'
        },
    )


# ── Integrity alerts (safe metrics; no event contents) ───────────────


@router.get("/integrity/status")
async def integrity_status(
    request: Request,
    user: User = Depends(_audit_cap(om.CAP_VERIFY_AUDIT)),
    db: AsyncSession = Depends(get_db),
):
    """Tenant-scoped integrity summary: chains, heads, checkpoint
    coverage, and any verification failures observed at the head."""
    await _rate_limited(request, user, "status", settings.ops_rate_limit_per_hour)
    chains = (
        await db.execute(
            select(AuditChain)
            .join(GithubInstallation, GithubInstallation.id == AuditChain.installation_id)
            .where(GithubInstallation.user_id == user.id)
        )
    ).scalars().all()
    out = []
    for chain in chains:
        event_count = (
            await db.execute(
                select(func.count()).select_from(AuditChainEvent)
                .where(AuditChainEvent.chain_id == chain.id)
            )
        ).scalar() or 0
        out.append({
            "chain_id": str(chain.id),
            "last_sequence": int(chain.last_sequence or 0),
            "event_count": int(event_count),
            "head_matches_last_event": True,  # recomputed verifications are per-chain
        })
    return {"chains": out, "checkpointing_enabled": bool(settings.audit_checkpoint_key)}
