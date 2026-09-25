"""CYVRIX V4.1 — public API (`/api/v1`).

The versioned, externally-integrable surface. Every request passes, in
order:

    authentication (hashed API key)
      → organization (derived FROM THE KEY, never from the request)
        → scope (closed world; a scope is permission to ASK)
          → resource authorization (the resource's own organization)
            → existing V3 security controls (unchanged)

This module NEVER re-exports an internal workflow mutation. Approving,
authorizing, executing, verifying and rolling back remain
session-authenticated console operations with their full V3 chain. The
single mutation here submits an analysis REQUEST, which is side-effect free
with respect to the security chain.

Deliberate absences, so nothing is implied that does not exist:

- No endpoint accepts an organization identifier. The tenant comes from the
  key, so a key cannot reach another organization.
- No endpoint accepts a URL, owner, or remote address. Every GitHub
  destination derives from trusted integration state (no SSRF surface).
- No endpoint declares security state. Only server-computed verification is
  ever reported as a verdict.
"""
from __future__ import annotations

import base64
import logging
import time
from datetime import datetime, timezone
from typing import Any, Generic, Optional, TypeVar
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.metrics import increment as metric
from app.models import (
    ActionProposal,
    AuditChain,
    ExecutionRun,
    Finding,
    GithubInstallation,
    Repository,
    RollbackRun,
    Scan,
    VerificationRun,
)
from app.quota_service import (
    QuotaDecision,
    consume_quota,
    limit_for,
)
from app.rate_limit import check_rate_limit
from app.services import audit_service
from app.services import idempotency_service as idem
from app.services import v4_rbac as rbac
from app.services.org_auth import api_key_auth, require_api_scope

logger = logging.getLogger("cyvrix.api_v1")

PUBLIC_API_VERSION = "v1"

router = APIRouter(
    prefix="/api/v1",
    tags=["public-api"],
    responses={
        401: {"description": "Missing, unknown, revoked or expired API key"},
        403: {"description": "Key lacks the required scope"},
        404: {"description": "Resource not found in this organization"},
        409: {"description": "Idempotency conflict"},
        429: {"description": "Organization rate limit exceeded"},
    },
)

# ── Rate-limit classes (Phase 19/20) ─────────────────────────────────
#
# ALL reads share one bucket and ALL writes share another, so a caller
# cannot multiply its budget by spreading requests across endpoints.
# Buckets are namespaced by organization in the key itself.
READ_BUCKET = "v1-read"
READ_LIMIT_PER_HOUR = 600
WRITE_BUCKET = "v1-write"
WRITE_LIMIT_PER_HOUR = 60

RATE_WINDOW_SECONDS = 3600

MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 50


# ── Public error contract (Phase 13/14) ──────────────────────────────


class PublicApiError(Exception):
    """A refusal rendered through the public error envelope.

    `code` is a stable machine-readable token; `message` is safe to show a
    human. Neither ever contains internal detail — no stack traces, SQL,
    paths or secrets.
    """

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: Optional[dict] = None,
    ) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details


def _uuid_or_400(value: Any, *, field_name: str = "id") -> UUID:
    try:
        return UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        raise PublicApiError(
            400, "INVALID_IDENTIFIER", f"{field_name} is not a valid identifier."
        )


async def _rate_limit(
    request: Request,
    response: Response,
    organization_id,
    *,
    bucket: str,
    limit: int,
) -> None:
    """Organization-scoped rate limit + truthful headers (Phase 20).

    Headers describe the CALLER'S OWN organization only, so no tenant can
    infer another tenant's budget. Redis being unreachable makes
    `check_rate_limit` return not-allowed, so this fails closed.
    """
    allowed, remaining = await check_rate_limit(
        f"org:{organization_id}:{bucket}", limit, RATE_WINDOW_SECONDS
    )
    now = int(time.time())
    reset = now - (now % RATE_WINDOW_SECONDS) + RATE_WINDOW_SECONDS
    headers = {
        "x-ratelimit-limit": str(limit),
        "x-ratelimit-remaining": str(max(0, int(remaining))),
        "x-ratelimit-reset": str(reset),
        "x-ratelimit-class": bucket,
    }
    # Set on the response AND stashed on the request: if this raises, the
    # error handler builds a new response and would otherwise drop them.
    response.headers.update(headers)
    request.state.public_headers = headers
    if not allowed:
        raise PublicApiError(
            429,
            "ORG_RATE_LIMITED",
            "This organization has exceeded its request budget for this class.",
            {"limit": limit, "reset": reset},
        )


# ── Pagination (Phase 15/16) ─────────────────────────────────────────

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    """Bounded, stable, cursor-paginated collection.

    A cursor (not an offset) is used because these collections are appended
    to while a client pages through them; an offset would silently skip or
    repeat rows as new findings/events arrive.
    """

    items: list[T] = Field(default_factory=list)
    next_cursor: Optional[str] = None
    has_more: bool = False


def encode_cursor(created_at: Optional[datetime], row_id: Any) -> str:
    stamp = created_at.isoformat() if created_at else ""
    raw = f"{stamp}|{row_id}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> tuple[Optional[datetime], str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        stamp, _, row_id = raw.rpartition("|")
        if not row_id:
            raise ValueError("missing id")
        parsed = datetime.fromisoformat(stamp) if stamp else None
        if parsed is not None and parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed, row_id
    except Exception:
        raise PublicApiError(
            400, "INVALID_CURSOR", "The pagination cursor is not valid."
        )


def _keyset_filter(model, cursor: str):
    """Rows strictly after the cursor position in (created_at DESC, id DESC)."""
    created_at, row_id = decode_cursor(cursor)
    row_uuid = _uuid_or_400(row_id, field_name="cursor")
    if created_at is None:
        # Rows without a timestamp are only reachable by id.
        return model.created_at.is_(None), and_(
            model.created_at.is_(None), model.id < row_uuid
        )
    return model.created_at.is_not(None), or_(
        model.created_at < created_at,
        and_(model.created_at == created_at, model.id < row_uuid),
    )


async def paginate(
    db: AsyncSession,
    *,
    query,
    model,
    limit: int,
    cursor: Optional[str],
    serialize,
) -> Page:
    """Apply keyset pagination to a tenant-scoped query.

    The caller has already constrained `query` to the key's organization;
    this helper only orders and bounds it.
    """
    bounded = min(max(int(limit), 1), MAX_PAGE_SIZE)
    q = query
    if cursor:
        has_stamp, condition = _keyset_filter(model, cursor)
        if has_stamp is True:
            q = q.where(condition)
        else:
            # Mixed rows (some without created_at) — apply the safest
            # combination so nothing is duplicated across pages.
            q = q.where(condition)
    q = (
        q.order_by(model.created_at.desc().nulls_last(), model.id.desc())
        .limit(bounded + 1)
    )
    rows = (await db.execute(q)).scalars().all()
    has_more = len(rows) > bounded
    rows = rows[:bounded]
    next_cursor = (
        encode_cursor(rows[-1].created_at, rows[-1].id) if has_more and rows else None
    )
    return Page(items=[serialize(r) for r in rows], next_cursor=next_cursor, has_more=has_more)


def _validate_choice(value: Optional[str], allowed: frozenset[str], field: str) -> Optional[str]:
    """Allowlist filter values.

    An unrecognised value is REFUSED rather than ignored: silently dropping
    a filter would let a client believe it had narrowed a result set that it
    had not.
    """
    if value is None:
        return None
    normalized = value.strip().upper()
    if normalized not in allowed:
        raise PublicApiError(
            400,
            "INVALID_FILTER",
            f"Unsupported {field} filter.",
            {"field": field, "allowed": sorted(allowed)},
        )
    return normalized


# ── Tenant-scoped query builders ─────────────────────────────────────


def _org_repositories(organization_id):
    return (
        select(Repository)
        .join(GithubInstallation, Repository.installation_id == GithubInstallation.id)
        .where(GithubInstallation.organization_id == organization_id)
    )


def _org_findings(organization_id):
    return (
        select(Finding)
        .join(Repository, Finding.repository_id == Repository.id)
        .join(GithubInstallation, Repository.installation_id == GithubInstallation.id)
        .where(GithubInstallation.organization_id == organization_id)
    )


def _org_actions(organization_id):
    return (
        select(ActionProposal)
        .join(Repository, ActionProposal.repository_id == Repository.id)
        .join(GithubInstallation, Repository.installation_id == GithubInstallation.id)
        .where(GithubInstallation.organization_id == organization_id)
    )


def _org_scans(organization_id):
    return (
        select(Scan)
        .join(Repository, Scan.repository_id == Repository.id)
        .join(GithubInstallation, Repository.installation_id == GithubInstallation.id)
        .where(GithubInstallation.organization_id == organization_id)
    )


def _org_executions(organization_id):
    return (
        select(ExecutionRun)
        .join(Repository, ExecutionRun.repository_id == Repository.id)
        .join(GithubInstallation, Repository.installation_id == GithubInstallation.id)
        .where(GithubInstallation.organization_id == organization_id)
    )


def _org_verifications(organization_id):
    return (
        select(VerificationRun)
        .join(Repository, VerificationRun.repository_id == Repository.id)
        .join(GithubInstallation, Repository.installation_id == GithubInstallation.id)
        .where(GithubInstallation.organization_id == organization_id)
    )


def _org_rollbacks(organization_id):
    return (
        select(RollbackRun)
        .join(Repository, RollbackRun.repository_id == Repository.id)
        .join(GithubInstallation, Repository.installation_id == GithubInstallation.id)
        .where(GithubInstallation.organization_id == organization_id)
    )


def _org_audit_chains(organization_id):
    return (
        select(AuditChain)
        .join(GithubInstallation, GithubInstallation.id == AuditChain.installation_id)
        .where(GithubInstallation.organization_id == organization_id)
    )


# ── Response models ──────────────────────────────────────────────────


class ApiIdentityOut(BaseModel):
    organization_id: str
    key_name: str
    key_prefix: str
    scopes: list[str]
    read_only: bool
    api_version: str


class RepositoryOut(BaseModel):
    id: str
    owner: str
    name: str
    default_branch: str
    is_active: bool


class FindingOut(BaseModel):
    id: str
    repository_id: str
    title: str
    severity: str
    status: str
    source_type: str
    vulnerability_id: Optional[str] = None


class ActionProposalOut(BaseModel):
    id: str
    repository_id: str
    action_type: str
    status: str
    risk_level: str
    policy_decision: str
    action_digest: str


class ScanOut(BaseModel):
    id: str
    repository_id: str
    status: str
    trigger: str
    commit_sha: Optional[str] = None
    error_reason: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    created_at: Optional[str] = None


class ExecutionOut(BaseModel):
    id: str
    repository_id: str
    action_proposal_id: str
    run_state: str
    fail_reason_code: Optional[str] = None
    created_at: Optional[str] = None


class VerificationOut(BaseModel):
    id: str
    repository_id: str
    verification_state: str
    result: Optional[str] = None
    reason_code: Optional[str] = None
    created_at: Optional[str] = None


class RollbackOut(BaseModel):
    id: str
    repository_id: str
    rollback_state: str
    fail_reason_code: Optional[str] = None
    created_at: Optional[str] = None


class AuditChainOut(BaseModel):
    chain_id: str
    installation_id: str
    last_sequence: int
    head_digest: Optional[str] = None


class AuditVerifyOut(BaseModel):
    chain_id: str
    status: str
    checked_events: int
    issues: list[dict]


class IntegrationOut(BaseModel):
    installation_id: str
    account_login: str
    account_type: str
    organization_id: Optional[str] = None
    repository_count: int


class ScanCreateRequest(BaseModel):
    """Submit an analysis request.

    Only a repository the key's organization owns may be named.

    `commit_sha` is OPTIONAL commit binding (V4.1): the exact commit the
    analysis is requested FOR. It is stored as a REQUESTED binding and
    verified server-side at clone time — the worker records the actual
    clone SHA and refuses the scan (COMMIT_MISMATCH) when they disagree.
    The request can never make the platform analyze a different commit
    than the one it actually clones, and the response never implies the
    scan has run or will pass.
    """

    model_config = ConfigDict(extra="forbid")

    repository_id: str = Field(min_length=8, max_length=64)
    commit_sha: Optional[str] = Field(default=None, min_length=40, max_length=40)

    @field_validator("commit_sha")
    @classmethod
    def _validate_commit_sha(cls, v: Optional[str]) -> Optional[str]:
        """A commit SHA is 40 lowercase hex characters — nothing else.

        Length-only validation would accept arbitrary 40-character
        strings, which would poison the binding record and make the
        worker's MISMATCH verdict meaningless for garbage requests."""
        if v is None:
            return v
        value = v.strip().lower()
        if len(value) != 40 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("commit_sha must be a full 40-character hex SHA")
        return value


class ScanCreatedOut(BaseModel):
    scan_id: str
    repository_id: str
    status: str
    reused: bool = False


def _iso(value) -> Optional[str]:
    return value.isoformat() if value else None


# Server-computed result semantics for scan jobs (Phase 24/7):
#   PASS          — analysis completed; the platform reported findings
#                   (a "pass" over the pipeline, NOT a clean bill)
#   FAIL          — the analysis could not be trusted (failed run)
#   INCONCLUSIVE  — the run produced no trustworthy verdict
# There is deliberately no client-writable result. BLOCKED is reported
# through 409 SCAN_IN_PROGRESS / 403 scope denials before a job exists.
SCAN_RESULT_BY_STATUS = {
    "COMPLETED": "PASS",
    "FAILED": "FAIL",
    "QUEUED": None,
    "CLONING": None,
    "SCANNING": None,
    "ANALYZING": None,
}


def _scan_job_result(scan: Scan) -> Optional[str]:
    """Machine-readable, SERVER-computed result for a scan job.

    Never trusts any client claim; derived only from server-managed scan
    state. Unknown statuses collapse to INCONCLUSIVE rather than PASS —
    unknown is never silently success.
    """
    status = (scan.status or "").upper()
    result = SCAN_RESULT_BY_STATUS.get(status, "INCONCLUSIVE")
    return result


class JobStatusOut(BaseModel):
    """Async job status view (Phase 7/11): the scan IS the job.

    `result` is the machine-readable outcome once the job is terminal;
    it is None while the job is running. STALE/SIDE_EFFECT_UNKNOWN are
    deliberately absent: public-API scans have no external side effect
    (clone + read-only analysis), so UNKNOWN collapses are impossible
    here, and no field pretends otherwise.
    """

    job_id: str
    kind: str = "SCAN"
    status: str
    result: Optional[str] = None
    repository_id: str
    commit_sha: Optional[str] = None
    requested_commit_sha: Optional[str] = None
    commit_binding: str  # UNBOUND | PENDING | VERIFIED | MISMATCH
    error_reason: Optional[str] = None
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


def _commit_binding(scan: Scan) -> str:
    """Server-derived commit-binding state for a scan job."""
    if not scan.requested_commit_sha:
        return "UNBOUND"
    if scan.status in ("QUEUED", "CLONING", "SCANNING", "ANALYZING"):
        return "PENDING"
    if scan.status == "FAILED" and scan.error_reason == "COMMIT_MISMATCH":
        return "MISMATCH"
    if scan.status == "COMPLETED" and scan.commit_sha and (
        scan.commit_sha.lower() == scan.requested_commit_sha.lower()
    ):
        return "VERIFIED"
    return "INCONCLUSIVE"


async def _enforce_quota(db, request: Request, organization_id, *, action: str) -> None:
    """Organization + platform quota enforcement (Phase 31/32).

    Atomic Redis counters, GLOBAL checked before ORGANIZATION. Redis
    unreachable → REFUSED (503), never allowed — a quota that degrades
    to allow under failure is a bypass. Refusals are audited as
    QUOTA_LIMIT_REACHED on the org chain (best-effort: refusal already
    protects the platform; the audit event is observability).
    """
    from app.session import get_redis

    org_limit, global_limit = limit_for(action)
    if org_limit <= 0 or global_limit <= 0:
        # An unregistered action refuses: there is no unlimited tier.
        raise PublicApiError(
            503, "QUOTA_UNAVAILABLE", "Quota enforcement is unavailable for this action."
        )
    try:
        redis = await get_redis()
    except Exception:  # noqa: BLE001
        redis = None
    decision = await consume_quota(
        redis,
        organization_id=organization_id,
        action=action,
        org_limit=org_limit,
        global_limit=global_limit,
        period_seconds=86400,
    )
    if decision.allowed:
        return
    metric("api_quota_rejections_total", {"scope": action})
    if decision.reason_code == "QUOTA_UNAVAILABLE":
        raise PublicApiError(
            503,
            "QUOTA_UNAVAILABLE",
            "Quota enforcement is temporarily unavailable; the request is refused.",
        )
    code = (
        "QUOTA_GLOBAL_EXCEEDED"
        if decision.reason_code == "QUOTA_GLOBAL_EXCEEDED"
        else "QUOTA_ORG_EXCEEDED"
    )
    # Best-effort audit: refusals are SECURITY-CRITICAL-adjacent but the
    # refusal itself is the protection; audit failure must not mask it.
    try:
        await audit_service.emit_security_event(
            db,
            organization_id=organization_id,
            event_type="QUOTA_LIMIT_REACHED",
            actor_type=audit_service.ActorType.SYSTEM,
            reason_code=code,
            payload={"action": action},
        )
        await db.commit()
    except Exception:  # noqa: BLE001
        await db.rollback()
    raise PublicApiError(
        429 if code == "QUOTA_ORG_EXCEEDED" else 429,
        code,
        "This organization has reached its quota for this action.",
        {"action": action, "org_limit": decision.org_limit},
    )


# ── Identity ─────────────────────────────────────────────────────────


@router.get("/me", response_model=ApiIdentityOut)
async def api_identity(
    request: Request,
    response: Response,
    key=Depends(api_key_auth),
):
    """Identity for the presented key. Reveals no secret material."""
    await _rate_limit(
        request, response, key.organization_id, bucket=READ_BUCKET, limit=READ_LIMIT_PER_HOUR
    )
    return ApiIdentityOut(
        organization_id=str(key.organization_id),
        key_name=key.name,
        key_prefix=key.prefix,
        scopes=list(key.scopes or []),
        read_only=rbac.key_is_read_only(key.scopes),
        api_version=PUBLIC_API_VERSION,
    )


# ── Reads ────────────────────────────────────────────────────────────

_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"})
_FINDING_STATUSES = frozenset({"OPEN", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED"})
_SOURCE_TYPES = frozenset({"DEPENDENCY", "CONTAINER", "LOG"})
_SCAN_STATUSES = frozenset(
    {"QUEUED", "CLONING", "SCANNING", "ANALYZING", "COMPLETED", "FAILED"}
)


@router.get("/repositories", response_model=Page[RepositoryOut])
async def list_repositories(
    request: Request,
    response: Response,
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    cursor: Optional[str] = Query(default=None, max_length=512),
    is_active: Optional[bool] = Query(default=None),
    key=Depends(require_api_scope("repositories:read")),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limit(
        request, response, key.organization_id, bucket=READ_BUCKET, limit=READ_LIMIT_PER_HOUR
    )
    q = _org_repositories(key.organization_id)
    if is_active is not None:
        q = q.where(Repository.is_active.is_(is_active))
    return await paginate(
        db,
        query=q,
        model=Repository,
        limit=limit,
        cursor=cursor,
        serialize=lambda r: RepositoryOut(
            id=str(r.id),
            owner=r.owner,
            name=r.name,
            default_branch=r.default_branch,
            is_active=bool(r.is_active),
        ),
    )


@router.get("/findings", response_model=Page[FindingOut])
async def list_findings(
    request: Request,
    response: Response,
    severity: Optional[str] = Query(default=None, max_length=16),
    status_filter: Optional[str] = Query(default=None, alias="status", max_length=24),
    source_type: Optional[str] = Query(default=None, max_length=24),
    repository_id: Optional[str] = Query(default=None, max_length=64),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    cursor: Optional[str] = Query(default=None, max_length=512),
    key=Depends(require_api_scope("findings:read")),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limit(
        request, response, key.organization_id, bucket=READ_BUCKET, limit=READ_LIMIT_PER_HOUR
    )
    q = _org_findings(key.organization_id)
    severity_value = _validate_choice(severity, _SEVERITIES, "severity")
    if severity_value:
        q = q.where(Finding.severity == severity_value)
    status_value = _validate_choice(status_filter, _FINDING_STATUSES, "status")
    if status_value:
        q = q.where(Finding.status == status_value)
    source_value = _validate_choice(source_type, _SOURCE_TYPES, "source_type")
    if source_value:
        q = q.where(Finding.source_type == source_value)
    if repository_id:
        q = q.where(Finding.repository_id == _uuid_or_400(repository_id, field_name="repository_id"))
    return await paginate(
        db,
        query=q,
        model=Finding,
        limit=limit,
        cursor=cursor,
        serialize=lambda f: FindingOut(
            id=str(f.id),
            repository_id=str(f.repository_id),
            title=f.title,
            severity=f.severity,
            status=f.status,
            source_type=f.source_type,
            vulnerability_id=f.vulnerability_id,
        ),
    )


@router.get("/actions", response_model=Page[ActionProposalOut])
async def list_actions(
    request: Request,
    response: Response,
    status_filter: Optional[str] = Query(default=None, alias="status", max_length=32),
    repository_id: Optional[str] = Query(default=None, max_length=64),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    cursor: Optional[str] = Query(default=None, max_length=512),
    key=Depends(require_api_scope("actions:read")),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limit(
        request, response, key.organization_id, bucket=READ_BUCKET, limit=READ_LIMIT_PER_HOUR
    )
    q = _org_actions(key.organization_id)
    if status_filter:
        q = q.where(ActionProposal.status == status_filter.strip().upper())
    if repository_id:
        q = q.where(
            ActionProposal.repository_id == _uuid_or_400(repository_id, field_name="repository_id")
        )
    return await paginate(
        db,
        query=q,
        model=ActionProposal,
        limit=limit,
        cursor=cursor,
        serialize=lambda a: ActionProposalOut(
            id=str(a.id),
            repository_id=str(a.repository_id),
            action_type=a.action_type,
            status=a.status,
            risk_level=a.risk_level,
            policy_decision=a.policy_decision,
            action_digest=a.action_digest,
        ),
    )


@router.get("/scans", response_model=Page[ScanOut])
async def list_scans(
    request: Request,
    response: Response,
    status_filter: Optional[str] = Query(default=None, alias="status", max_length=24),
    repository_id: Optional[str] = Query(default=None, max_length=64),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    cursor: Optional[str] = Query(default=None, max_length=512),
    key=Depends(require_api_scope("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limit(
        request, response, key.organization_id, bucket=READ_BUCKET, limit=READ_LIMIT_PER_HOUR
    )
    q = _org_scans(key.organization_id)
    status_value = _validate_choice(status_filter, _SCAN_STATUSES, "status")
    if status_value:
        q = q.where(Scan.status == status_value)
    if repository_id:
        q = q.where(Scan.repository_id == _uuid_or_400(repository_id, field_name="repository_id"))
    return await paginate(
        db,
        query=q,
        model=Scan,
        limit=limit,
        cursor=cursor,
        serialize=_scan_out,
    )


def _scan_out(s: Scan) -> ScanOut:
    return ScanOut(
        id=str(s.id),
        repository_id=str(s.repository_id),
        status=s.status,
        trigger=s.trigger,
        commit_sha=s.commit_sha,
        error_reason=s.error_reason,
        started_at=_iso(s.started_at),
        completed_at=_iso(s.completed_at),
        created_at=_iso(s.created_at),
    )


@router.get("/scans/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: str,
    request: Request,
    response: Response,
    key=Depends(require_api_scope("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Poll an analysis request. A scan outside this organization is 404."""
    await _rate_limit(
        request, response, key.organization_id, bucket=READ_BUCKET, limit=READ_LIMIT_PER_HOUR
    )
    row = (
        await db.execute(
            _org_scans(key.organization_id).where(
                Scan.id == _uuid_or_400(scan_id, field_name="scan_id")
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise PublicApiError(404, "SCAN_NOT_FOUND", "No such scan in this organization.")
    return _scan_out(row)


@router.get("/scans/{scan_id}/status", response_model=JobStatusOut)
async def get_scan_status(
    scan_id: str,
    request: Request,
    response: Response,
    key=Depends(require_api_scope("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Machine-readable async-job status (Phase 7/11/24).

    `result` is SERVER-COMPUTED from server-managed scan state — a CI
    caller can never declare its own security outcome. `commit_binding`
    reports whether the requested commit was actually analyzed
    (VERIFIED) or refused as stale (MISMATCH); unknown states surface as
    INCONCLUSIVE, never as silent success.
    """
    await _rate_limit(
        request, response, key.organization_id, bucket=READ_BUCKET, limit=READ_LIMIT_PER_HOUR
    )
    row = (
        await db.execute(
            _org_scans(key.organization_id).where(
                Scan.id == _uuid_or_400(scan_id, field_name="scan_id")
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise PublicApiError(404, "SCAN_NOT_FOUND", "No such scan in this organization.")
    return JobStatusOut(
        job_id=str(row.id),
        kind="SCAN",
        status=row.status,
        result=_scan_job_result(row),
        repository_id=str(row.repository_id),
        commit_sha=row.commit_sha,
        requested_commit_sha=row.requested_commit_sha,
        commit_binding=_commit_binding(row),
        error_reason=row.error_reason,
        created_at=_iso(row.created_at),
        started_at=_iso(row.started_at),
        completed_at=_iso(row.completed_at),
    )


@router.get("/executions", response_model=Page[ExecutionOut])
async def list_executions(
    request: Request,
    response: Response,
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    cursor: Optional[str] = Query(default=None, max_length=512),
    key=Depends(require_api_scope("executions:read")),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limit(
        request, response, key.organization_id, bucket=READ_BUCKET, limit=READ_LIMIT_PER_HOUR
    )
    return await paginate(
        db,
        query=_org_executions(key.organization_id),
        model=ExecutionRun,
        limit=limit,
        cursor=cursor,
        serialize=lambda r: ExecutionOut(
            id=str(r.id),
            repository_id=str(r.repository_id),
            action_proposal_id=str(r.action_proposal_id),
            run_state=r.run_state,
            fail_reason_code=r.fail_reason_code,
            created_at=_iso(r.created_at),
        ),
    )


@router.get("/verifications", response_model=Page[VerificationOut])
async def list_verifications(
    request: Request,
    response: Response,
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    cursor: Optional[str] = Query(default=None, max_length=512),
    key=Depends(require_api_scope("verifications:read")),
    db: AsyncSession = Depends(get_db),
):
    """Verification results are SERVER-COMPUTED. The public API reports them;
    it never accepts, infers, or overrides a verdict."""
    await _rate_limit(
        request, response, key.organization_id, bucket=READ_BUCKET, limit=READ_LIMIT_PER_HOUR
    )
    return await paginate(
        db,
        query=_org_verifications(key.organization_id),
        model=VerificationRun,
        limit=limit,
        cursor=cursor,
        serialize=lambda r: VerificationOut(
            id=str(r.id),
            repository_id=str(r.repository_id),
            verification_state=r.verification_state,
            result=r.result,
            reason_code=r.reason_code,
            created_at=_iso(r.created_at),
        ),
    )


@router.get("/rollbacks", response_model=Page[RollbackOut])
async def list_rollbacks(
    request: Request,
    response: Response,
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    cursor: Optional[str] = Query(default=None, max_length=512),
    key=Depends(require_api_scope("rollback:read")),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limit(
        request, response, key.organization_id, bucket=READ_BUCKET, limit=READ_LIMIT_PER_HOUR
    )
    return await paginate(
        db,
        query=_org_rollbacks(key.organization_id),
        model=RollbackRun,
        limit=limit,
        cursor=cursor,
        serialize=lambda r: RollbackOut(
            id=str(r.id),
            repository_id=str(r.repository_id),
            rollback_state=r.rollback_state,
            fail_reason_code=r.fail_reason_code,
            created_at=_iso(r.created_at),
        ),
    )


@router.get("/integrations", response_model=Page[IntegrationOut])
async def list_integrations(
    request: Request,
    response: Response,
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    cursor: Optional[str] = Query(default=None, max_length=512),
    key=Depends(require_api_scope("integrations:read")),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limit(
        request, response, key.organization_id, bucket=READ_BUCKET, limit=READ_LIMIT_PER_HOUR
    )
    q = select(GithubInstallation).where(
        GithubInstallation.organization_id == key.organization_id
    )
    return await paginate(
        db,
        query=q,
        model=GithubInstallation,
        limit=limit,
        cursor=cursor,
        serialize=lambda i: IntegrationOut(
            installation_id=str(i.installation_id),
            account_login=i.account_login,
            account_type=i.account_type,
            organization_id=str(i.organization_id) if i.organization_id else None,
            repository_count=0,
        ),
    )


# ── Audit (read + server-side verification) ──────────────────────────


@router.get("/audit/chains", response_model=Page[AuditChainOut])
async def list_audit_chains(
    request: Request,
    response: Response,
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    cursor: Optional[str] = Query(default=None, max_length=512),
    key=Depends(require_api_scope("audit:read")),
    db: AsyncSession = Depends(get_db),
):
    await _rate_limit(
        request, response, key.organization_id, bucket=READ_BUCKET, limit=READ_LIMIT_PER_HOUR
    )
    return await paginate(
        db,
        query=_org_audit_chains(key.organization_id),
        model=AuditChain,
        limit=limit,
        cursor=cursor,
        serialize=lambda c: AuditChainOut(
            chain_id=str(c.id),
            installation_id=str(c.installation_id),
            last_sequence=int(c.last_sequence or 0),
            head_digest=c.last_event_digest,
        ),
    )


@router.get("/audit/chains/{chain_id}/verify", response_model=AuditVerifyOut)
async def verify_audit_chain(
    chain_id: str,
    request: Request,
    response: Response,
    key=Depends(require_api_scope("audit:verify")),
    db: AsyncSession = Depends(get_db),
):
    """Verify a chain's integrity SERVER-SIDE.

    The browser/CI client never computes digests: it receives this verdict
    or nothing. A chain outside the key's organization is 404.
    """
    await _rate_limit(
        request, response, key.organization_id, bucket=READ_BUCKET, limit=READ_LIMIT_PER_HOUR
    )
    row = (
        await db.execute(
            _org_audit_chains(key.organization_id).where(
                AuditChain.id == _uuid_or_400(chain_id, field_name="chain_id")
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise PublicApiError(
            404, "AUDIT_CHAIN_NOT_FOUND", "No such audit chain in this organization."
        )
    result = await audit_service.verify_chain(db, chain_id=row.id)
    return AuditVerifyOut(
        chain_id=str(row.id),
        status=result.status,
        checked_events=result.checked_events,
        issues=[{"code": i.code, "seq": i.seq} for i in result.issues],
    )


# ── The one public mutation: submit an analysis request ──────────────


@router.post("/scans", response_model=ScanCreatedOut, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    body: ScanCreateRequest,
    request: Request,
    response: Response,
    key=Depends(require_api_scope("scans:create")),
    db: AsyncSession = Depends(get_db),
):
    """Submit an analysis request for a repository this organization owns.

    Returns `202 Accepted` with the scan id; the work happens in the worker.
    This endpoint is a REQUEST: it cannot approve, authorize, execute,
    verify or roll anything back, and it cannot name a repository outside
    the key's organization.

    Commit binding (V4.1): an optional `commit_sha` (full 40-hex) pins the
    request to a commit. The binding is VERIFIED by the worker against the
    actual clone; a mismatch fails the scan with COMMIT_MISMATCH rather
    than analyzing a different commit silently.

    Idempotency: supply an `Idempotency-Key` header and a retry replays the
    original outcome instead of creating a second scan.
    """
    await _rate_limit(
        request, response, key.organization_id, bucket=WRITE_BUCKET, limit=WRITE_LIMIT_PER_HOUR
    )

    # Quota (absolute daily ceiling) before any DB work.
    await _enforce_quota(db, request, key.organization_id, action="scans")

    idem_scope = "POST /api/v1/scans"
    client_key = idem.validate_client_key(request.headers.get("idempotency-key"))
    digest = idem.canonical_request_digest(body.model_dump())

    reservation: Optional[idem.Reservation] = None
    if client_key:
        reservation = await idem.reserve(
            db,
            organization_id=key.organization_id,
            scope=idem_scope,
            key_value=client_key,
            request_digest=digest,
            api_key_prefix=key.prefix,
        )
        if reservation.outcome == idem.OUTCOME_CONFLICT:
            metric("idempotency_conflicts_total")
            raise PublicApiError(
                409,
                "IDEMPOTENCY_KEY_REUSED",
                "This Idempotency-Key was used for a different request.",
            )
        if reservation.outcome == idem.OUTCOME_IN_PROGRESS:
            raise PublicApiError(
                409,
                "IDEMPOTENCY_IN_PROGRESS",
                "A request with this Idempotency-Key is still being processed.",
            )
        if reservation.outcome == idem.OUTCOME_REPLAY:
            return JSONResponse(
                status_code=reservation.status_code or status.HTTP_202_ACCEPTED,
                content=reservation.body or {},
            )

    # Authorize the resource THROUGH the organization (404 on mismatch, so
    # the endpoint cannot be used to discover other tenants' repositories).
    repository = (
        await db.execute(
            _org_repositories(key.organization_id).where(
                Repository.id
                == _uuid_or_400(body.repository_id, field_name="repository_id")
            )
        )
    ).scalar_one_or_none()
    if repository is None:
        raise PublicApiError(
            404, "REPOSITORY_NOT_FOUND", "No such repository in this organization."
        )
    if not repository.is_active:
        raise PublicApiError(
            409, "REPOSITORY_INACTIVE", "The repository is not active."
        )

    in_flight = (
        await db.execute(
            select(Scan).where(
                Scan.repository_id == repository.id,
                Scan.status.notin_(["COMPLETED", "FAILED"]),
            )
        )
    ).scalar_one_or_none()
    if in_flight is not None:
        raise PublicApiError(
            409,
            "SCAN_IN_PROGRESS",
            "An analysis is already running for this repository.",
            {"scan_id": str(in_flight.id)},
        )

    scan = Scan(
        repository_id=repository.id,
        status="QUEUED",
        trigger="api",
        requested_commit_sha=(body.commit_sha or None),
    )
    db.add(scan)
    await db.flush()

    payload = ScanCreatedOut(
        scan_id=str(scan.id),
        repository_id=str(repository.id),
        status=scan.status,
        reused=False,
    )

    # The reservation commits WITH the effect below, so "a scan exists" and
    # "we recorded that we created it" cannot diverge.
    try:
        from app.worker import enqueue_scan

        enqueue_scan(str(scan.id))
    except Exception as exc:  # noqa: BLE001 - surface, never swallow
        logger.error("api_scan_enqueue_failed scan=%s err=%s", scan.id, type(exc).__name__)
        scan.status = "FAILED"
        scan.error_reason = "ENQUEUE_FAILED"
        failure = PublicApiError(
            503, "ANALYSIS_UNAVAILABLE", "Analysis could not be queued. Try again."
        )
        if reservation is not None and reservation.owned:
            # Store EXACTLY what the client received (the public error
            # envelope), so a retry replays the original response rather
            # than a different-shaped body.
            await idem.complete(
                db,
                reservation,
                status_code=failure.status_code,
                body={
                    "detail": failure.code,
                    "code": failure.code,
                    "message": failure.message,
                    "request_id": getattr(request.state, "request_id", None),
                },
            )
        await db.commit()
        raise failure

    # Audit: the external boundary caused an analysis request. OPERATIONAL
    # criticality — the scan row is the security record; the chain event
    # is the integrity witness. Best-effort within the same transaction.
    try:
        await audit_service.emit_security_event(
            db,
            organization_id=key.organization_id,
            event_type="SCAN_REQUESTED",
            actor_type=audit_service.ActorType.SYSTEM,
            actor_id=key.prefix,
            repository_id=repository.id,
            reason_code=None,
            result="QUEUED",
            payload={
                "trigger": "api",
                "commit_binding": "REQUESTED" if body.commit_sha else "UNBOUND",
            },
        )
    except Exception as exc:  # noqa: BLE001 — audit must not crash intake
        logger.warning(
            "scan_request_audit_failed scan=%s err=%s", str(scan.id)[:8], type(exc).__name__
        )

    if reservation is not None and reservation.owned:
        await idem.complete(
            db, reservation, status_code=202, body=payload.model_dump()
        )
    await db.commit()
    metric("api_requests_total", {"outcome": "SCAN_CREATED"})
    metric("jobs_created_total", {"trigger": "api"})
    return payload
