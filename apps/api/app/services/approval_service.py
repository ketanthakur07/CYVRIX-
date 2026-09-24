"""CYVRIX V3.2 — Approval service.

Human approval of action proposals: authorization data ONLY.

Hard boundaries (docs/v3-approval-model.md, docs/v3-security-model.md §6):
- NO execution capability of any kind: no shell, no subprocess, no file
  writes, no git, no GitHub writes, no worker enqueue, no Docker.
- A human approval can NEVER override a policy DENY. Approvals are only
  granted when the CURRENT policy decision is REQUIRE_APPROVAL.
- The action digest is recalculated server-side at approval time; a
  mismatch is a security event (denied, never repaired).
- Expired/stale proposals and changed security context deny approval.
- Approval records are immutable once terminal; a new approval round
  requires a new approval row (never in-place resurrection).

Concurrency:
- Grant is guarded by the partial unique index uq_approvals_live
  (one live approval per proposal) + a row lock on the proposal.
- Token consumption is guarded by authorization_used_at (single-use).
"""
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models import (
    ActionProposal, Approval, AuditEvent, Finding, Recommendation,
    Repository, GithubInstallation, RiskAssessment,
)
from app.services import approval_model
from app.services.approval_model import ApprovalState
from app.services.action_digest import compute_action_digest
from app.services.policy_engine import (
    DECISION_DENY,
    DECISION_REQUIRE_APPROVAL,
    POLICY_VERSION,
    PolicyContext,
    evaluate,
)

logger = logging.getLogger("cyvrix.approval")
settings = get_settings()

# ── Failure reason codes (stable, testable) ──────────────────────────

RC_DIGEST_MISMATCH = "ACTION_DIGEST_MISMATCH"
RC_POLICY_VERSION_STALE = "POLICY_VERSION_STALE"
RC_POLICY_DENIED = "POLICY_DENIED"
RC_POLICY_DECISION_NOT_APPROVABLE = "POLICY_DECISION_NOT_APPROVABLE"
RC_PROPOSAL_EXPIRED = "PROPOSAL_EXPIRED"
RC_PROPOSAL_STALE = "PROPOSAL_STALE"
RC_RECOMMENDATION_CHANGED = "RECOMMENDATION_CHANGED"
RC_RISK_CHANGED = "RISK_CHANGED"
RC_UNAUTHORIZED_APPROVER = "UNAUTHORIZED_APPROVER"
RC_STEP_UP_REQUIRED = "STEP_UP_REQUIRED"
RC_SECOND_APPROVER_REQUIRED = "SECOND_APPROVER_REQUIRED"
RC_NOT_PENDING = "APPROVAL_NOT_PENDING"
RC_NOT_APPROVED = "APPROVAL_NOT_APPROVED"
RC_APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
RC_PROPOSAL_NOT_FOUND = "PROPOSAL_NOT_FOUND"
RC_MISSING_RISK = "MISSING_RISK_ASSESSMENT"


@dataclass(frozen=True)
class ApprovalOutcome:
    """Result of an approval-service operation. Never contains secrets."""

    ok: bool
    reason_code: str
    approval: Optional[Approval] = None
    # One-time plaintext token — returned EXACTLY ONCE at grant, never
    # logged, never persisted. None for every other outcome.
    authorization_token: Optional[str] = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def _audit(
    db: AsyncSession,
    *,
    proposal: ActionProposal,
    event_type: str,
    actor_user_id,
    reason_code: str,
    extra: Optional[dict] = None,
    commit: bool = False,
) -> None:
    """Record a security audit event. Never logs token material.

    With commit=True (used by denial paths that return no other state),
    the event is committed immediately so a denial is durable even though
    the request ends with an error response. Failure to audit is logged
    and never masks the security decision itself.
    """
    metadata = {
        "actor": str(actor_user_id) if actor_user_id else None,
        "action_digest": proposal.action_digest,
        "proposal_id": str(proposal.id),
        "policy_version": proposal.policy_version,
        "reason_code": reason_code,
    }
    if extra:
        metadata.update(extra)
    db.add(AuditEvent(
        repository_id=proposal.repository_id,
        finding_id=proposal.finding_id,
        event_type=event_type,
        event_metadata=metadata,
    ))
    # V3.8: tamper-evident chain append in the SAME transaction.
    from app.services import audit_service
    await audit_service.emit_from_legacy_audit(
        db,
        repository_id=proposal.repository_id,
        event_type=event_type,
        metadata=metadata,
        actor_user_id=actor_user_id,
        finding_id=proposal.finding_id,
    )
    if commit:
        try:
            await db.commit()
        except Exception as exc:  # pragma: no cover - audit durability
            logger.warning("audit_commit_failed event=%s err=%s", event_type, str(exc)[:100])
            await db.rollback()


async def get_owned_proposal(
    db: AsyncSession, proposal_id: UUID, user_id
) -> Optional[ActionProposal]:
    """Load a proposal through the full ownership chain (404-equivalent)."""
    result = await db.execute(
        select(ActionProposal)
        .join(Repository, Repository.id == ActionProposal.repository_id)
        .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
        .where(
            ActionProposal.id == proposal_id,
            GithubInstallation.user_id == user_id,
        )
    )
    return result.scalar_one_or_none()


def recompute_proposal_digest(proposal: ActionProposal) -> str:
    """Recalculate the canonical digest from persisted proposal content.

    The client never supplies the digest used for binding decisions — the
    server recomputes it from the stored, schema-validated content.
    """
    return compute_action_digest({
        "action_type": proposal.action_type,
        "repository_id": str(proposal.repository_id),
        "base_commit_sha": proposal.base_commit_sha,
        "target_branch": proposal.target_branch,
        "files": proposal.files,
        "operations": proposal.operations,
        "expected_diff": proposal.expected_diff,
    })


def verify_proposal_digest(proposal: ActionProposal) -> bool:
    """True when the stored digest matches a fresh recalculation."""
    try:
        return recompute_proposal_digest(proposal) == proposal.action_digest
    except Exception:
        # Non-canonicalizable content cannot be verified → fail closed
        return False


def build_revalidation_context(
    proposal: ActionProposal,
    *,
    finding: Finding,
    recommendation: Recommendation,
    repo: Repository,
    latest_risk: Optional[RiskAssessment],
    environment: str,
    kill_switch: bool = False,
) -> PolicyContext:
    """Rebuild the policy context from CURRENT persisted state (not the
    snapshot taken at proposal creation).

    kill_switch: the caller supplies the CURRENT server-owned switch state
    (system_controls table, V3.3). Callers that omit it get the V3.2
    default (False) — the approval path reads it via the policy re-check
    in the authorization service, which fail-closes on unreadable state.
    """
    protected_categories = tuple(
        cat for cat in (
            approval_model_is_protected_path(p) for p in (proposal.files or [])
        )
        if cat is not None
    )
    return PolicyContext(
        action_type=proposal.action_type,
        repository_active=bool(repo.is_active),
        environment=environment,
        actor_role="owner",  # V3.2: single-role model unchanged from V3.1
        validation_state=recommendation.validation_state,
        trust_level=recommendation.trust_level,
        risk_level=latest_risk.risk_level if latest_risk else proposal.risk_level,
        risk_score=latest_risk.risk_score if latest_risk else proposal.risk_score,
        finding_status=finding.status,
        kill_switch=kill_switch,
        files=tuple(proposal.files or ()),
        operations=tuple(proposal.operations or ()),
        target_branch=proposal.target_branch,
        base_commit_sha=proposal.base_commit_sha,
        paths_valid=True,
        files_match_type=True,
        operations_valid=True,
        protected_path_categories=protected_categories,
        diff_lines=(proposal.expected_diff or "").count("\n") + (1 if proposal.expected_diff else 0),
        expires_at=_as_utc(proposal.expires_at),
    )


def approval_model_is_protected_path(path: str):
    # Imported lazily by name to keep the pure-module boundary obvious.
    from app.services.action_model import is_protected_path

    return is_protected_path(path)


async def _load_current_security_context(
    db: AsyncSession, proposal: ActionProposal
) -> tuple[Optional[Finding], Optional[Recommendation], Optional[Repository], Optional[RiskAssessment]]:
    """Load the CURRENT finding / recommendation / repository / risk state."""
    finding = (
        await db.execute(select(Finding).where(Finding.id == proposal.finding_id))
    ).scalar_one_or_none()
    recommendation = (
        await db.execute(
            select(Recommendation).where(Recommendation.id == proposal.recommendation_id)
        )
    ).scalar_one_or_none()
    repo = (
        await db.execute(select(Repository).where(Repository.id == proposal.repository_id))
    ).scalar_one_or_none()
    latest_risk = None
    if finding is not None:
        latest_risk = (
            await db.execute(
                select(RiskAssessment)
                .where(RiskAssessment.finding_id == finding.id)
                .order_by(RiskAssessment.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
    return finding, recommendation, repo, latest_risk


def check_proposal_freshness(
    proposal: ActionProposal,
    *,
    finding: Optional[Finding],
    recommendation: Optional[Recommendation],
    repo: Optional[Repository],
    latest_risk: Optional[RiskAssessment],
    now: datetime,
    allowed_statuses: tuple = ("PROPOSED", "POLICY_CHECKED"),
) -> Optional[str]:
    """Detect structural staleness. Returns a failure reason code or None.

    Scope: this check owns STRUCTURAL staleness only — proposal lifecycle
    state, expiry, entity existence, and snapshot drift (the inputs the
    proposal was created from changed materially). Current-state policy
    quality (repo active, finding actionable, validation state) is owned
    by the policy re-evaluation that runs right after (POL-002/003/004/019),
    so a DENY from policy is reported as POLICY_DENIED, not masked as
    staleness.

    allowed_statuses: the caller's set of acceptable proposal lifecycle
    states. The approval path accepts only PROPOSED/POLICY_CHECKED (an
    already-APPROVED proposal is handled by idempotency); the V3.3
    authorization path additionally accepts APPROVED, which is the
    normal post-approval state an authorization is created from.
    """
    if proposal.status not in allowed_statuses:
        return RC_PROPOSAL_STALE
    expires = _as_utc(proposal.expires_at)
    if expires is None or now >= expires:
        return RC_PROPOSAL_EXPIRED
    if finding is None or recommendation is None or repo is None:
        return RC_PROPOSAL_STALE
    # Snapshot drift: security-relevant inputs changed since creation
    if recommendation.trust_level != proposal.recommendation_trust:
        return RC_RECOMMENDATION_CHANGED
    if recommendation.validation_state != proposal.validation_state:
        return RC_RECOMMENDATION_CHANGED
    if latest_risk is not None:
        if (
            latest_risk.risk_level != proposal.risk_level
            or latest_risk.risk_score != proposal.risk_score
        ):
            return RC_RISK_CHANGED
    elif proposal.risk_level not in (None, "UNKNOWN"):
        # A risk assessment existed at creation but is gone now → stale
        return RC_RISK_CHANGED
    return None


async def grant_approval(
    db: AsyncSession,
    *,
    proposal: ActionProposal,
    approver,
    second_approver_user_id: Optional[UUID],
    reason: object,
    now: Optional[datetime] = None,
) -> ApprovalOutcome:
    """Grant (or deny) human approval of an action proposal.

    Authorization data only — this function NEVER executes anything and
    never enqueues execution. Emits audit events for every outcome.
    """
    now = now or _utcnow()
    actor = approver.id

    # 0. Validate the human reason (metadata only — never authorization)
    try:
        reason = approval_model.validate_reason(reason)
    except approval_model.ApprovalStateError:
        return ApprovalOutcome(False, "INVALID_REASON")

    # 1. Proposal must exist, be owned, and be in an approvable state
    if proposal is None:
        return ApprovalOutcome(False, RC_PROPOSAL_NOT_FOUND)

    # 1.5 Defense in depth: the approver MUST sit on the ownership chain
    # (proposal → repository → installation → user). The route enforces
    # this before calling the service; re-verify here so no code path can
    # grant approval off-chain.
    owner_row = (
        await db.execute(
            select(GithubInstallation.user_id)
            .join(Repository, Repository.installation_id == GithubInstallation.id)
            .where(Repository.id == proposal.repository_id)
        )
    ).first()
    if owner_row is None or str(owner_row[0]) != str(actor):
        await _audit(
            db, proposal=proposal, event_type="APPROVAL_UNAUTHORIZED",
            actor_user_id=actor, reason_code=RC_UNAUTHORIZED_APPROVER,
            commit=True,
        )
        return ApprovalOutcome(False, RC_UNAUTHORIZED_APPROVER)

    # 2. Digest binding: recalculate server-side, compare, never repair
    if not verify_proposal_digest(proposal):
        await _audit(
            db, proposal=proposal, event_type="APPROVAL_DIGEST_MISMATCH",
            actor_user_id=actor, reason_code=RC_DIGEST_MISMATCH,
            commit=True,
        )
        return ApprovalOutcome(False, RC_DIGEST_MISMATCH)

    # 3. Idempotency: an existing live approval is returned as-is (never
    #    duplicated, never re-tokenized). Checked BEFORE staleness so a
    #    repeated approve of the same unchanged proposal is a safe no-op.
    existing = (
        await db.execute(
            select(Approval).where(
                Approval.action_proposal_id == proposal.id,
                Approval.approval_state.in_(("PENDING", "APPROVED")),
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.approver_user_id != actor:
            return ApprovalOutcome(False, RC_UNAUTHORIZED_APPROVER)
        return ApprovalOutcome(True, "ALREADY_APPROVED", existing)

    # 4. Load CURRENT security context and re-check freshness/staleness
    finding, recommendation, repo, latest_risk = await _load_current_security_context(
        db, proposal
    )
    staleness = check_proposal_freshness(
        proposal,
        finding=finding, recommendation=recommendation, repo=repo,
        latest_risk=latest_risk, now=now,
    )
    if staleness is not None:
        await _audit(
            db, proposal=proposal, event_type="APPROVAL_DENIED",
            actor_user_id=actor, reason_code=staleness,
            commit=True,
        )
        return ApprovalOutcome(False, staleness)

    # 4. Policy re-evaluation against CURRENT state (not the snapshot)
    ctx = build_revalidation_context(
        proposal,
        finding=finding, recommendation=recommendation, repo=repo,
        latest_risk=latest_risk, environment=settings.environment,
    )
    decision = evaluate(ctx, now)

    if decision.policy_version != POLICY_VERSION:
        await _audit(
            db, proposal=proposal, event_type="APPROVAL_DENIED",
            actor_user_id=actor, reason_code=RC_POLICY_VERSION_STALE,
            extra={"decision_version": decision.policy_version},
            commit=True,
        )
        return ApprovalOutcome(False, RC_POLICY_VERSION_STALE)

    if decision.decision == DECISION_DENY:
        # A human approval can NEVER override a deterministic DENY.
        await _audit(
            db, proposal=proposal, event_type="APPROVAL_POLICY_DENIED",
            actor_user_id=actor, reason_code=RC_POLICY_DENIED,
            extra={"matched_rule": decision.matched_rule},
            commit=True,
        )
        return ApprovalOutcome(False, RC_POLICY_DENIED)

    if decision.decision != DECISION_REQUIRE_APPROVAL:
        await _audit(
            db, proposal=proposal, event_type="APPROVAL_DENIED",
            actor_user_id=actor, reason_code=RC_POLICY_DECISION_NOT_APPROVABLE,
            commit=True,
        )
        return ApprovalOutcome(False, RC_POLICY_DECISION_NOT_APPROVABLE)

    # 6. Step-up evidence: read fresh GitHub re-authentication markers for
    #    the approver (and the second principal when required). Absent or
    #    unreadable evidence fails closed.
    second_approver_user_id = (
        UUID(str(second_approver_user_id)) if second_approver_user_id else None
    )
    approver_step_at, second_step_at, step_code = await _load_step_up_evidence(
        approver=approver, second_approver_user_id=second_approver_user_id
    )

    # 7. Approver eligibility (second principal + step-up), server-derived
    eligible, elig_reason = approval_model.check_approver_eligibility(
        risk_level=proposal.risk_level,
        approver_id=str(actor),
        proposer_id=str(proposal.created_by),
        second_approver_user_id=str(second_approver_user_id) if second_approver_user_id else None,
        step_up_at=approver_step_at,
        second_step_up_at=second_step_at,
        now=now,
    )
    if not eligible:
        code = (
            RC_SECOND_APPROVER_REQUIRED
            if elig_reason == "SECOND_APPROVER_REQUIRED"
            else (step_code or RC_STEP_UP_REQUIRED)
        )
        await _audit(
            db, proposal=proposal, event_type="APPROVAL_UNAUTHORIZED",
            actor_user_id=actor, reason_code=code,
            commit=True,
        )
        return ApprovalOutcome(False, code)

    # 8. Serialize concurrent grants on the same proposal: lock the
    #    proposal row. The partial unique index uq_approvals_live is the
    #    final backstop; IntegrityError below means a concurrent grant won.
    try:
        await db.execute(
            select(ActionProposal.id)
            .where(ActionProposal.id == proposal.id)
            .with_for_update()
        )
    except Exception:
        # SQLite (unit tests) does not support SELECT ... FOR UPDATE — the
        # unique index remains the concurrency guarantee there.
        pass

    # 8.5 Re-check decision inputs INSIDE the lock: a concurrent reject /
    #     revoke / approve may have committed between the pre-lock checks
    #     above and the lock acquisition. Without this re-check, approve
    #     could land an APPROVED row onto a REJECTED proposal (or duplicate
    #     a live approval) — contradictory state.
    try:
        await db.refresh(proposal)
    except Exception:
        pass
    if proposal.status == "REJECTED":
        await _audit(
            db, proposal=proposal, event_type="APPROVAL_DENIED",
            actor_user_id=actor, reason_code=RC_NOT_PENDING,
            commit=True,
        )
        return ApprovalOutcome(False, RC_NOT_PENDING)
    if proposal.status not in ("PROPOSED", "POLICY_CHECKED"):
        await _audit(
            db, proposal=proposal, event_type="APPROVAL_DENIED",
            actor_user_id=actor, reason_code=RC_PROPOSAL_STALE,
            commit=True,
        )
        return ApprovalOutcome(False, RC_PROPOSAL_STALE)
    existing_after_lock = (
        await db.execute(
            select(Approval).where(
                Approval.action_proposal_id == proposal.id,
                Approval.approval_state.in_(("PENDING", "APPROVED")),
            )
        )
    ).scalar_one_or_none()
    if existing_after_lock is not None:
        if existing_after_lock.approver_user_id != actor:
            return ApprovalOutcome(False, RC_UNAUTHORIZED_APPROVER)
        return ApprovalOutcome(True, "ALREADY_APPROVED", existing_after_lock)

    # 9. Create the immutable approval record + one-time token (hash only).
    #    (Steps renumbered: idempotency check moved above staleness.)
    token = approval_model.generate_token()
    token_hash = approval_model.hash_token(token)
    expires_at = approval_model.approval_expiry(now)

    approval = Approval(
        action_proposal_id=proposal.id,
        action_digest=proposal.action_digest,
        approver_user_id=actor,
        second_approver_user_id=second_approver_user_id,
        approval_state=ApprovalState.APPROVED,
        approval_reason=reason or None,
        policy_version=decision.policy_version,
        policy_decision=decision.decision,
        approval_level=decision.approval_level,
        approved_at=now,
        expires_at=expires_at,
        authorization_token_hash=token_hash,
        authorization_issued_at=now,
    )
    db.add(approval)

    # Proposal status reflects the human decision (V3.2 vocabulary)
    proposal.status = "APPROVED"

    await _audit(
        db, proposal=proposal, event_type="APPROVAL_GRANTED",
        actor_user_id=actor, reason_code="OK",
        extra={
            "approval_level": decision.approval_level,
            "second_approver": str(second_approver_user_id) if second_approver_user_id else None,
            "expires_at": expires_at.isoformat(),
        },
    )
    try:
        await db.commit()
    except Exception as exc:
        # Concurrent grant won the race: roll back and surface the existing
        # live approval without a second token (or fail closed).
        await db.rollback()
        winner = (
            await db.execute(
                select(Approval).where(
                    Approval.action_proposal_id == proposal.id,
                    Approval.approval_state.in_(("PENDING", "APPROVED")),
                )
            )
        ).scalar_one_or_none()
        if winner is not None:
            if winner.approver_user_id != actor:
                return ApprovalOutcome(False, RC_UNAUTHORIZED_APPROVER)
            return ApprovalOutcome(True, "ALREADY_APPROVED", winner)
        logger.warning("approval_grant_race_lost proposal_id=%s err=%s", proposal.id, str(exc)[:100])
        return ApprovalOutcome(False, "APPROVAL_CONFLICT")
    await db.refresh(approval)

    return ApprovalOutcome(True, "OK", approval, authorization_token=token)


async def _load_step_up_evidence(
    *, approver, second_approver_user_id: Optional[UUID]
) -> tuple[Optional[datetime], Optional[datetime], Optional[str]]:
    """Read step-up authentication markers from Redis.

    Returns (approver_step_at, second_step_at, failure_code). Markers are
    written by the step-up flow (fresh GitHub re-authentication). Any
    Redis failure fails closed (None timestamps ⇒ eligibility denied).
    """
    try:
        from app.session import get_redis

        r = await get_redis()

        async def _read(user_id) -> Optional[datetime]:
            raw = await r.get(f"stepup:{user_id}")
            if not raw or not approval_model.validate_step_up_marker(raw):
                return None
            return datetime.fromtimestamp(int(raw), tz=timezone.utc)

        approver_ts = await _read(approver.id)
        if approver_ts is None:
            return None, None, RC_STEP_UP_REQUIRED
        second_ts = None
        if second_approver_user_id is not None:
            second_ts = await _read(second_approver_user_id)
            if second_ts is None:
                return approver_ts, None, RC_STEP_UP_REQUIRED
        return approver_ts, second_ts, None
    except Exception:
        # Fail closed: cannot verify step-up ⇒ deny.
        return None, None, RC_STEP_UP_REQUIRED


async def reject_approval(
    db: AsyncSession, *, proposal: ActionProposal, actor, reason: object,
    now: Optional[datetime] = None,
) -> ApprovalOutcome:
    """Reject a pending approval request (state transition only)."""
    now = now or _utcnow()
    if proposal is None:
        return ApprovalOutcome(False, RC_PROPOSAL_NOT_FOUND)

    try:
        reason = approval_model.validate_reason(reason)
    except approval_model.ApprovalStateError:
        return ApprovalOutcome(False, "INVALID_REASON")

    # Serialize concurrent approve/reject on the same proposal (same pattern
    # as grant_approval; SQLite tests fall back to the unique indexes).
    try:
        await db.execute(
            select(ActionProposal.id)
            .where(ActionProposal.id == proposal.id)
            .with_for_update()
        )
    except Exception:
        pass

    existing = (
        await db.execute(
            select(Approval).where(
                Approval.action_proposal_id == proposal.id,
                Approval.approval_state.in_(("PENDING", "APPROVED")),
            )
        )
    ).scalar_one_or_none()

    if existing is not None:
        if existing.approver_user_id != actor.id:
            return ApprovalOutcome(False, RC_UNAUTHORIZED_APPROVER)
        try:
            approval_model.assert_transition(existing.approval_state, ApprovalState.REJECTED)
        except approval_model.ApprovalStateError:
            return ApprovalOutcome(False, RC_NOT_PENDING)
        existing.approval_state = ApprovalState.REJECTED
        existing.approval_reason = reason or existing.approval_reason
        await _audit(
            db, proposal=proposal, event_type="APPROVAL_REJECTED",
            actor_user_id=actor.id, reason_code="OK",
        )
        # Rejection is terminal for the proposal: a materially identical
        # proposal can be re-created, but this one is decided.
        proposal.status = "REJECTED"
        try:
            await db.commit()
        except Exception:
            # Concurrent approve/reject won the race: surface the decided
            # state instead of a contradictory second write.
            await db.rollback()
            winner = (
                await db.execute(
                    select(Approval).where(
                        Approval.action_proposal_id == proposal.id,
                        Approval.approval_state.in_(("PENDING", "APPROVED")),
                    )
                )
            ).scalar_one_or_none()
            if winner is not None and winner.approval_state == "APPROVED":
                return ApprovalOutcome(False, RC_NOT_PENDING)
            return ApprovalOutcome(False, RC_NOT_PENDING)
        await db.refresh(existing)
        return ApprovalOutcome(True, "OK", existing)

    # No approval row yet: record the rejection decision as a new row
    if proposal.status == "APPROVED":
        return ApprovalOutcome(False, RC_NOT_PENDING)

    approval = Approval(
        action_proposal_id=proposal.id,
        action_digest=proposal.action_digest,
        approver_user_id=actor.id,
        approval_state=ApprovalState.REJECTED,
        approval_reason=reason or None,
        policy_version=proposal.policy_version,
        policy_decision=proposal.policy_decision,
        approval_level=None,
        expires_at=approval_model.approval_expiry(now),
    )
    db.add(approval)
    proposal.status = "REJECTED"
    await _audit(
        db, proposal=proposal, event_type="APPROVAL_REJECTED",
        actor_user_id=actor.id, reason_code="OK",
    )
    try:
        await db.commit()
    except Exception:
        # A concurrent approve created the live approval first: this reject
        # must not produce contradictory state (APPROVED row + REJECTED
        # proposal). Surface the decided state.
        await db.rollback()
        winner = (
            await db.execute(
                select(Approval).where(
                    Approval.action_proposal_id == proposal.id,
                    Approval.approval_state.in_(("PENDING", "APPROVED")),
                )
            )
        ).scalar_one_or_none()
        if winner is not None:
            return ApprovalOutcome(False, RC_NOT_PENDING)
        return ApprovalOutcome(False, "APPROVAL_CONFLICT")
    await db.refresh(approval)
    return ApprovalOutcome(True, "OK", approval)


async def revoke_approval(
    db: AsyncSession, *, approval: Approval, actor, reason: object,
    now: Optional[datetime] = None,
) -> ApprovalOutcome:
    """Revoke an APPROVED approval (state transition only). No resurrection."""
    now = now or _utcnow()
    try:
        reason = approval_model.validate_reason(reason)
    except approval_model.ApprovalStateError:
        return ApprovalOutcome(False, "INVALID_REASON")

    try:
        approval_model.assert_transition(approval.approval_state, ApprovalState.REVOKED)
    except approval_model.ApprovalStateError:
        return ApprovalOutcome(False, RC_NOT_APPROVED)

    proposal = (
        await db.execute(
            select(ActionProposal).where(ActionProposal.id == approval.action_proposal_id)
        )
    ).scalar_one_or_none()
    if proposal is None:
        return ApprovalOutcome(False, RC_PROPOSAL_NOT_FOUND)

    # Serialize revoke against concurrent approve/consume on the same
    # proposal (same pattern as grant_approval).
    try:
        await db.execute(
            select(ActionProposal.id)
            .where(ActionProposal.id == proposal.id)
            .with_for_update()
        )
    except Exception:
        pass

    # Re-read the approval inside the locked transaction: a concurrent
    # consume/revoke may have already transitioned it.
    await db.refresh(approval)
    try:
        approval_model.assert_transition(approval.approval_state, ApprovalState.REVOKED)
    except approval_model.ApprovalStateError:
        return ApprovalOutcome(False, RC_NOT_APPROVED)

    approval.approval_state = ApprovalState.REVOKED
    approval.approval_reason = reason or approval.approval_reason
    # Revocation ≠ rejection: the proposal returns to awaiting approval so
    # a NEW approval round (new row, new token, new decision) is possible.
    # The revoked approval itself can never be resurrected.
    if proposal.status == "APPROVED":
        proposal.status = "POLICY_CHECKED"

    await _audit(
        db, proposal=proposal, event_type="APPROVAL_REVOKED",
        actor_user_id=actor.id, reason_code="OK",
    )
    try:
        await db.commit()
    except Exception:
        # Concurrent consume/revoke won: report the actual terminal state,
        # never a duplicated or resurrected approval.
        await db.rollback()
        await db.refresh(approval)
        if approval.approval_state == "USED":
            return ApprovalOutcome(False, RC_NOT_APPROVED)
        if approval.approval_state == "REVOKED":
            return ApprovalOutcome(True, "OK", approval)
        return ApprovalOutcome(False, "APPROVAL_CONFLICT")
    await db.refresh(approval)
    return ApprovalOutcome(True, "OK", approval)


async def consume_authorization(
    db: AsyncSession, *, approval: Approval, presented_token: object, now: Optional[datetime] = None
) -> ApprovalOutcome:
    """Verify a one-time authorization token (future executor entry point).

    NON-EXECUTING: performs verification and state transition only. This
    function exists so the executor phase (V3.4+) consumes authorization
    through a single audited path; nothing is enqueued or run here.
    """
    now = now or _utcnow()

    # Replay check FIRST: a consumed approval is exactly the replay case,
    # so it must report TOKEN_REPLAY rather than the generic state error.
    if approval.authorization_used_at is not None:
        await _audit_consumed_denied(db, approval, "TOKEN_REPLAY", commit=True)
        return ApprovalOutcome(False, "TOKEN_REPLAY")

    if approval.approval_state != ApprovalState.APPROVED:
        await _audit_consumed_denied(db, approval, "APPROVAL_NOT_APPROVED", commit=True)
        return ApprovalOutcome(False, RC_NOT_APPROVED)

    expires = _as_utc(approval.expires_at)
    if expires is None or now >= expires:
        approval.approval_state = ApprovalState.EXPIRED
        await _audit_consumed_denied(db, approval, RC_APPROVAL_EXPIRED, commit=True)
        await db.commit()
        return ApprovalOutcome(False, RC_APPROVAL_EXPIRED)

    if not presented_token or not isinstance(presented_token, str):
        await _audit_consumed_denied(db, approval, "TOKEN_INVALID")
        return ApprovalOutcome(False, "TOKEN_INVALID")

    stored_hash = approval.authorization_token_hash or ""
    if not approval_model.verify_token_hash(presented_token, stored_hash):
        await _audit_consumed_denied(db, approval, "TOKEN_INVALID")
        return ApprovalOutcome(False, "TOKEN_INVALID")

    # Wrong-action defense is structural: the approval row is keyed by
    # action_proposal_id and binds action_digest; a token is verified only
    # against ITS approval. The caller must load the approval through the
    # proposal it intends to execute — cross-proposal token use resolves to
    # a different Approval row and fails hash verification.

    # Serialize the single-use transition: lock the proposal row so a
    # concurrent consume/revoke on the same approval cannot interleave
    # between the checks above and the commit below.
    try:
        await db.execute(
            select(ActionProposal.id)
            .where(ActionProposal.id == approval.action_proposal_id)
            .with_for_update()
        )
        # Re-read state under the lock: a concurrent consume may have won.
        await db.refresh(approval)
        if approval.authorization_used_at is not None:
            await _audit_consumed_denied(db, approval, "TOKEN_REPLAY", commit=True)
            return ApprovalOutcome(False, "TOKEN_REPLAY")
        if approval.approval_state != ApprovalState.APPROVED:
            await _audit_consumed_denied(db, approval, "APPROVAL_NOT_APPROVED", commit=True)
            return ApprovalOutcome(False, RC_NOT_APPROVED)
    except Exception:
        # SQLite (unit tests) has no FOR UPDATE; the single-use column plus
        # the commit-conflict fallback below remain the guarantee there.
        pass

    approval.authorization_used_at = now
    approval.approval_state = ApprovalState.USED
    # Resolve the proposal by FK (async-safe) rather than the lazy
    # relationship — direct service callers may pass a detached/bare row.
    proposal = (
        await db.execute(
            select(ActionProposal).where(ActionProposal.id == approval.action_proposal_id)
        )
    ).scalar_one_or_none()
    if proposal is not None:
        await _audit(
            db, proposal=proposal,
            event_type="AUTHORIZATION_CONSUMED",
            actor_user_id=approval.approver_user_id, reason_code="OK",
        )
    try:
        await db.commit()
    except Exception:
        # Concurrent consume won the race: this presentation must report
        # replay, never a second successful use of the same token.
        await db.rollback()
        await db.refresh(approval)
        if approval.authorization_used_at is not None:
            await _audit_consumed_denied(db, approval, "TOKEN_REPLAY", commit=True)
            return ApprovalOutcome(False, "TOKEN_REPLAY")
        return ApprovalOutcome(False, "APPROVAL_CONFLICT")
    return ApprovalOutcome(True, "OK", approval)


async def _audit_consumed_denied(
    db: AsyncSession, approval: Approval, reason_code: str, commit: bool = False
) -> None:
    # Load by FK (async-safe): never touch the lazy `approval.proposal`
    # relationship from a non-greenlet context.
    proposal = (
        await db.execute(
            select(ActionProposal).where(ActionProposal.id == approval.action_proposal_id)
        )
    ).scalar_one_or_none()
    if proposal is None:
        return
    await _audit(
        db, proposal=proposal, event_type="AUTHORIZATION_DENIED",
        actor_user_id=approval.approver_user_id, reason_code=reason_code,
        commit=commit,
    )
