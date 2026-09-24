"""CYVRIX V3.3 — Execution authorization service.

The FINAL DETERMINISTIC AUTHORIZATION CONTRACT between an APPROVED action
and FUTURE EXECUTION. Answers exactly one question:

    "Is this exact action still authorized to execute RIGHT NOW?"

The answer is produced from trusted server-side state only. V3.3 does NOT
execute the action: no shell, no subprocess, no file writes, no git, no
GitHub writes, no Docker, no sandbox, no worker enqueue, no credentials
issued. The only outputs are EXECUTION_AUTHORIZED / EXECUTION_DENIED plus
structured audit events.

Trust hierarchy (docs/v3-execution-authorization.md §2):
    SYSTEM SECURITY POLICY > DATABASE TRUSTED STATE > DETERMINISTIC POLICY
    ENGINE > APPROVAL RECORD > ACTION PROPOSAL > CLIENT REQUEST

Flow (§5):
    authenticate → load proposal → load approval → ownership → states →
    expiries → digest recompute ×3-way → policy re-eval → kill switch →
    (authorize: create contract record) or (consume: atomic one-time
    transition) → audit → AUTHORIZED/DENIED

Every denial is audited. The client request is never trusted for any
security-relevant value.
"""
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models import (
    ActionProposal, Approval, AuditEvent, ExecutionAuthorization,
    Finding, Recommendation, Repository, GithubInstallation,
    RiskAssessment, SystemControl,
)
from app.services import approval_model, execution_authorization_model as eam
from app.services.approval_model import ApprovalState
from app.services.action_digest import compute_action_digest
from app.services.approval_service import (
    RC_DIGEST_MISMATCH as _APPROVAL_DIGEST_RC,
    build_revalidation_context,
    check_proposal_freshness,
    verify_proposal_digest,
)
from app.services.policy_engine import (
    DECISION_DENY,
    DECISION_REQUIRE_APPROVAL,
    POLICY_VERSION,
    PolicyContext,
    evaluate,
)
from app.services.execution_authorization_model import (
    AuthorizationState,
    RC_ACTION_DIGEST_MISMATCH,
    RC_ACTION_EXPIRED,
    RC_ACTION_NOT_FOUND,
    RC_ACTION_STALE,
    RC_APPROVAL_DIGEST_MISMATCH,
    RC_APPROVAL_EXPIRED,
    RC_APPROVAL_INVALID,
    RC_APPROVAL_REVOKED,
    RC_AUTHORIZATION_NOT_FOUND,
    RC_AUTHORIZATION_REPLAY,
    RC_CONTRACT_DIGEST_MISMATCH,
    RC_CONTRACT_INVALID,
    RC_KILL_SWITCH_ACTIVE,
    RC_NOT_AUTHORIZED,
    RC_POLICY_DENIED,
    RC_POLICY_VERSION_STALE,
    RC_RECOMMENDATION_CHANGED,
    RC_RISK_CHANGED,
    RC_TOKEN_INVALID,
    RC_TOKEN_REPLAY,
    RC_UNAUTHORIZED_CONSUMER,
)

logger = logging.getLogger("cyvrix.execution_auth")
settings = get_settings()

KILL_SWITCH_KEY = "execution_disabled"

# Outcome reason codes (service-level; contract codes live in the model)
OK = "OK"
RC_CONSUMED = "CONSUMED"


@dataclass(frozen=True)
class AuthorizationOutcome:
    """Result of an authorization-service operation. Never contains
    secrets, never contains executable content."""

    ok: bool
    reason_code: str
    authorization: Optional[ExecutionAuthorization] = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


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
    """Record a security audit event. Never logs token or credential material.

    Audit ordering (§35): every path that returns AUTHORIZED/CONSUMED has
    the corresponding audit event in the SAME transaction as the state
    change — the commit is all-or-nothing, so an authorization record can
    never exist without its durable audit event and vice versa. Pure
    denial paths commit the event before returning the error response.
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
    # V3.8: tamper-evident chain append in the SAME transaction (the
    # §35 all-or-nothing guarantee now covers the integrity chain too).
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
    db: AsyncSession, proposal_id, user_id
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


async def get_owned_authorization(
    db: AsyncSession, authorization_id, user_id
) -> Optional[ExecutionAuthorization]:
    """Load an authorization through the full ownership chain."""
    result = await db.execute(
        select(ExecutionAuthorization)
        .join(ActionProposal, ActionProposal.id == ExecutionAuthorization.action_proposal_id)
        .join(Repository, Repository.id == ActionProposal.repository_id)
        .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
        .where(
            ExecutionAuthorization.id == authorization_id,
            GithubInstallation.user_id == user_id,
        )
    )
    return result.scalar_one_or_none()


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


async def read_kill_switch(db: AsyncSession) -> tuple[bool, Optional[str]]:
    """Read the server-owned kill switch (system_controls table).

    Returns (disabled, failure_reason). FAIL CLOSED: a missing row is a
    hard failure (unprovisioned control), a read error is a hard failure,
    and any value other than the exact string 'false' counts as disabled.
    """
    try:
        row = (
            await db.execute(
                select(SystemControl).where(SystemControl.key == KILL_SWITCH_KEY)
            )
        ).scalar_one_or_none()
    except Exception as exc:
        return True, f"KILL_SWITCH_READ_FAILED:{type(exc).__name__}"
    if row is None:
        return True, "KILL_SWITCH_UNPROVISIONED"
    if row.value != "false":
        return True, None
    return False, None


def build_contract(
    authorization_id: str,
    proposal: ActionProposal,
    approval: Approval,
    authorized_at: datetime,
) -> eam.ExecutionAuthorizationContract:
    """Build the frozen, non-executable authorization contract (§26/§27).

    Scope is copied verbatim from the digest-verified proposal — the
    contract authorizes, it never describes HOW to execute. No commands,
    no paths to binaries, no credentials, no URLs, no secrets.
    """
    return eam.ExecutionAuthorizationContract(
        contract_version=eam.CONTRACT_VERSION,
        authorization_id=authorization_id,
        action_proposal_id=str(proposal.id),
        approval_id=str(approval.id),
        action_digest=proposal.action_digest,
        repository_id=str(proposal.repository_id),
        base_commit_sha=proposal.base_commit_sha,
        target_branch=proposal.target_branch,
        policy_version=approval.policy_version,
        policy_decision=approval.policy_decision,
        allowed_files=tuple(proposal.files or ()),
        allowed_operations=tuple(
            (op.get("type") if isinstance(op, dict) else str(op))
            for op in (proposal.operations or ())
        ),
        authorized_at=authorized_at.isoformat(),
        expires_at=approval.expires_at.isoformat() if approval.expires_at else "",
    )


def _context_digest(proposal: ActionProposal, approval: Approval, decision) -> str:
    """Security-context digest (§21): binds the decision to the full
    security context. Strengthens TOCTOU resistance; never replaces the
    action digest, which is checked separately."""
    from app.services.action_digest import generic_canonical_bytes

    ctx = {
        "action_digest": proposal.action_digest,
        "policy_version": decision.policy_version,
        "policy_decision": decision.decision,
        "policy_matched_rule": decision.matched_rule,
        "recommendation_id": str(proposal.recommendation_id),
        "validation_state": proposal.validation_state,
        "trust_level": proposal.recommendation_trust,
        "risk_level": proposal.risk_level,
        "risk_score": proposal.risk_score,
        "base_commit_sha": proposal.base_commit_sha,
        "approval_id": str(approval.id),
        "approval_digest": approval.action_digest,
    }
    import hashlib
    return hashlib.sha256(generic_canonical_bytes(ctx)).hexdigest()


async def authorize_execution(
    db: AsyncSession,
    *,
    proposal: ActionProposal,
    actor,
    now: Optional[datetime] = None,
) -> AuthorizationOutcome:
    """Create the execution authorization record for an APPROVED action.

    NON-EXECUTING: validates every security invariant server-side and
    writes an immutable authorization record. Nothing is enqueued, run,
    or written to any repository. The approval is NOT consumed here —
    one-time consumption happens at `consume_authorization` with the
    one-time token presented.
    """
    now = now or _utcnow()
    actor_id = actor.id

    # 0. Proposal must exist (route already enforced ownership)
    if proposal is None:
        return AuthorizationOutcome(False, RC_ACTION_NOT_FOUND)

    # 1. Kill switch FIRST (§22): emergency stop precedes everything.
    disabled, ks_reason = await read_kill_switch(db)
    if disabled:
        await _audit(
            db, proposal=proposal, event_type="EXECUTION_AUTHORIZATION_DENIED",
            actor_user_id=actor_id,
            reason_code=ks_reason or RC_KILL_SWITCH_ACTIVE,
            commit=True,
        )
        return AuthorizationOutcome(False, RC_KILL_SWITCH_ACTIVE)

    # 2. Digest revalidation — server recalculates, never trusts stored
    #    digest alone, never repairs a mismatch (§11).
    if not verify_proposal_digest(proposal):
        await _audit(
            db, proposal=proposal, event_type="EXECUTION_DIGEST_MISMATCH",
            actor_user_id=actor_id, reason_code=RC_ACTION_DIGEST_MISMATCH,
            commit=True,
        )
        return AuthorizationOutcome(False, RC_ACTION_DIGEST_MISMATCH)

    # 3. Load the approval bound to this proposal (§15)
    approval = (
        await db.execute(
            select(Approval).where(
                Approval.action_proposal_id == proposal.id,
                Approval.approval_state == ApprovalState.APPROVED,
            )
        )
    ).scalar_one_or_none()
    if approval is None:
        await _audit(
            db, proposal=proposal, event_type="EXECUTION_AUTHORIZATION_DENIED",
            actor_user_id=actor_id, reason_code=RC_APPROVAL_INVALID,
            commit=True,
        )
        return AuthorizationOutcome(False, RC_APPROVAL_INVALID)

    # 4. Approval ↔ proposal ↔ recomputed digest must agree three ways (§12)
    if approval.action_digest != proposal.action_digest:
        await _audit(
            db, proposal=proposal, event_type="EXECUTION_DIGEST_MISMATCH",
            actor_user_id=actor_id, reason_code=RC_APPROVAL_DIGEST_MISMATCH,
            commit=True,
        )
        return AuthorizationOutcome(False, RC_APPROVAL_DIGEST_MISMATCH)

    # 5. Approval must be unconsumed, unrevoked, unexpired (§15)
    if approval.authorization_used_at is not None:
        await _audit(
            db, proposal=proposal, event_type="EXECUTION_AUTHORIZATION_DENIED",
            actor_user_id=actor_id, reason_code=eam.RC_APPROVAL_CONSUMED,
            commit=True,
        )
        return AuthorizationOutcome(False, eam.RC_APPROVAL_CONSUMED)
    if approval.approval_state != ApprovalState.APPROVED:
        # REVOKED / EXPIRED / USED / PENDING approvals authorize nothing.
        code = RC_APPROVAL_REVOKED if approval.approval_state == ApprovalState.REVOKED else RC_APPROVAL_INVALID
        await _audit(
            db, proposal=proposal, event_type="EXECUTION_AUTHORIZATION_DENIED",
            actor_user_id=actor_id, reason_code=code,
            commit=True,
        )
        return AuthorizationOutcome(False, code)
    if approval_model.is_approval_expired(approval.expires_at, now):
        # Reconcile: an approval whose window closed is EXPIRED, always.
        approval.approval_state = ApprovalState.EXPIRED
        await _audit(
            db, proposal=proposal, event_type="EXECUTION_AUTHORIZATION_DENIED",
            actor_user_id=actor_id, reason_code=RC_APPROVAL_EXPIRED,
            commit=True,
        )
        try:
            await db.commit()
        except Exception:
            await db.rollback()
        return AuthorizationOutcome(False, RC_APPROVAL_EXPIRED)

    # 6. Idempotency: an existing live authorization is returned as-is
    #    (repeated valid requests never duplicate records).
    existing = (
        await db.execute(
            select(ExecutionAuthorization).where(
                ExecutionAuthorization.action_proposal_id == proposal.id,
                ExecutionAuthorization.authorization_state == AuthorizationState.AUTHORIZED,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return AuthorizationOutcome(True, "ALREADY_AUTHORIZED", existing)

    # 7. Current security context + structural staleness (§16/§17/§18)
    finding, recommendation, repo, latest_risk = await _load_current_security_context(
        db, proposal
    )
    staleness = check_proposal_freshness(
        proposal,
        finding=finding, recommendation=recommendation, repo=repo,
        latest_risk=latest_risk, now=now,
        # APPROVED is the normal post-approval state an authorization is
        # created from; PROPOSED/POLICY_CHECKED remain acceptable so a
        # proposal approved under an older flow still authorizes.
        allowed_statuses=("PROPOSED", "POLICY_CHECKED", "APPROVED"),
    )
    if staleness is not None:
        code = (
            RC_ACTION_EXPIRED if staleness == "PROPOSAL_EXPIRED"
            else RC_RECOMMENDATION_CHANGED if staleness == "RECOMMENDATION_CHANGED"
            else RC_RISK_CHANGED if staleness == "RISK_CHANGED"
            else RC_ACTION_STALE
        )
        await _audit(
            db, proposal=proposal, event_type="EXECUTION_AUTHORIZATION_DENIED",
            actor_user_id=actor_id, reason_code=code,
            commit=True,
        )
        return AuthorizationOutcome(False, code)

    # 8. Policy re-evaluation against CURRENT state (§13): never trust the
    #    snapshot or any client-supplied decision.
    ctx = build_revalidation_context(
        proposal,
        finding=finding, recommendation=recommendation, repo=repo,
        latest_risk=latest_risk, environment=settings.environment,
        kill_switch=disabled,
    )
    decision = evaluate(ctx, now)

    if decision.policy_version != POLICY_VERSION:
        await _audit(
            db, proposal=proposal, event_type="EXECUTION_AUTHORIZATION_DENIED",
            actor_user_id=actor_id, reason_code=RC_POLICY_VERSION_STALE,
            commit=True,
        )
        return AuthorizationOutcome(False, RC_POLICY_VERSION_STALE)
    if decision.decision == DECISION_DENY:
        # Policy DENY can never be overridden — by approval or anything else.
        await _audit(
            db, proposal=proposal, event_type="EXECUTION_POLICY_DENIED",
            actor_user_id=actor_id, reason_code=RC_POLICY_DENIED,
            extra={"matched_rule": decision.matched_rule},
            commit=True,
        )
        return AuthorizationOutcome(False, RC_POLICY_DENIED)
    if decision.decision != DECISION_REQUIRE_APPROVAL:
        # ALLOW is NOT authorization: approval requirements encoded
        # elsewhere still bind. V3.3 authorizes only from REQUIRE_APPROVAL
        # + valid approval (documented policy semantics).
        await _audit(
            db, proposal=proposal, event_type="EXECUTION_AUTHORIZATION_DENIED",
            actor_user_id=actor_id, reason_code=RC_NOT_AUTHORIZED,
            commit=True,
        )
        return AuthorizationOutcome(False, RC_NOT_AUTHORIZED)

    # 9. Serialize concurrent authorizations on the same proposal: lock the
    #    proposal row, then RE-CHECK every mutable precondition inside the
    #    lock (§38 transaction boundary). The partial unique index
    #    uq_execution_authorizations_live is the final backstop.
    try:
        await db.execute(
            select(ActionProposal.id)
            .where(ActionProposal.id == proposal.id)
            .with_for_update()
        )
    except Exception:
        # SQLite (unit tests) has no FOR UPDATE; the unique index plus the
        # commit-conflict fallback below remain the guarantee there.
        pass

    try:
        await db.refresh(proposal)
    except Exception:
        pass
    if proposal.status not in ("PROPOSED", "POLICY_CHECKED", "APPROVED"):
        # REJECTED/EXPIRED/STALE proposals authorize nothing (§16)
        await _audit(
            db, proposal=proposal, event_type="EXECUTION_AUTHORIZATION_DENIED",
            actor_user_id=actor_id, reason_code=RC_ACTION_STALE,
            commit=True,
        )
        return AuthorizationOutcome(False, RC_ACTION_STALE)

    live_after_lock = (
        await db.execute(
            select(ExecutionAuthorization).where(
                ExecutionAuthorization.action_proposal_id == proposal.id,
                ExecutionAuthorization.authorization_state == AuthorizationState.AUTHORIZED,
            )
        )
    ).scalar_one_or_none()
    if live_after_lock is not None:
        return AuthorizationOutcome(True, "ALREADY_AUTHORIZED", live_after_lock)

    # Kill switch re-check inside the lock: it may have been flipped while
    # the pre-lock validation ran (§22: no long-cached success).
    disabled_after_lock, _ = await read_kill_switch(db)
    if disabled_after_lock:
        await _audit(
            db, proposal=proposal, event_type="EXECUTION_AUTHORIZATION_DENIED",
            actor_user_id=actor_id, reason_code=RC_KILL_SWITCH_ACTIVE,
            commit=True,
        )
        return AuthorizationOutcome(False, RC_KILL_SWITCH_ACTIVE)

    # 10. Create the immutable authorization + frozen contract
    authorization_uuid = uuid4()
    authorization_id = str(authorization_uuid)
    contract = build_contract(authorization_id, proposal, approval, now)
    contract_digest = eam.compute_contract_digest(contract)
    if not eam.verify_contract_digest(contract, contract_digest):
        # Defensive: a non-deterministic contract build can never be stored.
        await _audit(
            db, proposal=proposal, event_type="EXECUTION_AUTHORIZATION_DENIED",
            actor_user_id=actor_id, reason_code=RC_CONTRACT_INVALID,
            commit=True,
        )
        return AuthorizationOutcome(False, RC_CONTRACT_INVALID)

    authorization = ExecutionAuthorization(
        id=authorization_uuid,
        action_proposal_id=proposal.id,
        approval_id=approval.id,
        action_digest=proposal.action_digest,
        repository_id=proposal.repository_id,
        base_commit_sha=proposal.base_commit_sha,
        target_branch=proposal.target_branch,
        policy_version=approval.policy_version,
        policy_decision=approval.policy_decision,
        authorization_state=AuthorizationState.AUTHORIZED,
        contract=contract.to_dict(),
        contract_digest=contract_digest,
        contract_version=eam.CONTRACT_VERSION,
        authorized_by_user_id=actor_id,
    )
    db.add(authorization)

    await _audit(
        db, proposal=proposal, event_type="EXECUTION_AUTHORIZED",
        actor_user_id=actor_id, reason_code=OK,
        extra={
            "authorization_id": authorization_id,
            "contract_digest": contract_digest,
            "security_context_digest": _context_digest(proposal, approval, decision),
            "expires_at": approval.expires_at.isoformat() if approval.expires_at else None,
        },
    )
    try:
        await db.commit()
    except Exception as exc:
        # A concurrent authorize won the race: surface the winner's record,
        # never a duplicate live authorization.
        await db.rollback()
        winner = (
            await db.execute(
                select(ExecutionAuthorization).where(
                    ExecutionAuthorization.action_proposal_id == proposal.id,
                    ExecutionAuthorization.authorization_state == AuthorizationState.AUTHORIZED,
                )
            )
        ).scalar_one_or_none()
        if winner is not None:
            return AuthorizationOutcome(True, "ALREADY_AUTHORIZED", winner)
        logger.warning(
            "execution_authorize_race_lost proposal_id=%s err=%s",
            proposal.id, str(exc)[:100],
        )
        return AuthorizationOutcome(False, "AUTHORIZATION_CONFLICT")
    await db.refresh(authorization)
    return AuthorizationOutcome(True, OK, authorization)


async def consume_authorization(
    db: AsyncSession,
    *,
    authorization: ExecutionAuthorization,
    actor,
    presented_token: object,
    now: Optional[datetime] = None,
) -> AuthorizationOutcome:
    """Atomically consume the one-time authorization (§8/§9/§10).

    NON-EXECUTING: transitions AUTHORIZED → CONSUMED and the bound
    approval APPROVED → USED in ONE transaction. The token presented must
    be the approval's one-time token (verified against the stored keyed
    hash). Exactly one concurrent consumer succeeds; every loser receives
    AUTHORIZATION_REPLAY. This starts no job and runs no code.
    """
    now = now or _utcnow()
    actor_id = actor.id

    # 0. The authorization must exist and be live
    if authorization is None:
        return AuthorizationOutcome(False, RC_AUTHORIZATION_NOT_FOUND)
    if authorization.authorization_state != AuthorizationState.AUTHORIZED:
        # CONSUMED → replay; EXPIRED/REVOKED → not authorized. No resurrection.
        code = (
            RC_AUTHORIZATION_REPLAY
            if authorization.authorization_state == AuthorizationState.CONSUMED
            else RC_NOT_AUTHORIZED
        )
        await _audit_denied(db, authorization, actor_id, code, commit=True)
        return AuthorizationOutcome(False, code)

    # 1. Proposal + approval reloaded from trusted state (the request is
    #    untrusted; the contract's proposal binding is verified, not assumed).
    proposal = (
        await db.execute(
            select(ActionProposal).where(
                ActionProposal.id == authorization.action_proposal_id
            )
        )
    ).scalar_one_or_none()
    if proposal is None:
        await _audit_denied(db, authorization, actor_id, RC_ACTION_NOT_FOUND, commit=True)
        return AuthorizationOutcome(False, RC_ACTION_NOT_FOUND)

    approval = (
        await db.execute(
            select(Approval).where(Approval.id == authorization.approval_id)
        )
    ).scalar_one_or_none()
    if approval is None:
        await _audit_denied(db, authorization, actor_id, RC_APPROVAL_INVALID, commit=True)
        return AuthorizationOutcome(False, RC_APPROVAL_INVALID)

    # 2. Contract integrity (§28): the stored contract digest must still
    #    match the persisted contract bytes — tamper evidence, never repaired.
    try:
        stored_contract = dict(authorization.contract or {})
    except Exception:
        stored_contract = {}
    if not stored_contract or not authorization.contract_digest:
        await _audit_denied(db, authorization, actor_id, RC_CONTRACT_INVALID, commit=True)
        return AuthorizationOutcome(False, RC_CONTRACT_INVALID)
    rebuilt = eam.ExecutionAuthorizationContract(
        contract_version=stored_contract.get("contract_version", ""),
        authorization_id=stored_contract.get("authorization_id", ""),
        action_proposal_id=stored_contract.get("action_proposal_id", ""),
        approval_id=stored_contract.get("approval_id", ""),
        action_digest=stored_contract.get("action_digest", ""),
        repository_id=stored_contract.get("repository_id", ""),
        base_commit_sha=stored_contract.get("base_commit_sha", ""),
        target_branch=stored_contract.get("target_branch", ""),
        policy_version=stored_contract.get("policy_version", ""),
        policy_decision=stored_contract.get("policy_decision", ""),
        allowed_files=tuple(stored_contract.get("allowed_files") or ()),
        allowed_operations=tuple(stored_contract.get("allowed_operations") or ()),
        authorized_at=stored_contract.get("authorized_at", ""),
        expires_at=stored_contract.get("expires_at", ""),
    )
    if not eam.verify_contract_digest(rebuilt, authorization.contract_digest):
        await _audit_denied(
            db, authorization, actor_id, RC_CONTRACT_DIGEST_MISMATCH, commit=True
        )
        return AuthorizationOutcome(False, RC_CONTRACT_DIGEST_MISMATCH)

    # 3. Kill switch: checked at authorize AND at consume (§22)
    disabled, ks_reason = await read_kill_switch(db)
    if disabled:
        await _audit_denied(
            db, authorization, actor_id,
            ks_reason or RC_KILL_SWITCH_ACTIVE, commit=True,
        )
        return AuthorizationOutcome(False, RC_KILL_SWITCH_ACTIVE)

    # 4. Digest revalidation ×3-way at consume time (§11/§12)
    if not verify_proposal_digest(proposal):
        await _audit_denied(db, authorization, actor_id, RC_ACTION_DIGEST_MISMATCH, commit=True)
        return AuthorizationOutcome(False, RC_ACTION_DIGEST_MISMATCH)
    if approval.action_digest != proposal.action_digest or \
            authorization.action_digest != proposal.action_digest:
        await _audit_denied(db, authorization, actor_id, RC_APPROVAL_DIGEST_MISMATCH, commit=True)
        return AuthorizationOutcome(False, RC_APPROVAL_DIGEST_MISMATCH)

    # 5. Approval must still be unconsumed + unexpired + APPROVED (§15)
    if approval.authorization_used_at is not None:
        await _audit_denied(db, authorization, actor_id, eam.RC_APPROVAL_CONSUMED, commit=True)
        return AuthorizationOutcome(False, eam.RC_APPROVAL_CONSUMED)
    if approval.approval_state != ApprovalState.APPROVED:
        code = (
            RC_APPROVAL_REVOKED
            if approval.approval_state == ApprovalState.REVOKED
            else RC_APPROVAL_INVALID
        )
        await _audit_denied(db, authorization, actor_id, code, commit=True)
        return AuthorizationOutcome(False, code)
    if approval_model.is_approval_expired(approval.expires_at, now):
        await _audit_denied(db, authorization, actor_id, RC_APPROVAL_EXPIRED, commit=True)
        return AuthorizationOutcome(False, RC_APPROVAL_EXPIRED)

    # 6. Token verification BEFORE the lock: cheap checks first. The
    #    presented token must be the bound approval's one-time token.
    if not presented_token or not isinstance(presented_token, str):
        await _audit_denied(db, authorization, actor_id, RC_TOKEN_INVALID, commit=True)
        return AuthorizationOutcome(False, RC_TOKEN_INVALID)
    stored_hash = approval.authorization_token_hash or ""
    if not approval_model.verify_token_hash(presented_token, stored_hash):
        await _audit_denied(db, authorization, actor_id, RC_TOKEN_INVALID, commit=True)
        return AuthorizationOutcome(False, RC_TOKEN_INVALID)

    # 7. ATOMIC single-use transition (§9): lock the proposal row (the
    #    same serialization point the approval service uses), re-read the
    #    authorization + approval INSIDE the lock, then transition both in
    #    this transaction. Concurrent consumers serialize here; exactly
    #    one observes AUTHORIZED+unconsumed and commits.
    try:
        await db.execute(
            select(ActionProposal.id)
            .where(ActionProposal.id == authorization.action_proposal_id)
            .with_for_update()
        )
        await db.refresh(authorization)
        if authorization.authorization_state != AuthorizationState.AUTHORIZED:
            code = (
                RC_AUTHORIZATION_REPLAY
                if authorization.authorization_state == AuthorizationState.CONSUMED
                else RC_NOT_AUTHORIZED
            )
            await _audit_denied(db, authorization, actor_id, code, commit=True)
            return AuthorizationOutcome(False, code)
        await db.refresh(approval)
        if approval.authorization_used_at is not None:
            await _audit_denied(db, authorization, actor_id, eam.RC_APPROVAL_CONSUMED, commit=True)
            return AuthorizationOutcome(False, eam.RC_APPROVAL_CONSUMED)
        if approval.approval_state != ApprovalState.APPROVED:
            await _audit_denied(db, authorization, actor_id, RC_APPROVAL_INVALID, commit=True)
            return AuthorizationOutcome(False, RC_APPROVAL_INVALID)
    except Exception:
        # SQLite (unit tests) has no FOR UPDATE; the state columns plus the
        # commit-conflict fallback below remain the guarantee there.
        pass

    authorization.authorization_state = AuthorizationState.CONSUMED
    authorization.consumed_at = now
    approval.authorization_used_at = now
    approval.approval_state = ApprovalState.USED

    await _audit(
        db, proposal=proposal, event_type="EXECUTION_AUTHORIZATION_CONSUMED",
        actor_user_id=actor_id, reason_code=OK,
        extra={
            "authorization_id": str(authorization.id),
            "contract_digest": authorization.contract_digest,
            "approval_id": str(approval.id),
        },
    )
    try:
        await db.commit()
    except Exception:
        # A concurrent consumer committed first: this presentation is a
        # replay, never a second successful use.
        await db.rollback()
        await db.refresh(authorization)
        if authorization.authorization_state == AuthorizationState.CONSUMED:
            await _audit_denied(db, authorization, actor_id, RC_AUTHORIZATION_REPLAY, commit=True)
            return AuthorizationOutcome(False, RC_AUTHORIZATION_REPLAY)
        return AuthorizationOutcome(False, "AUTHORIZATION_CONFLICT")
    await db.refresh(authorization)
    return AuthorizationOutcome(True, RC_CONSUMED, authorization)


async def revoke_authorization(
    db: AsyncSession,
    *,
    authorization: ExecutionAuthorization,
    actor,
    reason: object = None,
    now: Optional[datetime] = None,
) -> AuthorizationOutcome:
    """Revoke a live authorization (AUTHORIZED → REVOKED, no resurrection).

    NON-EXECUTING state transition. A consumed authorization cannot be
    un-consumed; a revoked authorization can never be consumed afterwards.
    """
    now = now or _utcnow()
    if authorization is None:
        return AuthorizationOutcome(False, RC_AUTHORIZATION_NOT_FOUND)
    if authorization.authorization_state != AuthorizationState.AUTHORIZED:
        return AuthorizationOutcome(False, RC_NOT_AUTHORIZED)

    # Serialize against concurrent admission/consumption on the same
    # proposal (the system-wide serialization point). Without this lock a
    # revoke that read AUTHORIZED could overwrite a concurrently committed
    # CONSUMED state — an EXECUTED authorization recorded as REVOKED (a
    # lost terminal-state update, proven by the admit×revoke race suite).
    try:
        await db.execute(
            select(ActionProposal.id)
            .where(ActionProposal.id == authorization.action_proposal_id)
            .with_for_update()
        )
    except Exception:
        # SQLite (unit tests) has no FOR UPDATE; the re-read below plus
        # the commit-conflict fallback remain the guarantee there.
        pass

    try:
        await db.refresh(authorization)
    except Exception:
        pass
    if authorization.authorization_state != AuthorizationState.AUTHORIZED:
        # A concurrent consumer/admission won: never overwrite terminal state.
        return AuthorizationOutcome(False, RC_NOT_AUTHORIZED)

    authorization.authorization_state = AuthorizationState.REVOKED

    proposal = (
        await db.execute(
            select(ActionProposal).where(
                ActionProposal.id == authorization.action_proposal_id
            )
        )
    ).scalar_one_or_none()
    if proposal is not None:
        await _audit(
            db, proposal=proposal, event_type="EXECUTION_AUTHORIZATION_REVOKED",
            actor_user_id=actor.id, reason_code=OK,
            extra={"authorization_id": str(authorization.id)},
        )
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        await db.refresh(authorization)
        if authorization.authorization_state == AuthorizationState.REVOKED:
            return AuthorizationOutcome(True, OK, authorization)
        return AuthorizationOutcome(False, "AUTHORIZATION_CONFLICT")
    await db.refresh(authorization)
    return AuthorizationOutcome(True, OK, authorization)


async def reconcile_expired(db: AsyncSession, *, now: Optional[datetime] = None) -> int:
    """Reconcile live authorizations whose approval window has closed.

    AUTHORIZED → EXPIRED. Called opportunistically on read paths; the
    state machine guarantees expiry even without this sweep (consumption
    re-checks the approval window), so this is observability hygiene.
    """
    now = now or _utcnow()
    rows = (
        await db.execute(
            select(ExecutionAuthorization, Approval.expires_at)
            .join(Approval, Approval.id == ExecutionAuthorization.approval_id)
            .where(
                ExecutionAuthorization.authorization_state == AuthorizationState.AUTHORIZED,
            )
        )
    ).all()
    count = 0
    for authorization, approval_expires in rows:
        if approval_model.is_approval_expired(approval_expires, now):
            # Never overwrite a terminal state: the sweep is opportunistic
            # and unsynchronized, so a concurrent consume may have landed.
            try:
                await db.refresh(authorization)
            except Exception:
                continue
            if authorization.authorization_state != AuthorizationState.AUTHORIZED:
                continue
            authorization.authorization_state = AuthorizationState.EXPIRED
            count += 1
    if count:
        await db.commit()
    return count


async def _audit_denied(
    db: AsyncSession,
    authorization: ExecutionAuthorization,
    actor_id,
    reason_code: str,
    commit: bool = False,
) -> None:
    """Durable denial audit for an existing authorization record."""
    proposal = (
        await db.execute(
            select(ActionProposal).where(
                ActionProposal.id == authorization.action_proposal_id
            )
        )
    ).scalar_one_or_none()
    if proposal is None:
        return
    await _audit(
        db, proposal=proposal, event_type="EXECUTION_AUTHORIZATION_DENIED",
        actor_user_id=actor_id, reason_code=reason_code,
        extra={"authorization_id": str(authorization.id)} if authorization is not None else None,
        commit=commit,
    )
