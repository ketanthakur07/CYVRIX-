"""CYVRIX V3.4 — Sandboxed execution engine (the FIRST real execution).

Consumes ONLY a V3.3 execution authorization contract. Flow (ADR-010):

    admission transaction (atomic reservation)
        → workspace materialization (pinned commit, trusted source)
        → sandbox creation + hardened execution
        → host-side scope/diff verification (host owns final status)
        → bounded result + snapshots + diff digest
        → guaranteed cleanup → audit → COMPLETED/FAILED

V3.4 execution is ISOLATED LOCAL PROCESSING ONLY:
- no push, no commit to any remote, no PR, no GitHub write APIs (§90)
- no credentials are issued to the sandbox (§89/§23)
- the sandbox has no network, no docker socket, no host mounts
- the worker cannot self-authorize: every run is bound to an
  AUTHORIZED V3.3 authorization record verified in-transaction (§88)
- the final status is derived HOST-SIDE from workspace verification,
  never from sandbox-produced files (§53)

Kill switch is checked at admission, before sandbox creation, and
immediately before container start (§54). Admission is atomic: a
partial unique live index + proposal row lock + in-lock re-checks make
two concurrent admissions of one authorization impossible (§5/§55/§101).
"""
import logging
import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models import (
    ActionProposal, Approval, AuditEvent, ExecutionAuthorization,
    ExecutionRun, GithubInstallation, Repository, SystemControl,
    WorkspaceSnapshot,
)
from app.services import approval_model, execution_run_model as erm
from app.services.approval_model import ApprovalState
from app.services.action_digest import compute_action_digest
from app.services.execution_authorization_model import AuthorizationState
from app.services.execution_authorization_service import (
    KILL_SWITCH_KEY, read_kill_switch,
)
from app.services import workspace as workspace_svc

logger = logging.getLogger("cyvrix.execution")
settings = get_settings()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def _audit(
    db: AsyncSession,
    *,
    repository_id,
    finding_id,
    event_type: str,
    reason_code: str,
    extra: Optional[dict] = None,
) -> None:
    """Security audit event. Never contains secrets or tokens (§59)."""
    metadata = {"reason_code": reason_code}
    if extra:
        metadata.update(extra)
    db.add(AuditEvent(
        repository_id=repository_id,
        finding_id=finding_id,
        event_type=event_type,
        event_metadata=metadata,
    ))


class ExecutionDenied(Exception):
    """Admission or execution denied. Carries the stable reason code."""

    def __init__(self, reason_code: str, detail: str = "",
                 authorization: Optional[ExecutionAuthorization] = None):
        self.reason_code = reason_code
        self.detail = detail[:500]
        self.authorization = authorization
        super().__init__(reason_code)


class ExecutionFailure(Exception):
    """The run was ADMITTED but failed before completion. Terminal."""

    def __init__(self, reason_code: str, detail: str = ""):
        self.reason_code = reason_code
        self.detail = detail[:500]
        super().__init__(reason_code)


# ── Admission (§4/§5/§101/§102) ──────────────────────────────────────

async def admit_execution(
    db: AsyncSession,
    *,
    authorization: ExecutionAuthorization,
    actor,
    presented_token: object,
) -> ExecutionRun:
    """Atomically reserve the authorization and create the run record.

    Raises ExecutionDenied (nothing reserved) or ExecutionFailure
    (reservation committed, run FAILED). Admission verifies ALL §4
    checks inside the lock; the sandbox is created only AFTER commit.
    """
    now = _utcnow()
    # The caller is the INTERNAL executor service identity (§88) — not a
    # user session. Audit events record the service boundary, never a
    # user identity, because no user session exists on this path.
    actor_id = actor.id if actor is not None else None

    # 0. Ownership is enforced by the route (get_owned_authorization);
    #    the service re-verifies state from trusted DB rows only.
    if authorization is None:
        raise ExecutionDenied(erm.RC_AUTHORIZATION_NOT_FOUND)

    # 1. Kill switch BEFORE everything (§54 check #1)
    disabled, ks_reason = await read_kill_switch(db)
    if disabled:
        await _audit(
            db, repository_id=authorization.repository_id, finding_id=None,
            event_type="EXECUTION_DENIED",
            reason_code=ks_reason or erm.RC_KILL_SWITCH_ACTIVE,
            extra={"authorization_id": str(authorization.id)},
        )
        await db.commit()
        raise ExecutionDenied(erm.RC_KILL_SWITCH_ACTIVE,
                              ks_reason or "kill switch active")

    # 2. Authorization must be live; CONSUMED → replay (§5/§56)
    if authorization.authorization_state == AuthorizationState.CONSUMED:
        await _audit(
            db, repository_id=authorization.repository_id, finding_id=None,
            event_type="EXECUTION_DENIED",
            reason_code=erm.RC_EXECUTION_REPLAY,
            extra={"authorization_id": str(authorization.id)},
        )
        await db.commit()
        raise ExecutionDenied(erm.RC_EXECUTION_REPLAY,
                              "authorization already consumed")
    if authorization.authorization_state != AuthorizationState.AUTHORIZED:
        code = (
            erm.RC_AUTHORIZATION_REVOKED
            if authorization.authorization_state == AuthorizationState.REVOKED
            else erm.RC_AUTHORIZATION_EXPIRED
            if authorization.authorization_state == AuthorizationState.EXPIRED
            else erm.RC_AUTHORIZATION_INVALID
        )
        await _audit(
            db, repository_id=authorization.repository_id, finding_id=None,
            event_type="EXECUTION_DENIED", reason_code=code,
            extra={"authorization_id": str(authorization.id)},
        )
        await db.commit()
        raise ExecutionDenied(code)

    # 3. The presented token must be the bound approval's one-time token.
    #    Admission consumes the authorization atomically (state move to
    #    CONSUMED happens below inside the same locked transaction as
    #    run creation — one-time semantics carry over from V3.3).
    proposal = (
        await db.execute(
            select(ActionProposal).where(
                ActionProposal.id == authorization.action_proposal_id
            )
        )
    ).scalar_one_or_none()
    if proposal is None:
        await _audit(
            db, repository_id=authorization.repository_id, finding_id=None,
            event_type="EXECUTION_DENIED",
            reason_code=erm.RC_AUTHORIZATION_INVALID,
            extra={"authorization_id": str(authorization.id), "detail": "proposal missing"},
        )
        await db.commit()
        raise ExecutionDenied(erm.RC_AUTHORIZATION_INVALID, "proposal missing")

    approval = (
        await db.execute(
            select(Approval).where(Approval.id == authorization.approval_id)
        )
    ).scalar_one_or_none()
    if approval is None:
        await _audit(
            db, repository_id=authorization.repository_id,
            finding_id=proposal.finding_id,
            event_type="EXECUTION_DENIED",
            reason_code=erm.RC_AUTHORIZATION_INVALID,
            extra={"authorization_id": str(authorization.id), "detail": "approval missing"},
        )
        await db.commit()
        raise ExecutionDenied(erm.RC_AUTHORIZATION_INVALID, "approval missing")

    if not isinstance(presented_token, str) or not presented_token:
        await _audit(
            db, repository_id=authorization.repository_id,
            finding_id=proposal.finding_id,
            event_type="EXECUTION_DENIED",
            reason_code="TOKEN_INVALID",
            extra={"authorization_id": str(authorization.id), "detail": "token missing"},
        )
        await db.commit()
        raise ExecutionDenied(erm.RC_AUTHORIZATION_INVALID, "missing execution token")
    stored_hash = approval.authorization_token_hash or ""
    if not stored_hash or not approval_model.verify_token_hash(
        presented_token, stored_hash
    ):
        await _audit(
            db, repository_id=authorization.repository_id,
            finding_id=proposal.finding_id,
            event_type="EXECUTION_DENIED",
            reason_code="TOKEN_INVALID",
            extra={"authorization_id": str(authorization.id)},
        )
        await db.commit()
        raise ExecutionDenied(erm.RC_AUTHORIZATION_INVALID, "token invalid")

    # 4. ATOMIC RESERVATION: lock the proposal row (the system-wide
    #    serialization point), re-read EVERYTHING mutable inside the
    #    lock, then transition authorization → CONSUMED and create the
    #    run in ONE commit (§101). uq_execution_runs_live/done are the
    #    DB backstops.
    lock_denied: Optional[tuple] = None
    try:
        await db.execute(
            select(ActionProposal.id)
            .where(ActionProposal.id == proposal.id)
            .with_for_update()
        )
        await db.refresh(authorization)
        if authorization.authorization_state != AuthorizationState.AUTHORIZED:
            code = (
                erm.RC_EXECUTION_REPLAY
                if authorization.authorization_state == AuthorizationState.CONSUMED
                else erm.RC_AUTHORIZATION_INVALID
            )
            lock_denied = (code, "authorization no longer live")
        else:
            await db.refresh(approval)
            if approval.authorization_used_at is not None or \
                    approval.approval_state != ApprovalState.APPROVED:
                lock_denied = (erm.RC_AUTHORIZATION_INVALID,
                               "approval no longer valid")
            elif approval_model.is_approval_expired(approval.expires_at, now):
                # clock race (§42): the approval window closed between
                # authorize and admit — no execution after expiry
                lock_denied = (erm.RC_AUTHORIZATION_EXPIRED,
                               "approval window closed")
    except Exception:
        # SQLite unit tests: no FOR UPDATE. State columns + unique
        # indexes + commit-conflict fallback remain the guarantee.
        lock_denied = None
    if lock_denied is not None:
        await _audit(
            db, repository_id=authorization.repository_id,
            finding_id=proposal.finding_id,
            event_type="EXECUTION_DENIED",
            reason_code=lock_denied[0],
            extra={"authorization_id": str(authorization.id),
                   "detail": lock_denied[1]},
        )
        await db.commit()
        raise ExecutionDenied(lock_denied[0], lock_denied[1])

    # 5. Kill switch re-check INSIDE the lock (§54 check #3)
    disabled_after_lock, _ = await read_kill_switch(db)
    if disabled_after_lock:
        await _audit(
            db, repository_id=authorization.repository_id,
            finding_id=proposal.finding_id,
            event_type="EXECUTION_DENIED",
            reason_code=erm.RC_KILL_SWITCH_ACTIVE,
            extra={"authorization_id": str(authorization.id)},
        )
        await db.commit()
        raise ExecutionDenied(erm.RC_KILL_SWITCH_ACTIVE)

    # 6. Server-derived profile binding (§39): unknown action type → deny
    profile = erm.profile_for_action_type(proposal.action_type)
    if profile is None:
        await _audit(
            db, repository_id=authorization.repository_id,
            finding_id=proposal.finding_id,
            event_type="EXECUTION_DENIED",
            reason_code=erm.RC_ACTION_SCOPE_VIOLATION,
            extra={"authorization_id": str(authorization.id),
                   "detail": "action type has no execution profile"},
        )
        await db.commit()
        raise ExecutionDenied(erm.RC_ACTION_SCOPE_VIOLATION,
                              "action type has no execution profile")

    # 7. Digest revalidation: proposal content must still hash to the
    #    bound action digest (§4 check #6/#7; never repaired).
    recomputed = compute_action_digest({
        "action_type": proposal.action_type,
        "repository_id": str(proposal.repository_id),
        "base_commit_sha": proposal.base_commit_sha,
        "target_branch": proposal.target_branch,
        "files": proposal.files,
        "operations": proposal.operations,
        "expected_diff": proposal.expected_diff,
    })
    if recomputed != proposal.action_digest or \
            authorization.action_digest != proposal.action_digest:
        await _audit(
            db, repository_id=authorization.repository_id,
            finding_id=proposal.finding_id,
            event_type="EXECUTION_DIGEST_MISMATCH",
            reason_code=erm.RC_ACTION_DIGEST_MISMATCH,
            extra={"authorization_id": str(authorization.id)},
        )
        await db.commit()
        raise ExecutionDenied(erm.RC_ACTION_DIGEST_MISMATCH)

    # 8. Server-side scope re-validation at admission (§4 check #12-14):
    #    protected paths and allowlists re-checked NOW, not just at
    #    proposal time (§50 defense in depth).
    from app.services.action_model import (
        ProposalValidationError, is_protected_path,
        validate_operations, validate_files_for_action_type,
    )
    try:
        canonical_files = validate_files_for_action_type(
            proposal.action_type, list(proposal.files or ()), None
        )
        validate_operations(
            list(proposal.operations or ()), proposal.action_type,
            canonical_files,
        )
    except ProposalValidationError as exc:
        await _audit(
            db, repository_id=authorization.repository_id,
            finding_id=proposal.finding_id,
            event_type="SCOPE_VIOLATION",
            reason_code=erm.RC_ACTION_SCOPE_VIOLATION,
            extra={"authorization_id": str(authorization.id),
                   "detail": str(exc)[:200]},
        )
        await db.commit()
        raise ExecutionDenied(erm.RC_ACTION_SCOPE_VIOLATION,
                              str(exc)[:300])
    for f in canonical_files:
        category = is_protected_path(f)
        if category:
            await _audit(
                db, repository_id=authorization.repository_id,
                finding_id=proposal.finding_id,
                event_type="SCOPE_VIOLATION",
                reason_code=erm.RC_PROTECTED_PATH,
                extra={"authorization_id": str(authorization.id),
                       "path_category": category},
            )
            await db.commit()
            raise ExecutionDenied(erm.RC_PROTECTED_PATH,
                                  f"protected path category {category}")

    # 9. Reserve: consume authorization + create run atomically.
    existing_run = (
        await db.execute(
            select(ExecutionRun).where(
                ExecutionRun.execution_authorization_id == authorization.id,
                ExecutionRun.run_state.in_((
                    "ADMISSION_PENDING", "EXECUTING",
                    "RESULT_READY", "COMPLETED", "CLEANUP_FAILED",
                )),
            )
        )
    ).scalar_one_or_none()
    if existing_run is not None:
        code = (
            erm.RC_EXECUTION_IN_PROGRESS
            if existing_run.run_state in ("ADMISSION_PENDING", "EXECUTING")
            else erm.RC_EXECUTION_REPLAY
        )
        await _audit(
            db, repository_id=authorization.repository_id,
            finding_id=proposal.finding_id,
            event_type="EXECUTION_DENIED",
            reason_code=code,
            extra={"authorization_id": str(authorization.id),
                   "execution_run_id": str(existing_run.id)},
        )
        await db.commit()
        raise ExecutionDenied(code,
                              "execution already in progress"
                              if code == erm.RC_EXECUTION_IN_PROGRESS
                              else "authorization already executed")

    run_uuid = uuid_mod.uuid4()
    run = ExecutionRun(
        id=run_uuid,
        execution_authorization_id=authorization.id,
        action_proposal_id=proposal.id,
        repository_id=authorization.repository_id,
        action_digest=authorization.action_digest,
        contract_digest=authorization.contract_digest,
        run_state="ADMISSION_PENDING",
        execution_profile=profile,
        resource_profile=dict(erm.RESOURCE_LIMITS),
        cleanup_status="NOT_STARTED",
    )
    db.add(run)

    # one-time consumption of the authorization + approval (V3.3
    # semantics, same transaction as the reservation)
    authorization.authorization_state = AuthorizationState.CONSUMED
    authorization.consumed_at = now
    approval.authorization_used_at = now
    approval.approval_state = ApprovalState.USED

    await _audit(
        db, repository_id=authorization.repository_id,
        finding_id=proposal.finding_id,
        event_type="EXECUTION_ADMITTED",
        reason_code=erm.RC_OK,
        extra={
            "authorization_id": str(authorization.id),
            "execution_run_id": str(run_uuid),
            "profile": profile,
            "action_digest": authorization.action_digest[:16],
        },
    )
    try:
        await db.commit()
    except Exception as exc:
        await db.rollback()
        # A concurrent admission won: classify deterministically.
        winner = (
            await db.execute(
                select(ExecutionRun).where(
                    ExecutionRun.execution_authorization_id == authorization.id
                )
            )
        ).scalar_one_or_none()
        await db.refresh(authorization)
        if authorization.authorization_state == AuthorizationState.CONSUMED and \
                winner is not None:
            if winner.run_state in ("ADMISSION_PENDING", "EXECUTING"):
                raise ExecutionDenied(erm.RC_EXECUTION_IN_PROGRESS)
            raise ExecutionDenied(erm.RC_EXECUTION_REPLAY)
        logger.warning("execution admission conflict err=%s", str(exc)[:100])
        raise ExecutionDenied("AUTHORIZATION_CONFLICT")
    await db.refresh(run)
    return run


# ── Execution (§7-§33) ───────────────────────────────────────────────


async def _materialize(run: ExecutionRun, authorization: ExecutionAuthorization,
                       proposal: ActionProposal) -> tuple[str, dict]:
    """Materialize the workspace at the pinned commit (§13/§42)."""
    repo = (
        await _session_repo(run.repository_id)
    )
    installation = (
        await _session_installation(repo.installation_id)
    )
    ws_dir = workspace_svc.new_workspace_dir()
    try:
        materialization = await workspace_svc.materialize_workspace(
            installation_id=int(installation.installation_id),
            owner=repo.owner,
            repo_name=repo.name,
            base_commit_sha=authorization.base_commit_sha,
            files=list(proposal.files or ()),
            workspace_dir=ws_dir,
        )
    except Exception:
        workspace_svc.remove_workspace_dir(ws_dir)
        raise
    return ws_dir, materialization


# These two helpers exist so _materialize stays testable with a mocked
# session; production passes the real AsyncSession-bound functions in
# via partial (see execute_authorized_run).
async def _session_repo(repository_id):
    raise ExecutionFailure("SANDBOX_UNAVAILABLE", "session not bound")


async def _session_installation(installation_id):
    raise ExecutionFailure("SANDBOX_UNAVAILABLE", "session not bound")


def bind_session_lookups(db: AsyncSession) -> None:
    """Bind DB lookups used by the execution pipeline."""
    global _session_repo, _session_installation

    async def _repo(repository_id):
        return (
            await db.execute(
                select(Repository).where(Repository.id == repository_id)
            )
        ).scalar_one_or_none()

    async def _installation(installation_id):
        return (
            await db.execute(
                select(GithubInstallation).where(
                    GithubInstallation.id == installation_id
                )
            )
        ).scalar_one_or_none()

    _session_repo = _repo
    _session_installation = _installation


# Optional process-level sandbox factory override (module attribute so
# integration/race harnesses can substitute a deterministic in-process
# executor without touching the docker layer). Production code never sets
# it; the real container factory is used whenever it is None.
SANDBOX_FACTORY = None


async def execute_authorized_run(
    db: AsyncSession,
    *,
    run: ExecutionRun,
    authorization: ExecutionAuthorization,
    sandbox_factory=None,
) -> ExecutionRun:
    """Run the admitted execution through the sandbox and finalize it.

    The caller owns failure handling of the ADMIN phase; this function
    owns the EXECUTION phase and guarantees cleanup (§33/§103).
    """
    bind_session_lookups(db)
    proposal = (
        await db.execute(
            select(ActionProposal).where(ActionProposal.id == run.action_proposal_id)
        )
    ).scalar_one_or_none()
    if proposal is None:
        return await _fail_run(db, run, erm.RC_AUTHORIZATION_INVALID,
                               "proposal vanished after admission")

    # Kill switch immediately before any sandbox work (§54 check #2)
    disabled, ks_reason = await read_kill_switch(db)
    if disabled:
        return await _fail_run(
            db, run, erm.RC_KILL_SWITCH_ACTIVE,
            ks_reason or "kill switch active", cleanups=[],
        )

    # platform capability check (§35/§36): unsupported → fail closed
    from app.services import sandbox as sandbox_svc
    try:
        platform_info = sandbox_svc.check_platform_support()
    except sandbox_svc.SandboxUnavailable as exc:
        return await _fail_run(db, run, exc.reason_code, exc.detail)

    ws_dir = None
    sandbox = None
    sandbox_destroyed = True
    try:
        # Workspace materialization at the pinned commit
        try:
            ws_dir, _materialization = await _materialize(
                run, authorization, proposal
            )
        except workspace_svc.MaterializationError as exc:
            return await _fail_run(db, run, exc.reason_code, exc.detail)

        # mark EXECUTING before the container starts
        run.run_state = "EXECUTING"
        run.started_at = _utcnow()
        await _audit(
            db, repository_id=run.repository_id, finding_id=None,
            event_type="EXECUTION_STARTED",
            reason_code=erm.RC_OK,
            extra={"execution_run_id": str(run.id),
                   "authorization_id": str(authorization.id)},
        )
        await db.commit()

        # sandbox creation AFTER admission reservation (§102)
        try:
            sandbox_svc.write_operations_payload(
                ws_dir, list(proposal.files or ()), list(proposal.operations or ())
            )
            before_snap = workspace_svc.snapshot_workspace(ws_dir, "BEFORE")
            factory = sandbox_factory or SANDBOX_FACTORY or sandbox_svc.create_sandbox
            sandbox = factory(ws_dir)
        except sandbox_svc.SandboxUnavailable as exc:
            return await _fail_run(db, run, exc.reason_code, exc.detail,
                                   cleanups=[_ws_cleanup(ws_dir)])
        except Exception as exc:
            return await _fail_run(db, run, erm.RC_SANDBOX_UNAVAILABLE,
                                   f"sandbox creation failed: {type(exc).__name__}",
                                   cleanups=[_ws_cleanup(ws_dir)])

        # Kill switch immediately before container start (§54 check #3)
        disabled, ks_reason = await read_kill_switch(db)
        if disabled:
            destroyed_unused, _ = _destroy_sandbox(sandbox)
            sandbox = None
            return await _fail_run(
                db, run, erm.RC_KILL_SWITCH_ACTIVE,
                ks_reason or "kill switch active",
                cleanups=[_ws_cleanup(ws_dir)],
            )

        # persist BEFORE snapshot hashes
        await _persist_snapshots(db, run.id, "BEFORE", before_snap)

        # HARD timeout from the frozen resource profile
        timeout = int(erm.RESOURCE_LIMITS["execution_timeout_seconds"])
        result = sandbox_svc.run_executor(sandbox, timeout_seconds=timeout)

        # read the sandbox's RAW data (never trusted as status, §53)
        raw_result = sandbox_svc.read_executor_result(ws_dir)
        probes = sandbox_svc.read_probe_results(ws_dir)

        # destroy the sandbox BEFORE verification: repository content
        # gets no chance to influence host decisions (§53)
        sandbox_destroyed, destroy_detail = sandbox_svc.destroy_sandbox(sandbox)
        sandbox = None

        # AFTER snapshot + HOST-SIDE verification
        after_snap = workspace_svc.snapshot_workspace(ws_dir, "AFTER")
        await _persist_snapshots(db, run.id, "AFTER", after_snap)

        ok_scope, scope_reason, changed = workspace_svc.verify_scope_and_diff(
            before_snap, after_snap,
            list(proposal.files or ()), list(proposal.operations or ()),
        )

        change_set = workspace_svc.build_change_set(before_snap, after_snap)
        diff_digest = erm.compute_diff_digest(change_set)

        # output hygiene: bounded metadata only
        stdout_bytes = len(result.stdout) if result else 0
        output_limit = erm.RESOURCE_LIMITS["output_limit_bytes"]

        if result is not None and result.timed_out:
            return await _fail_run(
                db, run, erm.RC_EXECUTION_TIMEOUT,
                f"execution exceeded {timeout}s hard timeout",
                cleanups=[_ws_cleanup(ws_dir)],
            )
        if result is not None and not result.timed_out and result.exit_code not in (0, None):
            return await _fail_run(
                db, run, erm.RC_OPERATION_FAILED,
                f"executor exited {result.exit_code}",
                cleanups=[_ws_cleanup(ws_dir)],
            )
        if not ok_scope:
            await _audit(
                db, repository_id=run.repository_id, finding_id=None,
                event_type="SCOPE_VIOLATION",
                reason_code=scope_reason,
                extra={"execution_run_id": str(run.id),
                       "violations": changed[:10]},
            )
            return await _fail_run(
                db, run, scope_reason,
                "workspace verification failed",
                cleanups=[_ws_cleanup(ws_dir)],
            )

        # finalize: RESULT_READY → COMPLETED in one commit
        executor_meta = raw_result.to_dict() if hasattr(raw_result, "to_dict") else raw_result
        run.result = {
            "executor": erm.ExecutorResult.from_dict(executor_meta or {}).to_dict(),
            "changed_files": changed,
            "diff_digest": diff_digest,
            "stdout_bytes": min(stdout_bytes, output_limit),
            "probes_available": bool(probes),
            "profile": run.execution_profile,
        }
        run.diff_digest = diff_digest
        run.run_state = "RESULT_READY"
        run.finished_at = _utcnow()

        ws_ok, ws_detail = workspace_svc.remove_workspace_dir(ws_dir)
        run.cleanup_status = "COMPLETED" if ws_ok else "FAILED"
        run.cleanup_detail = ws_detail[:200] if ws_detail else None
        if not ws_ok:
            run.run_state = "CLEANUP_FAILED"
            await _audit(
                db, repository_id=run.repository_id, finding_id=None,
                event_type="SANDBOX_CLEANUP_FAILED",
                reason_code=erm.RC_CLEANUP_FAILED,
                extra={"execution_run_id": str(run.id),
                       "detail": ws_detail[:200]},
            )
        else:
            run.run_state = "COMPLETED"
            await _audit(
                db, repository_id=run.repository_id, finding_id=None,
                event_type="EXECUTION_COMPLETED",
                reason_code=erm.RC_OK,
                extra={"execution_run_id": str(run.id),
                       "authorization_id": str(authorization.id),
                       "changed_files": changed[:10],
                       "diff_digest": diff_digest},
            )
        await db.commit()
        await db.refresh(run)
        return run

    except ExecutionFailure:
        raise
    except Exception as exc:
        logger.exception("execution pipeline error")
        if sandbox is not None:
            sandbox_destroyed = _destroy_sandbox(sandbox)[0]
            sandbox = None
        if ws_dir is not None:
            workspace_svc.remove_workspace_dir(ws_dir)
        return await _fail_run(
            db, run, erm.RC_SANDBOX_UNAVAILABLE,
            f"execution error: {type(exc).__name__}",
            cleanups=[],
        )


def _destroy_sandbox(sandbox) -> tuple[bool, str]:
    from app.services import sandbox as sandbox_svc
    try:
        return sandbox_svc.destroy_sandbox(sandbox)
    except Exception as exc:
        return False, type(exc).__name__


def _ws_cleanup(ws_dir: str):
    def _do():
        return workspace_svc.remove_workspace_dir(ws_dir)
    return _do


async def _persist_snapshots(db: AsyncSession, run_id, phase: str,
                             snap: dict) -> None:
    for rel, meta in snap.items():
        db.add(WorkspaceSnapshot(
            execution_run_id=run_id,
            phase=phase,
            file_path=rel,
            content_sha256=str(meta.get("sha256", ""))[:64],
            size_bytes=int(meta.get("size_bytes", 0)),
        ))


async def _fail_run(db: AsyncSession, run: ExecutionRun, reason_code: str,
                    detail: str, cleanups: Optional[list] = None) -> ExecutionRun:
    """Terminal failure path: cleanup → audit → FAILED/CLEANUP_FAILED.

    cleanups: zero-arg callables, each returning (ok, detail), executed
    in order (sandbox teardown first, workspace second — §103). Fail
    closed, record everything, never report a leaked sandbox as a clean
    failure (§33/§60/§61).
    """
    run.run_state = "FAILED"
    run.fail_reason_code = reason_code
    run.fail_detail = detail[:500]
    run.finished_at = _utcnow()

    cleanup_ok, cleanup_detail = True, ""
    for fn in (cleanups or []):
        try:
            ok, det = fn()
        except Exception as exc:
            ok, det = False, type(exc).__name__
        if not ok:
            cleanup_ok = False
            cleanup_detail = (cleanup_detail + " " + (det or "cleanup failed")).strip()

    run.cleanup_status = "COMPLETED" if cleanup_ok else "FAILED"
    run.cleanup_detail = (cleanup_detail or "")[:200] or None
    if not cleanup_ok:
        run.run_state = "CLEANUP_FAILED"

    await _audit(
        db, repository_id=run.repository_id, finding_id=None,
        event_type="EXECUTION_FAILED",
        reason_code=reason_code,
        extra={"execution_run_id": str(run.id),
               "cleanup": run.cleanup_status,
               "detail": detail[:200]},
    )
    try:
        await db.commit()
    except Exception:
        await db.rollback()
    await db.refresh(run)
    return run


async def get_run_for_user(db: AsyncSession, run_id, user_id):
    """Load a run through the full ownership chain (cross-tenant 404)."""
    result = await db.execute(
        select(ExecutionRun)
        .join(ActionProposal, ActionProposal.id == ExecutionRun.action_proposal_id)
        .join(Repository, Repository.id == ActionProposal.repository_id)
        .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
        .where(ExecutionRun.id == run_id, GithubInstallation.user_id == user_id)
    )
    return result.scalar_one_or_none()
