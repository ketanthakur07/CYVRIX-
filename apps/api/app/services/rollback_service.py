"""CYVRIX V3.6 — Controlled rollback engine.

Returns a pushed remediation to a precisely defined known state using
ONLY structured, deterministic Git/GitHub mechanisms. NON-NEGOTIABLE
rules (docs/v3-verification-rollback.md):

- The rollback TARGET is server-derived: the frozen remediation
  contract's base_commit_sha. No client-supplied SHA exists anywhere
  (there is deliberately no rollback(any SHA) endpoint).
- Rollback is AUTHORIZED, not automatic: it exists only for a
  remediation whose push actually happened, whose authorization chain
  is intact (digest revalidated), and whose kill switch is off.
- Pre-flight state verification (Phase 16): the remote remediation
  branch tip must STILL equal the recorded pushed_sha; the base branch
  tip must still equal the authorized base. Any movement → CONFLICT,
  never a blind rollback.
- Mechanism (Phase 19): a NEW server-generated revert branch from the
  base, a single revert commit restoring the authorized files to their
  pre-remediation content (proven against the run's BEFORE snapshot
  hashes fetched from the remote base commit), pushed WITHOUT force,
  plus a verified PR back to the target branch. NO history rewrite,
  NO force push, NO default-branch mutation.
- Post-rollback verification (VERIFYING → COMPLETED): the revert PR
  readback must match the revert SHA. Success is recorded only after
  proof (never success-before-proof).
- Idempotency (Phase 21): UNIQUE(rollback per remediation) — a second
  request returns the existing record; nothing executes twice.
- Concurrency (Phase 22): PENDING claim happens under a row lock;
  losers observe a live state and become no-ops. A rollback that lost
  the race to a moved branch records CONFLICT.
- Rollback preserves auditability: the original remediation, the revert
  commit, and the revert PR all remain traceable to one another.
"""
import logging
import os
import shutil
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    ActionProposal, AuditEvent, RollbackRun, WorkspaceSnapshot,
)
from app.services import git_ops, workspace as workspace_svc
from app.services import verification_model as vm
from app.services.execution_authorization_service import read_kill_switch
from app.services.git_remediation_model import (
    GitRemediationState, validate_repo_branch_name,
)
from app.services.git_remediation_service import (
    _github_json, _verify_remote_branch,
)

logger = logging.getLogger("cyvrix.rollback")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RollbackDenied(Exception):
    """Rollback refused before any Git/GitHub effect. Nothing created."""

    def __init__(self, reason_code: str, detail: str = ""):
        self.reason_code = reason_code
        self.detail = detail[:500]
        super().__init__(reason_code)


async def _audit(
    db: AsyncSession, *, repository_id, event_type: str,
    reason_code: str, extra: Optional[dict] = None, commit: bool = False,
) -> None:
    metadata = {"reason_code": reason_code}
    if extra:
        metadata.update(extra)
    db.add(AuditEvent(
        repository_id=repository_id,
        finding_id=None,
        event_type=event_type,
        event_metadata=metadata,
    ))
    # V3.8: tamper-evident chain append in the SAME transaction.
    from app.services import audit_service
    await audit_service.emit_from_legacy_audit(
        db,
        repository_id=repository_id,
        event_type=event_type,
        metadata=metadata,
    )
    if commit:
        try:
            await db.commit()
        except Exception as exc:
            logger.warning("audit_commit_failed event=%s err=%s",
                           event_type, str(exc)[:100])
            await db.rollback()


async def get_owned_rollback_row(db: AsyncSession, rollback_id, user_id):
    from app.models import GithubInstallation, GitRemediation, Repository
    result = await db.execute(
        select(RollbackRun)
        .join(GitRemediation,
              GitRemediation.id == RollbackRun.git_remediation_id)
        .join(Repository, Repository.id == GitRemediation.repository_id)
        .join(GithubInstallation,
              GithubInstallation.id == Repository.installation_id)
        .where(RollbackRun.id == rollback_id,
               GithubInstallation.user_id == user_id)
    )
    return result.scalar_one_or_none()


# ── Server-derived rollback target + branch ──────────────────────────


def _revert_branch_name(remediation_id) -> str:
    """Server-derived deterministic revert branch (Phase 14/15).

    Namespace is fixed; the remediation UUID is the only variable part.
    Clients can never choose it."""
    import uuid as uuid_mod
    try:
        safe_id = str(uuid_mod.UUID(str(remediation_id))).replace("-", "")
    except (ValueError, AttributeError, TypeError):
        raise RollbackDenied(vm.RC_ROLLBACK_TARGET_INVALID,
                             "remediation id is not a UUID")
    return f"cyvrix/remediation/{safe_id}-revert"


# ── Creation (exactly-once reservation) ──────────────────────────────


async def start_rollback(
    db: AsyncSession, *, remediation, actor_id,
) -> RollbackRun:
    """Create the exactly-once rollback record for a PUSHED remediation.

    Raises RollbackDenied (nothing created) on any failed precondition.
    The record is created in state PENDING; execution is a separate step
    performed by the internal executor service identity.
    """
    now = _utcnow()

    # 0. Kill switch FIRST (fail closed)
    disabled, ks_reason = await read_kill_switch(db)
    if disabled:
        raise RollbackDenied(
            ks_reason or vm.RC_KILL_SWITCH_ACTIVE, "kill switch active")

    # 0b. V3.7 operational gate: a rollback is a GitHub mutation, so
    # PAUSED/DRAINING/EMERGENCY_STOP all block NEW rollback initiation
    # (an already-running rollback is reconciled, not abandoned).
    from app.services import ops_service
    repo_id = getattr(remediation, "repository_id", None)
    if repo_id is not None:
        ops_ok, ops_reason = await ops_service.assert_rollback_allowed(
            db, repository_id=repo_id, now=now)
        if not ops_ok:
            raise RollbackDenied(ops_reason or "OPS_GATE_DENIED",
                                 "operational control active")

    # 1. The push must actually have happened (Phase 14: rollback of a
    #    local-only commit is a workspace delete, not a rollback record)
    if remediation is None:
        raise RollbackDenied(vm.RC_ROLLBACK_NOT_FOUND)
    if not remediation.pushed_sha or not remediation.committed_sha:
        raise RollbackDenied(vm.RC_ROLLBACK_NOT_ALLOWED,
                             "remediation has no pushed commit to roll back")
    if remediation.remediation_state not in (
            GitRemediationState.PUSHED, GitRemediationState.PR_CREATED,
            GitRemediationState.COMMITTED):
        raise RollbackDenied(
            vm.RC_ROLLBACK_NOT_ALLOWED,
            f"remediation state {remediation.remediation_state} is not rollback-eligible")

    # 2. Authorization chain integrity: action digest still validates
    #    against the proposal (policy re-evaluation precondition, Phase 28)
    proposal = (
        await db.execute(
            select(ActionProposal).where(
                ActionProposal.id == remediation.action_proposal_id)
        )
    ).scalar_one_or_none()
    if proposal is None:
        raise RollbackDenied(vm.RC_AUTHORIZATION_INVALID, "proposal missing")
    if proposal.action_digest != remediation.action_digest:
        raise RollbackDenied(vm.RC_ACTION_DIGEST_MISMATCH)

    # 3. Exactly-once per remediation (idempotency key = remediation id)
    existing = (
        await db.execute(
            select(RollbackRun).where(
                RollbackRun.git_remediation_id == remediation.id)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise RollbackDenied(
            vm.RC_ROLLBACK_REPLAY,
            f"existing rollback {existing.id} state={existing.rollback_state}")

    # 4. ATOMIC reservation: lock the remediation row (system
    #    serialization point), re-check inside the lock, then create.
    try:
        await db.execute(
            select(RollbackRun.git_remediation_id).where(
                RollbackRun.git_remediation_id == remediation.id)
            .with_for_update()
        )
        dup = (
            await db.execute(
                select(RollbackRun.id).where(
                    RollbackRun.git_remediation_id == remediation.id)
            )
        ).scalar_one_or_none()
        if dup is not None:
            raise RollbackDenied(vm.RC_ROLLBACK_REPLAY,
                                 f"existing rollback {dup}")
    except RollbackDenied:
        raise
    except Exception:
        pass  # SQLite unit tests: unique indexes are the backstop

    rollback = RollbackRun(
        id=uuid4(),
        git_remediation_id=remediation.id,
        repository_id=remediation.repository_id,
        action_digest=remediation.action_digest,
        rollback_state="PENDING",
        # SERVER-DERIVED target + expected state (never client input)
        rollback_target_sha=remediation.base_commit_sha,
        expected_branch_sha=remediation.pushed_sha,
        revert_branch=_revert_branch_name(remediation.id),
        requested_by_user_id=actor_id,
    )
    try:
        validate_repo_branch_name(rollback.revert_branch)
    except Exception:
        raise RollbackDenied(vm.RC_BRANCH_INVALID,
                             "derived revert branch failed validation")

    db.add(rollback)
    await _audit(
        db, repository_id=remediation.repository_id,
        event_type="ROLLBACK_REQUESTED", reason_code=vm.RC_OK,
        extra={
            "rollback_run_id": str(rollback.id),
            "git_remediation_id": str(remediation.id),
            "committed_sha": remediation.committed_sha,
            "pushed_sha": remediation.pushed_sha,
            "rollback_target_sha": rollback.rollback_target_sha,
            "revert_branch": rollback.revert_branch,
        },
    )
    # Capture identity BEFORE the commit: a failed commit + rollback()
    # expires ORM attributes (see start_verification — MissingGreenlet).
    _remediation_id = remediation.id
    try:
        await db.commit()
    except Exception as exc:
        await db.rollback()
        winner = (
            await db.execute(
                select(RollbackRun).where(
                    RollbackRun.git_remediation_id == _remediation_id)
            )
        ).scalar_one_or_none()
        if winner is not None:
            raise RollbackDenied(vm.RC_ROLLBACK_REPLAY,
                                 f"existing rollback {winner.id}")
        logger.warning("rollback creation conflict err=%s", str(exc)[:100])
        raise RollbackDenied("ROLLBACK_CONFLICT")
    await db.refresh(rollback)
    return rollback


# ── Execution (the pipeline) ─────────────────────────────────────────


async def execute_rollback(
    db: AsyncSession, *, rollback: RollbackRun,
) -> RollbackRun:
    """Run the controlled rollback pipeline for a created rollback.

    Stages: PRECHECK (remote state) → ROLLING_BACK (revert branch +
    revert commit + push) → VERIFYING (post-rollback readback) →
    COMPLETED. Every uncertain state fails closed.
    """
    from app.models import GitRemediation
    remediation = (
        await db.execute(
            select(GitRemediation).where(
                GitRemediation.id == rollback.git_remediation_id)
        )
    ).scalar_one_or_none()
    if remediation is None:
        rollback.rollback_state = "FAILED"
        rollback.fail_reason_code = vm.RC_ROLLBACK_NOT_FOUND
        rollback.finished_at = _utcnow()
        await db.commit()
        await db.refresh(rollback)
        return rollback

    # Identity strings captured BEFORE any db.rollback(): a rollback()
    # expires ORM attributes, and touching them afterwards would trigger
    # an implicit lazy load on an unusable session (MissingGreenlet).
    _rollback_id = str(rollback.id)
    _remediation_id = str(remediation.id)

    async def _fail(state: str, code: str, detail: str) -> RollbackRun:
        # A prior failure may have left the session in a rolled-back state
        # (e.g. a unique-index conflict inside the credential step). Clear
        # it so the failure record itself can be persisted; repository_id
        # is read defensively because expired attributes would trigger a
        # lazy load on an unusable session.
        try:
            repo_id = rollback.repository_id
        except Exception:
            repo_id = None
        try:
            await db.rollback()
        except Exception:
            pass
        rollback.rollback_state = state
        rollback.fail_reason_code = code
        rollback.fail_detail = detail[:500]
        rollback.finished_at = _utcnow()
        await _audit(
            db, repository_id=repo_id,
            event_type="ROLLBACK_FAILED" if state == "FAILED"
            else "ROLLBACK_STATE_MISMATCH",
            reason_code=code,
            extra={
                "rollback_run_id": _rollback_id,
                "git_remediation_id": _remediation_id,
                "detail": detail[:200],
            },
            commit=True,
        )
        try:
            await db.refresh(rollback)
        except Exception:
            pass
        return rollback

    # 0. ATOMIC claim: serialize concurrent executors on the rollback row.
    await db.execute(
        select(RollbackRun.id).where(
            RollbackRun.id == rollback.id).with_for_update()
    )
    await db.refresh(rollback)
    if rollback.rollback_state != "PENDING":
        return rollback  # live: no-op · terminal: never resurrect

    # 1. Kill switch (Phase 27)
    disabled, ks_reason = await read_kill_switch(db)
    if disabled:
        return await _fail("FAILED", ks_reason or vm.RC_KILL_SWITCH_ACTIVE,
                           "kill switch active")

    rollback.rollback_state = "PRECHECK"
    await db.commit()

    remote_base = os.environ.get(
        "GITHUB_REMOTE_BASE",
        os.environ.get("GITHUB_API_BASE", "https://github.com"),
    )
    remote_base = (remote_base.replace("api.", "", 1)
                   if remote_base.startswith("https://api.") else remote_base)

    git_ws = None
    token: Optional[str] = None
    try:
        from app.services import github_credentials
        token, cred_denied = await github_credentials.issue_push_token(
            db, remediation_row=remediation, actor_id=None,
            purpose="ROLLBACK_PUSH")
        if token is None:
            return await _fail("FAILED",
                               cred_denied or vm.RC_CREDENTIAL_DENIED,
                               "rollback credential denied")

        # 2. PRECHECK: authoritative remote state must match the recorded
        #    context exactly (Phase 16/29). Repository identity is fixed by
        #    the remediation row; branch state by pushed_sha.
        remote_url = git_ops.build_remote_url(
            remote_base, remediation.repo_owner, remediation.repo_name)

        branch_sha = git_ops.ls_remote(
            f"refs/heads/{remediation.remediation_branch}", remote_url, token)
        if branch_sha is None:
            # The remediation branch vanished from the remote: the state we
            # are being asked to roll back no longer exists as recorded.
            return await _fail(
                "CONFLICT", vm.RC_ROLLBACK_STATE_MISMATCH,
                "remediation branch no longer present on remote")
        if branch_sha != (rollback.expected_branch_sha or "").lower():
            # Branch moved after remediation (developer/CI push) — never
            # blindly roll back unrelated changes (Phase 16).
            return await _fail(
                "CONFLICT", vm.RC_ROLLBACK_STATE_MISMATCH,
                "remediation branch tip moved after remediation")
        base_sha = git_ops.ls_remote(
            f"refs/heads/{remediation.target_branch}", remote_url, token)
        if base_sha is None:
            return await _fail("CONFLICT", vm.RC_BASE_COMMIT_MISMATCH,
                               "base branch missing on remote")
        if base_sha != (remediation.base_commit_sha or "").lower():
            # Base advanced past the authorized base: a revert PR against
            # the recorded base would no longer describe reality.
            return await _fail(
                "CONFLICT", vm.RC_ROLLBACK_CONFLICT,
                "target branch moved past the authorized base")

        # 3. ROLLING_BACK: fetch base, rebuild pre-remediation content,
        #    create the revert branch + commit (no force push, ever).
        rollback.rollback_state = "ROLLING_BACK"
        await db.commit()

        git_ws = workspace_svc.new_workspace_dir()
        repo_dir = os.path.join(git_ws, "repo")
        os.makedirs(repo_dir, mode=0o700)
        git_ops.init_repo(repo_dir, remote_url)
        git_ops.fetch_and_verify_base(
            repo_dir, remote_url, remediation.target_branch,
            remediation.base_commit_sha)
        # Fetch the pushed remediation tip too: the revert branch is cut
        # FROM the state being rolled back (the pushed tip), so the revert
        # commit is a real inverse diff (base content applied ON TOP of
        # the remediation). Cutting from base would produce an empty diff
        # and nothing to push.
        ok, _, fetch_err = git_ops.run_git(
            ["git", *git_ops._config_args(), "fetch", "--quiet", "--no-tags",
             "--no-recurse-submodules", "origin",
             remediation.remediation_branch],
            cwd=repo_dir, timeout=git_ops.GIT_TIMEOUT_FETCH)
        if not ok:
            return await _fail("FAILED", vm.RC_ROLLBACK_FAILED,
                               f"remediation branch fetch failed: {fetch_err[:200]}")
        pushed_tip = git_ops.ls_remote(
            f"refs/heads/{remediation.remediation_branch}", remote_url, token)
        if pushed_tip != (rollback.expected_branch_sha or "").lower():
            return await _fail("CONFLICT", vm.RC_ROLLBACK_STATE_MISMATCH,
                               "remediation branch tip moved during rollback")
        git_ops.checkout_base(repo_dir, pushed_tip)
        git_ops.create_branch(repo_dir, rollback.revert_branch, pushed_tip)

        # Pre-remediation content = files at the BASE commit (authoritative
        # git objects; proven against the run's BEFORE snapshot hashes).
        authorized_files = sorted(
            (remediation.remediation_contract or {}).get("authorized_files")
            or ())
        before_rows = (
            await db.execute(
                select(WorkspaceSnapshot).where(
                    WorkspaceSnapshot.execution_run_id
                    == remediation.execution_run_id,
                    WorkspaceSnapshot.phase == "BEFORE",
                )
            )
        ).scalars().all()
        before_hashes = {r.file_path: r.content_sha256 for r in before_rows}

        for rel in authorized_files:
            content = git_ops.show_object(
                repo_dir, remediation.base_commit_sha, rel)
            target = os.path.join(repo_dir, *rel.split("/"))
            if content is None:
                # File did not exist at base → the remediation ADDED it;
                # rollback removes it.
                if os.path.exists(target):
                    os.remove(target)
            else:
                os.makedirs(os.path.dirname(target) or repo_dir, exist_ok=True)
                with open(target, "w", encoding="utf-8", newline="") as fh:
                    fh.write(content)
            expected_before = before_hashes.get(rel)
            if expected_before is not None and content is not None:
                observed = workspace_svc.sha256_bytes(
                    content.encode("utf-8"))
                if observed != expected_before:
                    # Base content drifted from the run's BEFORE snapshot:
                    # the rollback would restore something we cannot prove.
                    return await _fail(
                        "FAILED", vm.RC_ROLLBACK_VERIFY_FAILED,
                        f"base content for {rel} does not match the run's "
                        "BEFORE snapshot")

        git_ops.stage_authorized_files(repo_dir, authorized_files)
        changes, _raw = git_ops.staged_change_set(repo_dir)
        changed_paths = {c["path"] for c in changes}
        if changed_paths != set(authorized_files):
            return await _fail(
                "FAILED", vm.RC_ROLLBACK_NOT_NEEDED
                if not changed_paths else vm.RC_ROLLBACK_VERIFY_FAILED,
                "revert change set differs from the authorized scope")

        revert_message = (
            "CYVRIX rollback: revert remediation\n\n"
            f"Reverts commit {remediation.committed_sha}\n"
            f"Remediation id: {remediation.id}\n"
            f"Rollback run id: {rollback.id}\n"
            f"Action digest: {remediation.action_digest}\n"
            f"Base commit: {remediation.base_commit_sha}\n"
        )
        revert_sha = git_ops.commit(repo_dir, revert_message)
        parent = git_ops.commit_parent(repo_dir)
        if parent != pushed_tip:
            return await _fail("FAILED", vm.RC_BASE_COMMIT_MISMATCH,
                               "revert commit parent is not the pushed tip")
        rollback.revert_sha = revert_sha

        # 4. PUSH (no force; expected remote state = branch must NOT exist)
        remote_revert_sha = git_ops.ls_remote(
            f"refs/heads/{rollback.revert_branch}", remote_url, token)
        if remote_revert_sha is not None:
            return await _fail("CONFLICT", vm.RC_ROLLBACK_REPLAY,
                               "revert branch already exists on remote")
        pushed = git_ops.push_branch(
            repo_dir, remote_url, rollback.revert_branch, token,
            expected_remote_sha=None)
        if pushed != revert_sha:
            return await _fail("FAILED", vm.RC_ROLLBACK_FAILED,
                               "pushed revert SHA differs from local commit")

        # 5. VERIFYING: post-rollback readback — the remote revert branch
        #    must now carry exactly the revert commit (Phase 19).
        rollback.rollback_state = "VERIFYING"
        await db.commit()
        ok, reason, readback = await _verify_remote_branch(
            token, remediation.repo_owner, remediation.repo_name,
            rollback.revert_branch, revert_sha)
        if not ok:
            return await _fail("FAILED", vm.RC_ROLLBACK_VERIFY_FAILED,
                               f"revert branch readback failed: {reason}")

        # 6. Revert PR (Phase 20: leave clear, reviewable state — do not
        #    mutate the original PR or the default branch directly).
        title = "CYVRIX rollback: revert remediation"
        body = (
            f"## Automated rollback\n\n"
            f"Reverts the CYVRIX remediation on branch "
            f"`{remediation.remediation_branch}`.\n\n"
            f"- Reverted commit: `{remediation.committed_sha}`\n"
            f"- Rollback target (base): `{remediation.base_commit_sha}`\n"
            f"- Remediation id: `{remediation.id}`\n"
            f"- Rollback run id: `{rollback.id}`\n"
            f"- Action digest: `{remediation.action_digest}`\n\n"
            f"---\nGenerated by CYVRIX V3.6 controlled rollback. "
            f"No history was rewritten; no force push was used."
        )
        status, pr = await _github_json(
            "POST", f"/repos/{remediation.repo_owner}/{remediation.repo_name}/pulls",
            token,
            json_body={
                "title": title,
                "body": body,
                "head": rollback.revert_branch,
                "base": remediation.target_branch,
            },
        )
        if status in (200, 201) and isinstance(pr, dict):
            rollback.revert_pr_number = int(pr.get("number") or 0) or None
            rollback.revert_pr_url = str(pr.get("html_url") or "")
        elif status == 422:
            # A PR for this head already exists — the revert is already
            # reviewable; treat as satisfied (idempotent semantics).
            pass
        else:
            return await _fail("FAILED", vm.RC_PR_FAILED,
                               f"revert PR creation failed (status {status})")

        # 7. COMPLETED — only after the readback proved the revert landed
        rollback.rollback_state = "COMPLETED"
        rollback.finished_at = _utcnow()
        await _audit(
            db, repository_id=rollback.repository_id,
            event_type="ROLLBACK_SUCCEEDED", reason_code=vm.RC_OK,
            extra={
                "rollback_run_id": str(rollback.id),
                "git_remediation_id": str(remediation.id),
                "revert_sha": revert_sha,
                "revert_pr_number": rollback.revert_pr_number,
            },
        )
        await db.commit()
        await db.refresh(rollback)
        return rollback

    except git_ops.GitError as exc:
        state = ("CONFLICT" if exc.reason_code in (
            vm.RC_ROLLBACK_STATE_MISMATCH, vm.RC_BASE_COMMIT_MISMATCH,
            vm.RC_REMOTE_STATE_MISMATCH) else "FAILED")
        return await _fail(state, exc.reason_code, exc.detail)
    except Exception as exc:
        logger.exception("rollback pipeline error")
        return await _fail("FAILED", vm.RC_ROLLBACK_FAILED,
                           f"rollback error: {type(exc).__name__}")
    finally:
        if git_ws is not None:
            ws_ok, ws_detail = workspace_svc.remove_workspace_dir(git_ws)
            rollback.cleanup_status = "COMPLETED" if ws_ok else "FAILED"
            rollback.cleanup_detail = (ws_detail or "")[:200] or None
            # Cleanup failure does NOT convert a proven rollback success
            # into failure (Phase 26): COMPLETED/CONFLICT/FAILED security
            # outcomes are independent of resource cleanup.
            try:
                await db.commit()
            except Exception:
                await db.rollback()
