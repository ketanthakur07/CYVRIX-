"""CYVRIX V3.5 — Controlled Git/GitHub remediation service.

Turns ONE server-verified V3.4 execution run into a controlled Git branch,
a scoped commit, a short-lived-credential push to a server-generated
remediation branch, and (when the stage ceiling permits) a verified pull
request. NON-NEGOTIABLE rules (docs/v3-github-remediation.md):

- Created ONLY from trusted server-side run state; the client supplies
  nothing security-relevant (no branch name, no stage, no digest).
- Exactly-once per execution run (UNIQUE run id) and one live pipeline
  per authorization (partial unique index) — replay is refused at the DB.
- Content reconstruction happens INSIDE THE SANDBOX (same closed-world
  executor, same hardened container); the reconstructed AFTER content is
  proven byte-identical to the run's persisted AFTER snapshot hashes
  BEFORE any commit. Mismatch ⇒ STALE, never "apply anyway".
- Git layer: argv-only, hooks disabled, repository config cut off, base
  SHA verified against the remote, NO force push, NO default-branch push,
  remote identity verified before push and after push.
- GitHub credential: short-lived, repo-scoped, in-process only, audited
  without token material, denied when kill switch/authorization say no.
- Kill switch is checked at: start, before commit, before credential
  issuance, before push, before PR creation (fail closed everywhere).
- ACTUAL GIT EFFECT ⊆ AUTHORIZED EFFECT — any extra path, deletion,
  rename, permission, or binary change fails the pipeline CLOSED.
"""
import logging
import os
import shutil
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models import (
    ActionProposal, AuditEvent, ExecutionAuthorization, ExecutionRun,
    GithubInstallation, GitRemediation, Repository, WorkspaceSnapshot,
)
from app.services import (
    git_ops, git_remediation_model as grm, sandbox as sandbox_svc,
    workspace as workspace_svc,
)
from app.services.action_digest import compute_action_digest
from app.services.action_model import validate_operations
from app.services.execution_authorization_service import read_kill_switch

logger = logging.getLogger("cyvrix.git_remediation")
settings = get_settings()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RemediationDenied(Exception):
    """Remediation refused before any Git/GitHub effect. Nothing created."""

    def __init__(self, reason_code: str, detail: str = ""):
        self.reason_code = reason_code
        self.detail = detail[:500]
        super().__init__(reason_code)


async def _audit(
    db: AsyncSession, *, remediation: Optional[GitRemediation],
    repository_id, event_type: str, reason_code: str,
    extra: Optional[dict] = None, commit: bool = False,
) -> None:
    """Security audit event. Never contains token/credential material."""
    metadata = {"reason_code": reason_code}
    if remediation is not None:
        metadata.update({
            "git_remediation_id": str(remediation.id),
            "execution_run_id": str(remediation.execution_run_id),
            "execution_authorization_id": str(remediation.execution_authorization_id),
            "action_digest": remediation.action_digest,
            "remediation_state": remediation.remediation_state,
            "remediation_branch": remediation.remediation_branch,
        })
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
            logger.warning("audit_commit_failed event=%s err=%s", event_type, str(exc)[:100])
            await db.rollback()


async def get_owned_remediation(db: AsyncSession, remediation_id, user_id):
    result = await db.execute(
        select(GitRemediation)
        .join(ActionProposal, ActionProposal.id == GitRemediation.action_proposal_id)
        .join(Repository, Repository.id == ActionProposal.repository_id)
        .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
        .where(GitRemediation.id == remediation_id, GithubInstallation.user_id == user_id)
    )
    return result.scalar_one_or_none()


async def get_run_for_remediation(db: AsyncSession, run_id, user_id):
    """Load a run through the full ownership chain (cross-tenant 404)."""
    result = await db.execute(
        select(ExecutionRun)
        .join(ActionProposal, ActionProposal.id == ExecutionRun.action_proposal_id)
        .join(Repository, Repository.id == ActionProposal.repository_id)
        .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
        .where(ExecutionRun.id == run_id, GithubInstallation.user_id == user_id)
    )
    return result.scalar_one_or_none()


# ── Stage ceiling (server-derived; never client-controlled) ──────────

# V3.5 delivery model: every remediable action type is delivered as a
# controlled branch + verified PR. Direct default-branch push does not
# exist in any stage; force push does not exist in any stage.
_ACTION_TYPE_TO_CEILING = {
    "DEPENDENCY_UPGRADE": grm.STAGE_PR_ALLOWED,
    "DOCKERFILE_UPDATE": grm.STAGE_PR_ALLOWED,
    "CONFIGURATION_UPDATE": grm.STAGE_PR_ALLOWED,
    "DOCUMENTED_SECURITY_FIX": grm.STAGE_PR_ALLOWED,
}


def _ceiling_for(action_type: object) -> Optional[str]:
    if not isinstance(action_type, str):
        return None
    return _ACTION_TYPE_TO_CEILING.get(action_type)


# ── Creation (exactly-once reservation) ──────────────────────────────


async def start_remediation(
    db: AsyncSession, *, run: ExecutionRun, actor_id=None,
) -> GitRemediation:
    """Create the remediation record for a verified V3.4 run.

    Raises RemediationDenied (nothing created) on any failed precondition.
    The record is created in state PENDING; execution is a separate step.
    """
    now = _utcnow()

    # 0. Kill switch FIRST (fail closed)
    disabled, ks_reason = await read_kill_switch(db)
    if disabled:
        raise RemediationDenied(
            ks_reason or grm.RC_KILL_SWITCH_ACTIVE, "kill switch active")

    # 0b. V3.7 operational gate: system state × repository control ×
    # circuit breaker × quotas. Fail closed on any unknown state.
    from app.services import ops_service
    ops_ok, ops_reason = await ops_service.assert_execution_allowed(
        db, repository_id=run.repository_id, scope="REMEDIATION",
        action_type=None, now=now,
    )
    if not ops_ok:
        raise RemediationDenied(ops_reason or "OPS_GATE_DENIED", "operational control active")

    # 1. The run must be a SERVER-VERIFIED successful local execution.
    if run is None:
        raise RemediationDenied(grm.RC_RUN_NOT_FOUND)
    if run.run_state not in ("RESULT_READY", "COMPLETED"):
        raise RemediationDenied(
            grm.RC_RUN_NOT_VERIFIED,
            f"run state {run.run_state} is not a verified execution")
    result = dict(run.result or {})
    if not result.get("changed_files"):
        raise RemediationDenied(grm.RC_SCOPE_NOT_VERIFIED, "run recorded no verified changes")
    if result.get("executor", {}).get("ok") is False:
        raise RemediationDenied(grm.RC_RUN_NOT_VERIFIED, "executor reported failure")

    # 2. Proposal + digest revalidation (server recomputes, never trusts)
    proposal = (
        await db.execute(
            select(ActionProposal).where(ActionProposal.id == run.action_proposal_id)
        )
    ).scalar_one_or_none()
    if proposal is None:
        raise RemediationDenied(grm.RC_RUN_NOT_FOUND, "proposal missing")
    recomputed = compute_action_digest({
        "action_type": proposal.action_type,
        "repository_id": str(proposal.repository_id),
        "base_commit_sha": proposal.base_commit_sha,
        "target_branch": proposal.target_branch,
        "files": proposal.files,
        "operations": proposal.operations,
        "expected_diff": proposal.expected_diff,
    })
    if recomputed != proposal.action_digest or run.action_digest != proposal.action_digest:
        raise RemediationDenied(grm.RC_ACTION_DIGEST_MISMATCH)

    # 3. Idempotency: an existing remediation for THIS run is returned as-is
    existing = (
        await db.execute(
            select(GitRemediation).where(
                GitRemediation.execution_run_id == run.id)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise RemediationDenied(grm.RC_REPLAY,
                                f"existing remediation {existing.id} state={existing.remediation_state}")

    # 4. One live pipeline per authorization
    live = (
        await db.execute(
            select(GitRemediation).where(
                GitRemediation.execution_authorization_id == run.execution_authorization_id,
                GitRemediation.remediation_state.in_(tuple(grm.LIVE_STATES)),
            )
        )
    ).scalar_one_or_none()
    if live is not None:
        raise RemediationDenied(grm.RC_REMEDIATION_IN_PROGRESS,
                                f"authorization already has live remediation {live.id}")

    # 5. Canonical repository identity (server rows, re-validated by the
    #    Git layer before any URL construction)
    repo = (
        await db.execute(select(Repository).where(Repository.id == proposal.repository_id))
    ).scalar_one_or_none()
    installation = None
    if repo is not None:
        installation = (
            await db.execute(
                select(GithubInstallation).where(
                    GithubInstallation.id == repo.installation_id)
            )
        ).scalar_one_or_none()
    if repo is None or installation is None:
        raise RemediationDenied(grm.RC_REMOTE_MISMATCH, "repository identity incomplete")

    # 6. Server-derived stage ceiling (unknown action type → deny)
    ceiling = _ceiling_for(proposal.action_type)
    if ceiling is None:
        raise RemediationDenied(grm.RC_STAGE_EXCEEDED,
                                "action type has no remediation stage ceiling")

    # 7. Branches: remediation branch is SERVER-GENERATED; the PR base is
    #    the digest-bound, human-approved proposal target branch.
    try:
        grm.validate_repo_branch_name(proposal.target_branch)
        remediation_branch = grm.generate_remediation_branch(str(run.id))
    except Exception:
        raise RemediationDenied(grm.RC_BRANCH_INVALID, "proposal branches failed validation")

    # 8. ATOMIC reservation: lock the run row (system serialization point),
    #    re-check inside the lock, then create the exactly-once record.
    lock_denied: Optional[str] = None
    try:
        await db.execute(
            select(ExecutionRun.id).where(ExecutionRun.id == run.id).with_for_update()
        )
        await db.refresh(run)
        if run.run_state not in ("RESULT_READY", "COMPLETED"):
            lock_denied = grm.RC_RUN_NOT_VERIFIED
        else:
            dup = (
                await db.execute(
                    select(GitRemediation.id).where(
                        GitRemediation.execution_run_id == run.id)
                )
            ).scalar_one_or_none()
            if dup is not None:
                lock_denied = grm.RC_REPLAY
    except Exception:
        lock_denied = None  # SQLite unit tests: unique indexes are the backstop
    if lock_denied is not None:
        raise RemediationDenied(lock_denied)

    # 9. Freeze the remediation contract
    remediation_uuid = uuid4()
    contract = grm.GitRemediationContract(
        contract_version=grm.CONTRACT_VERSION,
        git_remediation_id=str(remediation_uuid),
        execution_run_id=str(run.id),
        execution_authorization_id=str(run.execution_authorization_id),
        action_digest=proposal.action_digest,
        repository_id=str(proposal.repository_id),
        repo_owner=repo.owner,
        repo_name=repo.name,
        installation_id=int(installation.installation_id),
        base_commit_sha=proposal.base_commit_sha,
        source_branch=proposal.target_branch,
        target_branch=proposal.target_branch,
        remediation_branch=remediation_branch,
        authorized_files=tuple(proposal.files or ()),
        stage_ceiling=ceiling,
    )
    contract_digest = grm.compute_contract_digest(contract)
    if not grm.verify_contract_digest(contract, contract_digest):
        raise RemediationDenied(grm.RC_CONTRACT_INVALID)

    remediation = GitRemediation(
        id=remediation_uuid,
        execution_run_id=run.id,
        execution_authorization_id=run.execution_authorization_id,
        action_proposal_id=proposal.id,
        repository_id=proposal.repository_id,
        action_digest=proposal.action_digest,
        remediation_contract=contract.to_dict(),
        remediation_contract_digest=contract_digest,
        contract_version=grm.CONTRACT_VERSION,
        repo_owner=repo.owner,
        repo_name=repo.name,
        installation_id=int(installation.installation_id),
        base_commit_sha=proposal.base_commit_sha,
        source_branch=proposal.target_branch,
        target_branch=proposal.target_branch,
        remediation_state=grm.GitRemediationState.PENDING,
        remediation_branch=remediation_branch,
        stage_ceiling=ceiling,
        created_by_user_id=proposal.created_by,
    )
    db.add(remediation)
    await _audit(
        db, remediation=remediation, repository_id=remediation.repository_id,
        event_type="GIT_REMEDIATION_CREATED", reason_code=grm.RC_OK,
        extra={"stage_ceiling": ceiling, "contract_digest": contract_digest},
    )
    # Capture identity BEFORE the commit: a failed commit + rollback()
    # expires ORM attributes, and reading run.id afterwards would trigger
    # an implicit lazy load outside the greenlet context (MissingGreenlet).
    _run_id = run.id
    try:
        await db.commit()
    except Exception as exc:
        await db.rollback()
        # Concurrent creation won: classify deterministically (no duplicates)
        winner = (
            await db.execute(
                select(GitRemediation).where(
                    GitRemediation.execution_run_id == _run_id)
            )
        ).scalar_one_or_none()
        if winner is not None:
            raise RemediationDenied(grm.RC_REPLAY,
                                    f"existing remediation {winner.id}")
        logger.warning("remediation creation conflict err=%s", str(exc)[:100])
        raise RemediationDenied("REMEDIATION_CONFLICT")
    await db.refresh(remediation)
    return remediation


# ── Content reconstruction (sandboxed; proven against run snapshots) ─


def _load_after_hashes(db: AsyncSession, run_id) -> dict[str, str]:
    raise RuntimeError("session not bound")


def bind_session_lookups(db: AsyncSession) -> None:
    """Bind the DB lookup used by the remediation pipeline.

    The loader keeps the same (db, run_id) signature as the unbound stub:
    the session argument is the pipeline's request-scoped session, while
    the bound loader pins the session this binding was created with.
    """
    global _load_after_hashes

    async def _loader(_db: AsyncSession, run_id):
        rows = (
            await db.execute(
                select(WorkspaceSnapshot)
                .where(
                    WorkspaceSnapshot.execution_run_id == run_id,
                    WorkspaceSnapshot.phase == "AFTER",
                )
            )
        ).scalars().all()
        return {r.file_path: r.content_sha256 for r in rows}

    _load_after_hashes = _loader


async def _reconstruct_verified_content(
    db: AsyncSession, *, run: ExecutionRun, proposal: ActionProposal,
    ws_dir: str, sandbox_factory=None,
) -> list[dict]:
    """Reconstruct the run's verified AFTER content INSIDE the sandbox and
    prove it byte-identical to the run's persisted snapshot hashes.

    The sandbox materializes files from server-trusted data (the payload
    written by this host), runs the SAME closed-world executor over the
    SAME base content, and produces the after-content. No repository code
    runs; the sandbox has no network; the host never applies content it
    has not verified.

    Returns the reconstructed file list [{path, sha256, size_bytes}].
    Raises RemediationDenied on any mismatch (fail closed → STALE).
    """
    bind_session_lookups(db)
    after_hashes = await _load_after_hashes(db, run.id)
    if not after_hashes:
        raise RemediationDenied(grm.RC_SCOPE_NOT_VERIFIED, "run has no AFTER snapshot")

    # Re-derive content: base content is fetched by the host from the SAME
    # trusted source (GitHub contents API at the pinned base SHA) into the
    # workspace; the sandbox then applies the approved operations and the
    # host proves the result equals the run's AFTER hashes.
    try:
        from app.services import execution_service as exec_svc
        exec_svc.bind_session_lookups(db)
        repo_row = await exec_svc._session_repo(proposal.repository_id)
        installation = await exec_svc._session_installation(repo_row.installation_id)
        await workspace_svc.materialize_workspace(
            installation_id=int(installation.installation_id),
            owner=repo_row.owner,
            repo_name=repo_row.name,
            base_commit_sha=proposal.base_commit_sha,
            files=list(proposal.files or ()),
            workspace_dir=ws_dir,
        )
    except workspace_svc.MaterializationError as exc:
        raise RemediationDenied(grm.RC_BASE_COMMIT_MISMATCH, exc.detail)
    except RemediationDenied:
        raise
    except Exception as exc:
        raise RemediationDenied(grm.RC_GIT_UNAVAILABLE,
                                f"content source unavailable: {type(exc).__name__}")

    # Sandbox: closed-world executor re-applies the approved operations
    sandbox_svc.write_operations_payload(
        ws_dir, list(proposal.files or ()), list(proposal.operations or ())
    )
    sandbox = None
    try:
        sandbox_svc.check_platform_support()
    except sandbox_svc.SandboxUnavailable as exc:
        raise RemediationDenied(exc.reason_code, exc.detail)
    try:
        sandbox = (sandbox_factory(ws_dir) if sandbox_factory is not None
                   else sandbox_svc.create_sandbox(ws_dir))
        result = sandbox_svc.run_executor(sandbox, timeout_seconds=60)
        sandbox_svc.destroy_sandbox(sandbox)
        sandbox = None
        if result.timed_out or (result.exit_code not in (0, None)):
            raise RemediationDenied(grm.RC_GIT_OPERATION_FAILED,
                                    "content reconstruction failed in sandbox")
    except sandbox_svc.SandboxUnavailable as exc:
        raise RemediationDenied(exc.reason_code, exc.detail)
    finally:
        if sandbox is not None:
            sandbox_svc.destroy_sandbox(sandbox)

    # Prove reconstruction == run's verified AFTER content (per-file)
    reconstructed = workspace_svc.snapshot_workspace(ws_dir, "RECON")
    for rel, meta in reconstructed.items():
        if rel == ".cyvrix" or rel.startswith(".cyvrix/"):
            continue
        if rel not in after_hashes:
            raise RemediationDenied(grm.RC_UNEXPECTED_FILE_CHANGE,
                                    f"reconstruction produced unverified path {rel}")
        if meta["sha256"] != after_hashes[rel]:
            raise RemediationDenied(grm.RC_SCOPE_NOT_VERIFIED,
                                    f"reconstruction mismatch for {rel}")
    missing = set(after_hashes) - set(reconstructed)
    if missing:
        raise RemediationDenied(grm.RC_SCOPE_NOT_VERIFIED,
                                f"reconstruction missing {sorted(missing)[:3]}")

    return [
        {"path": rel, "sha256": meta["sha256"], "size_bytes": meta["size_bytes"]}
        for rel, meta in sorted(reconstructed.items())
        if rel != ".cyvrix" and not rel.startswith(".cyvrix/")
    ]


# ── GitHub-side state (fixed endpoints, trusted server identity) ─────


def _github_headers(token: str) -> dict:
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
    }


async def _github_json(method: str, path: str, token: str, *,
                       json_body: Optional[dict] = None) -> tuple[int, Optional[dict]]:
    """Call a FIXED GitHub API path (never repository-derived) with TLS
    verification ON. Returns (status, json-or-None)."""
    base = os.environ.get("GITHUB_API_BASE", "https://api.github.com").rstrip("/")
    if not (base.startswith("https://api.github.com") or
            base.startswith("http://localhost") or
            base.startswith("http://127.0.0.1") or
            base.startswith("http://mock-providers")):
        return 0, None  # fail closed: non-allowlisted host
    import httpx
    async with httpx.AsyncClient(timeout=30.0) as client:  # verify=True default
        resp = await client.request(method, f"{base}{path}",
                                    headers=_github_headers(token), json=json_body)
    try:
        body = resp.json()
    except Exception:
        body = None
    return resp.status_code, body


async def _verify_remote_branch(
    token: str, owner: str, name: str, branch: str, expected_sha: Optional[str]
) -> tuple[bool, str, Optional[str]]:
    """Read back the remote branch (Phase 20). Returns (ok, reason, sha)."""
    status, body = await _github_json(
        "GET", f"/repos/{owner}/{name}/branches/{branch}", token)
    if status == 404:
        if expected_sha is None:
            return True, grm.RC_OK, None  # expected: branch does not exist yet
        return False, grm.RC_REMOTE_STATE_MISMATCH, None
    if status != 200 or not isinstance(body, dict):
        return False, grm.RC_GITHUB_INCONSISTENT, None
    sha = (body.get("commit") or {}).get("sha", "")
    if not sha:
        return False, grm.RC_GITHUB_INCONSISTENT, None
    if expected_sha is not None and sha.lower() != expected_sha.lower():
        return False, grm.RC_REMOTE_STATE_MISMATCH, None
    return True, grm.RC_OK, sha.lower()


# ── The pipeline ─────────────────────────────────────────────────────


async def execute_remediation(
    db: AsyncSession, *, remediation: GitRemediation, actor_id=None,
    sandbox_factory=None,
) -> GitRemediation:
    """Run the controlled Git/GitHub pipeline for a created remediation.

    Stages: verify → (branch) → commit → [credential → push → verify → PR]
    per the frozen stage ceiling. Every uncertain state fails closed.
    """
    contract_dict = dict(remediation.remediation_contract or {})
    authorized_files = list(contract_dict.get("authorized_files") or ())
    ceiling = remediation.stage_ceiling
    remote_base = os.environ.get("GITHUB_REMOTE_BASE", os.environ.get("GITHUB_API_BASE", "https://github.com"))
    remote_base = remote_base.replace("api.", "", 1) if remote_base.startswith("https://api.") else remote_base

    async def _fail(code: str, detail: str, state: str = "FAILED") -> GitRemediation:
        remediation.remediation_state = state
        remediation.fail_reason_code = code
        remediation.fail_detail = detail[:500]
        remediation.finished_at = _utcnow()
        await _audit(
            db, remediation=remediation, repository_id=remediation.repository_id,
            event_type="GIT_REMEDIATION_FAILED" if state == "FAILED" else f"REMEDIATION_{state}",
            reason_code=code, commit=True,
        )
        await db.refresh(remediation)
        return remediation

    # 0. ATOMIC claim: serialize concurrent executors on the remediation
    #    row (Phase 24). Only the transaction that observes PENDING inside
    #    the lock may start the pipeline; every other concurrent call
    #    re-reads the committed state (live → idempotent no-op, terminal →
    #    never resurrect). Without this, two simultaneous executors could
    #    both pass the PENDING check and race the git/push stages.
    #    (SQLite unit tests ignore FOR UPDATE; their serialized event loop
    #    plus the state guards below remain the backstop there.)
    await db.execute(
        select(GitRemediation.id).where(
            GitRemediation.id == remediation.id).with_for_update()
    )
    await db.refresh(remediation)
    if remediation.remediation_state != grm.GitRemediationState.PENDING:
        return remediation  # live: no-op · terminal: never resurrect

    # 1. Contract integrity
    try:
        from app.services.git_remediation_model import GitRemediationContract
        rebuilt = GitRemediationContract(
            contract_version=contract_dict.get("contract_version", ""),
            git_remediation_id=contract_dict.get("git_remediation_id", ""),
            execution_run_id=contract_dict.get("execution_run_id", ""),
            execution_authorization_id=contract_dict.get("execution_authorization_id", ""),
            action_digest=contract_dict.get("action_digest", ""),
            repository_id=contract_dict.get("repository_id", ""),
            repo_owner=contract_dict.get("repo_owner", ""),
            repo_name=contract_dict.get("repo_name", ""),
            installation_id=int(contract_dict.get("installation_id", 0)),
            base_commit_sha=contract_dict.get("base_commit_sha", ""),
            source_branch=contract_dict.get("source_branch", ""),
            target_branch=contract_dict.get("target_branch", ""),
            remediation_branch=contract_dict.get("remediation_branch", ""),
            authorized_files=tuple(contract_dict.get("authorized_files") or ()),
            stage_ceiling=contract_dict.get("stage_ceiling", ""),
        )
        if not grm.verify_contract_digest(rebuilt, remediation.remediation_contract_digest):
            return await _fail(grm.RC_CONTRACT_DIGEST_MISMATCH, "contract digest mismatch")
    except Exception:
        return await _fail(grm.RC_CONTRACT_INVALID, "contract unusable")

    # 2. VERIFYING: workspace → reconstruct+prove → remote/base verification
    remediation.remediation_state = grm.GitRemediationState.VERIFYING
    await db.commit()

    ws_dir = workspace_svc.new_workspace_dir()
    git_ws = os.path.join(ws_dir, "repo")
    os.makedirs(git_ws, mode=0o700)
    token: Optional[str] = None
    try:
        run = (
            await db.execute(
                select(ExecutionRun).where(ExecutionRun.id == remediation.execution_run_id)
            )
        ).scalar_one_or_none()
        proposal = (
            await db.execute(
                select(ActionProposal).where(
                    ActionProposal.id == remediation.action_proposal_id)
            )
        ).scalar_one_or_none()
        if run is None or proposal is None:
            return await _fail(grm.RC_RUN_NOT_FOUND, "run/proposal vanished")

        # Kill switch again before any Git work (Phase 25)
        disabled, ks_reason = await read_kill_switch(db)
        if disabled:
            return await _fail(ks_reason or grm.RC_KILL_SWITCH_ACTIVE,
                               "kill switch active (verify)")

        # V3.7: pause/drain takes effect at stage boundaries too —
        # DRAINING stops the pipeline before the next external effect.
        from app.services import ops_service as _ops
        _ops_state, _ops_fail = await _ops.read_operational_state(db)
        if _ops_state == "DRAINING":
            return await _fail("SYSTEM_DRAINING", "drain requested at stage boundary")
        if _ops_state is None:
            return await _fail(_ops_fail or "OPS_STATE_UNREADABLE", "operational state unreadable")

        # Reconstruct + prove content (sandboxed; fail closed on mismatch)
        reconstructed = await _reconstruct_verified_content(
            db, run=run, proposal=proposal, ws_dir=ws_dir,
            sandbox_factory=sandbox_factory)

        # Git workspace: init + fetch + verify base (remote identity checked
        # by git_ops URL construction from canonical identity)
        try:
            remote_url = git_ops.build_remote_url(remote_base, remediation.repo_owner,
                                                  remediation.repo_name)
            git_ops.init_repo(git_ws, remote_url)
            git_ops.fetch_and_verify_base(
                git_ws, remote_url, remediation.source_branch,
                remediation.base_commit_sha)
            git_ops.checkout_base(git_ws, remediation.base_commit_sha)
            git_ops.create_branch(git_ws, remediation.remediation_branch,
                                  remediation.base_commit_sha)
        except git_ops.GitError as exc:
            state = ("STALE" if exc.reason_code in
                     (grm.RC_BASE_COMMIT_MISMATCH, grm.RC_REMOTE_STATE_MISMATCH)
                     else "FAILED")
            return await _fail(exc.reason_code, exc.detail, state=state)

        # Apply reconstructed content into the git workspace (scoped)
        try:
            for item in reconstructed:
                rel = item["path"]
                if rel not in set(authorized_files):
                    return await _fail(grm.RC_UNEXPECTED_FILE_CHANGE,
                                       f"reconstructed path outside authorization: {rel}")
                target = os.path.join(git_ws, *rel.split("/"))
                src = os.path.join(ws_dir, *rel.split("/"))
                os.makedirs(os.path.dirname(target) or git_ws, exist_ok=True)
                shutil.copyfile(src, target)
        except RemediationDenied:
            raise
        except Exception as exc:
            return await _fail(grm.RC_GIT_OPERATION_FAILED,
                               f"content apply failed: {type(exc).__name__}")

        # Stage + server-side diff + scope/secret validation (Phases 14-16)
        try:
            git_ops.stage_authorized_files(git_ws, authorized_files)
            changes, raw_diff = git_ops.staged_change_set(git_ws)
        except git_ops.GitError as exc:
            return await _fail(exc.reason_code, exc.detail)

        changed_paths = {c["path"] for c in changes}
        if changed_paths != set(authorized_files):
            return await _fail(grm.RC_UNEXPECTED_FILE_CHANGE,
                               f"git change set differs from authorization: "
                               f"{sorted(changed_paths ^ set(authorized_files))[:5]}")
        for c in changes:
            if c["status"] not in ("M", "A"):
                return await _fail(grm.RC_UNEXPECTED_FILE_CHANGE,
                                   f"unexpected change status {c['status']} for {c['path']}")

        # Secret scan over the staged diff (never prints matches)
        secret_hits = grm.scan_text_for_secrets(raw_diff)
        if secret_hits:
            return await _fail(grm.RC_SECRET_DETECTED,
                               f"credential-shaped content in staged changes: {secret_hits[:3]}")

        # Commit (kill switch check first; Phase 25)
        disabled, ks_reason = await read_kill_switch(db)
        if disabled:
            return await _fail(ks_reason or grm.RC_KILL_SWITCH_ACTIVE,
                               "kill switch active (commit)")
        remediation.remediation_state = grm.GitRemediationState.COMMITTING
        await db.commit()
        try:
            message = grm.build_commit_message(
                repo_name=remediation.repo_name,
                action_digest=remediation.action_digest,
                base_commit_sha=remediation.base_commit_sha,
                execution_run_id=str(remediation.execution_run_id),
                git_remediation_id=str(remediation.id),
                finding_title=f"{proposal.action_type} remediation",
            )
            committed = git_ops.commit(git_ws, message)
            parent = git_ops.commit_parent(git_ws)
            if parent != remediation.base_commit_sha.lower():
                return await _fail(grm.RC_BASE_COMMIT_MISMATCH,
                                   "commit parent is not the authorized base")
        except git_ops.GitError as exc:
            return await _fail(exc.reason_code, exc.detail)
        remediation.committed_sha = committed
        remediation.remediation_state = grm.GitRemediationState.COMMITTED
        await _audit(db, remediation=remediation,
                     repository_id=remediation.repository_id,
                     event_type="GIT_COMMIT_CREATED", reason_code=grm.RC_OK,
                     extra={"committed_sha": committed})
        await db.commit()

        if not grm.stage_at_least(ceiling, grm.STAGE_PUSH_ALLOWED):
            remediation.finished_at = _utcnow()
            await db.commit()
            await db.refresh(remediation)
            return remediation  # LOCAL_ONLY / COMMIT_ALLOWED ceiling reached

        # 3. CREDENTIAL (kill switch checked inside issuance)
        from app.services import github_credentials
        token, cred_denied = await github_credentials.issue_push_token(
            db, remediation_row=remediation, actor_id=actor_id)
        if token is None:
            return await _fail(cred_denied or grm.RC_CREDENTIAL_DENIED,
                               "credential issuance denied")

        # 4. PUSH (no force; expected remote state = absent-or-matching)
        disabled, ks_reason = await read_kill_switch(db)
        if disabled:
            return await _fail(ks_reason or grm.RC_KILL_SWITCH_ACTIVE,
                               "kill switch active (push)")
        remediation.remediation_state = grm.GitRemediationState.PUSHING
        await _audit(db, remediation=remediation,
                     repository_id=remediation.repository_id,
                     event_type="GITHUB_PUSH_STARTED", reason_code=grm.RC_OK,
                     commit=True)
        try:
            pushed = git_ops.push_branch(
                git_ws, remote_url, remediation.remediation_branch, token,
                expected_remote_sha=None)
            if pushed != committed:
                return await _fail(grm.RC_GITHUB_STATE_MISMATCH,
                                   "pushed SHA differs from local commit")
        except git_ops.GitError as exc:
            code = (grm.RC_REMOTE_STATE_MISMATCH if exc.reason_code == grm.RC_REMOTE_STATE_MISMATCH
                    else exc.reason_code)
            state = "INCONSISTENT" if exc.reason_code == grm.RC_GITHUB_STATE_MISMATCH else "FAILED"
            return await _fail(code, exc.detail, state=state)
        remediation.pushed_sha = pushed
        remediation.remediation_state = grm.GitRemediationState.PUSHED
        await _audit(db, remediation=remediation,
                     repository_id=remediation.repository_id,
                     event_type="GITHUB_PUSH_SUCCEEDED", reason_code=grm.RC_OK,
                     extra={"pushed_sha": pushed})
        await db.commit()

        if not grm.stage_at_least(ceiling, grm.STAGE_PR_ALLOWED):
            remediation.finished_at = _utcnow()
            await db.commit()
            await db.refresh(remediation)
            return remediation  # PUSH_ALLOWED ceiling reached

        # 5. PR creation (Phase 19; kill switch first)
        disabled, ks_reason = await read_kill_switch(db)
        if disabled:
            return await _fail(ks_reason or grm.RC_KILL_SWITCH_ACTIVE,
                               "kill switch active (pr)")
        remediation.remediation_state = grm.GitRemediationState.PR_CREATING
        await db.commit()
        # Expected remote state for the base branch is existence-only
        ok_base, base_reason, _ = await _verify_remote_branch(
            token, remediation.repo_owner, remediation.repo_name,
            remediation.target_branch, expected_sha=None)
        if not ok_base:
            return await _fail(base_reason, "PR base branch verification failed")
        title, body = grm.build_pr_title_and_body(
            finding_title=f"{proposal.action_type} remediation",
            severity=str(proposal.risk_level or "UNKNOWN"),
            repo_name=remediation.repo_name,
            base_commit_sha=remediation.base_commit_sha,
            remediation_branch=remediation.remediation_branch,
            authorized_files=tuple(authorized_files),
            action_digest=remediation.action_digest,
            git_remediation_id=str(remediation.id),
            execution_run_id=str(remediation.execution_run_id),
        )
        status, pr = await _github_json(
            "POST", f"/repos/{remediation.repo_owner}/{remediation.repo_name}/pulls",
            token,
            json_body={
                "title": title,
                "body": body,
                "head": remediation.remediation_branch,
                "base": remediation.target_branch,
            },
        )
        if status not in (200, 201) or not isinstance(pr, dict):
            return await _fail(grm.RC_PR_FAILED, f"PR creation failed (status {status})")
        # PR verification (Phase 21): repository identity, branches, head SHA
        pr_head_ref = ((pr.get("head") or {}).get("ref") or "")
        pr_base_ref = ((pr.get("base") or {}).get("ref") or "")
        pr_head_sha = ((pr.get("head") or {}).get("sha") or "").lower()
        pr_repo_full = (((pr.get("base") or {}).get("repo") or {}).get("full_name") or "")
        if (pr_head_ref != remediation.remediation_branch
                or pr_base_ref != remediation.target_branch
                or pr_head_sha != (remediation.pushed_sha or "").lower()
                or pr_repo_full.lower() != f"{remediation.repo_owner}/{remediation.repo_name}".lower()):
            return await _fail(grm.RC_GITHUB_STATE_MISMATCH,
                               "returned PR does not match the authorized mutation",
                               state="INCONSISTENT")
        remediation.pr_number = int(pr.get("number") or 0) or None
        remediation.pr_url = str(pr.get("html_url") or "")
        remediation.pr_state = str(pr.get("state") or "open")
        remediation.remediation_state = grm.GitRemediationState.PR_CREATED
        await _audit(db, remediation=remediation,
                     repository_id=remediation.repository_id,
                     event_type="PR_CREATED", reason_code=grm.RC_OK,
                     extra={"pr_number": remediation.pr_number,
                            "pr_url": remediation.pr_url})
        remediation.finished_at = _utcnow()
        await db.commit()
        await db.refresh(remediation)
        return remediation

    except RemediationDenied as exc:
        return await _fail(exc.reason_code, exc.detail)
    except Exception as exc:
        logger.exception("remediation pipeline error")
        return await _fail(grm.RC_GIT_OPERATION_FAILED,
                           f"pipeline error: {type(exc).__name__}")
    finally:
        # Guaranteed cleanup: destroy the workspace either way (§103 analog).
        ws_ok, ws_detail = workspace_svc.remove_workspace_dir(ws_dir)
        remediation.cleanup_status = "COMPLETED" if ws_ok else "FAILED"
        remediation.cleanup_detail = (ws_detail or "")[:200] or None
        if not ws_ok:
            remediation.remediation_state = (
                remediation.remediation_state
                if remediation.remediation_state in ("FAILED", "STALE", "INCONSISTENT")
                else "FAILED"
            )
        try:
            await db.commit()
        except Exception:
            await db.rollback()
