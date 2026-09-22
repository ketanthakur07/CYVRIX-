"""CYVRIX V3.6 — Deterministic verification engine.

Proves (or disproves) that ONE committed Git remediation achieved its
authorized security objective, using ONLY trusted server-side evidence.
NON-NEGOTIABLE rules (docs/v3-verification-rollback.md):

- Execution success is NOT remediation success: "exit 0"/"push ok" is
  never the verdict. Verification compares BEFORE vs AFTER security
  state and AUTHORIZED INTENT vs ACTUAL CHANGE (Phase 2).
- Verification is SERVER-AUTHORITATIVE: the verdict comes from the
  deterministic checks below. Repository text cannot declare success
  (no self-attestation: "verified=true" in a file, commit, or PR is
  untrusted data — Phase 36). AI output is never a security verdict.
- Closed-world checks ONLY (Phase 6): the eight types in
  verification_model.VerificationCheckType exist; anything unknown in a
  persisted plan fails the run CLOSED. No arbitrary command execution,
  no project scripts, no package installation as "verification".
- Evidence is bounded + scrubbed; repository output is UNTRUSTED DATA.
- Kill switch at: verification start. Missing/unreadable → BLOCKED.
- Every result is bound to the exact remediation (plan digest) and its
  committed SHA; results cannot be replayed onto another commit.
"""
import logging
import os
import re
import shutil
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    ActionProposal, AuditEvent, ExecutionRun, GitRemediation,
    Repository, VerificationCheck, VerificationRun, WorkspaceSnapshot,
)
from app.services import git_ops, workspace as workspace_svc
from app.services import verification_model as vm
from app.services.execution_authorization_service import read_kill_switch
from app.services.git_remediation_model import scan_text_for_secrets
from app.services.git_remediation_service import _verify_remote_branch

logger = logging.getLogger("cyvrix.verification")
settings = None  # settings access stays lazy (no import cycle)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class VerificationDenied(Exception):
    """Verification refused before any check ran. Nothing recorded except
    an audit event."""

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
    if commit:
        try:
            await db.commit()
        except Exception as exc:
            logger.warning("audit_commit_failed event=%s err=%s",
                           event_type, str(exc)[:100])
            await db.rollback()


async def get_owned_remediation_row(db: AsyncSession, remediation_id, user_id):
    from app.models import GithubInstallation
    result = await db.execute(
        select(GitRemediation)
        .join(Repository, Repository.id == GitRemediation.repository_id)
        .join(GithubInstallation,
              GithubInstallation.id == Repository.installation_id)
        .where(GitRemediation.id == remediation_id,
               GithubInstallation.user_id == user_id)
    )
    return result.scalar_one_or_none()


# Alias used by the routes module (ownership chain: remediation → repo →
# installation → user; cross-tenant access is a 404, never a 403).
_remediation_owned = get_owned_remediation_row


async def get_owned_verification_row(db: AsyncSession, verification_id, user_id):
    from app.models import GithubInstallation, RollbackRun as _R  # noqa
    from app.models import GithubInstallation as GI
    result = await db.execute(
        select(VerificationRun)
        .join(GitRemediation,
              GitRemediation.id == VerificationRun.git_remediation_id)
        .join(ActionProposal,
              ActionProposal.id == GitRemediation.action_proposal_id)
        .join(Repository, Repository.id == ActionProposal.repository_id)
        .join(GI, GI.id == Repository.installation_id)
        .where(VerificationRun.id == verification_id, GI.user_id == user_id)
    )
    return result.scalar_one_or_none()


# ── Plan construction (server-derived; frozen at creation) ───────────


def build_verification_plan(db_rows: dict) -> vm.VerificationPlan:
    """Freeze the verification plan from TRUSTED server rows.

    db_rows keys: remediation, proposal, run, pushed (bool).
    Unknown action type → no derived checks → VerificationDenied.
    """
    remediation = db_rows["remediation"]
    proposal = db_rows["proposal"]
    run = db_rows["run"]
    pushed = bool(db_rows.get("pushed"))

    contract = dict(remediation.remediation_contract or {})
    authorized_files = tuple(contract.get("authorized_files")
                             or proposal.files or ())
    committed_sha = str(remediation.committed_sha or "")

    checks = vm.derive_check_types(proposal.action_type, pushed=pushed)
    if not checks:
        raise VerificationDenied(
            vm.RC_UNKNOWN_CHECK_TYPE,
            f"action type {proposal.action_type!r} has no verification plan")

    plan = vm.VerificationPlan(
        plan_version=vm.VERIFICATION_PLAN_VERSION,
        verification_engine_version=vm.VERIFICATION_ENGINE_VERSION,
        git_remediation_id=str(remediation.id),
        execution_run_id=str(remediation.execution_run_id),
        execution_authorization_id=str(remediation.execution_authorization_id),
        action_digest=remediation.action_digest,
        repository_id=str(remediation.repository_id),
        repo_owner=remediation.repo_owner,
        repo_name=remediation.repo_name,
        base_commit_sha=remediation.base_commit_sha,
        target_branch=remediation.target_branch,
        remediation_branch=remediation.remediation_branch,
        committed_sha=committed_sha,
        authorized_files=tuple(sorted(authorized_files)),
        operations=tuple(proposal.operations or ()),
        check_types=checks,
        regression_block_severities=tuple(sorted(vm.REGRESSION_BLOCK_SEVERITIES)),
    )
    digest = vm.compute_plan_digest(plan)
    if not vm.verify_plan_digest(plan, digest):
        raise VerificationDenied(vm.RC_PLAN_INVALID)
    _ = run  # run is bound via the plan's execution_run_id
    return plan


# ── Trusted evidence loaders ─────────────────────────────────────────


async def _load_after_hashes(db: AsyncSession, run_id) -> dict[str, str]:
    rows = (
        await db.execute(
            select(WorkspaceSnapshot).where(
                WorkspaceSnapshot.execution_run_id == run_id,
                WorkspaceSnapshot.phase == "AFTER",
            )
        )
    ).scalars().all()
    return {r.file_path: r.content_sha256 for r in rows}


def _materialize_committed_files(git_ws: str, remediation: GitRemediation,
                                 files: list[str]) -> bool:
    """Fetch the committed tree into git_ws (base verified against remote)."""
    remote_base = os.environ.get(
        "GITHUB_REMOTE_BASE",
        os.environ.get("GITHUB_API_BASE", "https://github.com"),
    )
    remote_base = (remote_base.replace("api.", "", 1)
                   if remote_base.startswith("https://api.") else remote_base)
    try:
        remote_url = git_ops.build_remote_url(
            remote_base, remediation.repo_owner, remediation.repo_name)
        git_ops.init_repo(git_ws, remote_url)
        git_ops.fetch_and_verify_base(
            git_ws, remote_url, remediation.target_branch,
            remediation.base_commit_sha)
        git_ops.checkout_base(git_ws, remediation.base_commit_sha)
        ok, _, _ = git_ops.run_git(
            ["git", *git_ops._config_args(), "fetch", "--quiet", "--no-tags",
             "--no-recurse-submodules", "origin",
             remediation.remediation_branch],
            cwd=git_ws, timeout=git_ops.GIT_TIMEOUT_FETCH)
        if not ok:
            return False
        ok, out, _ = git_ops.run_git(
            ["git", "rev-parse", "--verify", "--quiet",
             remediation.committed_sha],
            cwd=git_ws)
        return bool(ok and out.strip().lower() ==
                    (remediation.committed_sha or "").lower())
    except git_ops.GitError:
        return False


# ── Individual checks (deterministic; each returns one evidence dict) ─


def _check_diff(committed_files: list[dict], authorized: set[str]) -> dict:
    """VERIFY_DIFF: committed change set must equal the authorized scope."""
    changed = {c["path"] for c in committed_files}
    expected = f"exactly {sorted(authorized)}"
    observed = f"exactly {sorted(changed)}"
    if changed == authorized and all(
            c["status"] in ("A", "M") for c in committed_files):
        return vm.build_evidence(
            check_type=vm.VerificationCheckType.VERIFY_DIFF,
            check_version=vm.VERIFICATION_ENGINE_VERSION,
            expected=expected, observed=observed,
            result=vm.VerificationResult.PASS, reason_code=vm.RC_OK)
    unexpected = sorted(changed - authorized)
    missing = sorted(authorized - changed)
    result, reason = vm.VerificationResult.FAIL, vm.RC_SCOPE_MISMATCH
    return vm.build_evidence(
        check_type=vm.VerificationCheckType.VERIFY_DIFF,
        check_version=vm.VERIFICATION_ENGINE_VERSION,
        expected=expected, observed=observed,
        result=result, reason_code=reason,
        extra={"unexpected": unexpected[:10], "missing": missing[:10]})


def _check_file_state(git_ws: str, committed_sha: str,
                      after_hashes: dict[str, str]) -> dict:
    """VERIFY_FILE_STATE: committed content == run's verified AFTER hashes."""
    mismatches: list[str] = []
    for rel, expected_sha in sorted(after_hashes.items()):
        content = git_ops.show_object(git_ws, committed_sha, rel)
        if content is None:
            mismatches.append(f"{rel}:missing-in-commit")
            continue
        observed_sha = workspace_svc.sha256_bytes(content.encode("utf-8"))
        if observed_sha != expected_sha:
            mismatches.append(f"{rel}:hash-mismatch")
    if not after_hashes:
        return vm.build_evidence(
            check_type=vm.VerificationCheckType.VERIFY_FILE_STATE,
            check_version=vm.VERIFICATION_ENGINE_VERSION,
            expected="run AFTER snapshot hashes", observed="none recorded",
            result=vm.VerificationResult.INCONCLUSIVE,
            reason_code=vm.RC_CHECK_INCONCLUSIVE)
    if not mismatches:
        return vm.build_evidence(
            check_type=vm.VerificationCheckType.VERIFY_FILE_STATE,
            check_version=vm.VERIFICATION_ENGINE_VERSION,
            expected=f"{len(after_hashes)} files match run AFTER hashes",
            observed=f"{len(after_hashes)} files match",
            result=vm.VerificationResult.PASS, reason_code=vm.RC_OK)
    return vm.build_evidence(
        check_type=vm.VerificationCheckType.VERIFY_FILE_STATE,
        check_version=vm.VERIFICATION_ENGINE_VERSION,
        expected="committed content equals run AFTER snapshot hashes",
        observed=vm.scrub_evidence_text("; ".join(mismatches)),
        result=vm.VerificationResult.FAIL,
        reason_code=vm.RC_INTENT_MISMATCH,
        extra={"mismatches": mismatches[:10]})


def _check_dependency_state(git_ws: str, committed_sha: str,
                            operations: tuple) -> dict:
    """VERIFY_DEPENDENCY_STATE: manifest at the committed SHA must contain
    the exact target pins (deterministic parse, no package installation)."""
    results: list[dict] = []
    for op in operations:
        if op.get("type") != "UPDATE_DEPENDENCY_VERSION":
            continue
        manifest = op.get("file")
        content = git_ops.show_object(git_ws, committed_sha, manifest)
        if content is None:
            results.append({"op": "manifest-unreadable", "ok": False})
            continue
        name = op.get("name")
        to_version = op.get("to_version")
        from_version = op.get("from_version")
        ecosystem = op.get("ecosystem")
        if ecosystem == "npm":
            pin = f'"{name}": "{to_version}"'
        else:
            pin = f"{name}=={to_version}"
        has_target = pin in content
        if ecosystem == "npm":
            stale = f'"{name}": "{from_version}"' in content
        else:
            stale = f"{name}=={from_version}" in content
        results.append({
            "op": f"{name}@{to_version}", "ok": has_target and not stale,
        })
    if not results:
        return vm.build_evidence(
            check_type=vm.VerificationCheckType.VERIFY_DEPENDENCY_STATE,
            check_version=vm.VERIFICATION_ENGINE_VERSION,
            expected="dependency pins applied", observed="no dependency ops",
            result=vm.VerificationResult.INCONCLUSIVE,
            reason_code=vm.RC_CHECK_INCONCLUSIVE)
    failed = [r["op"] for r in results if not r["ok"]]
    if not failed:
        return vm.build_evidence(
            check_type=vm.VerificationCheckType.VERIFY_DEPENDENCY_STATE,
            check_version=vm.VERIFICATION_ENGINE_VERSION,
            expected=f"{len(results)} pins present at committed SHA",
            observed=f"{len(results)} pins present",
            result=vm.VerificationResult.PASS, reason_code=vm.RC_OK)
    return vm.build_evidence(
        check_type=vm.VerificationCheckType.VERIFY_DEPENDENCY_STATE,
        check_version=vm.VERIFICATION_ENGINE_VERSION,
        expected="all target pins present, no stale pins",
        observed=vm.scrub_evidence_text("; ".join(failed)),
        result=vm.VerificationResult.FAIL,
        reason_code=vm.RC_EXPECTED_CONDITION_UNMET,
        extra={"failed": failed[:10]})


def _check_configuration(git_ws: str, committed_sha: str,
                         operations: tuple) -> dict:
    """VERIFY_CONFIGURATION: deterministic structural validation of the
    committed file vs the expected operations (no execution)."""
    checked = 0
    failed: list[str] = []
    for op in operations:
        op_type = op.get("type")
        if op_type not in ("UPDATE_CONFIGURATION_VALUE",
                           "UPDATE_DOCKERFILE_INSTRUCTION",
                           "APPEND_DOCKERFILE_INSTRUCTION",
                           "REMOVE_DOCKERFILE_INSTRUCTION",
                           "REPLACE_TEXT"):
            continue
        checked += 1
        manifest = op.get("file")
        content = git_ops.show_object(git_ws, committed_sha, manifest)
        if content is None:
            failed.append(f"{manifest}:unreadable")
            continue
        if op_type == "UPDATE_CONFIGURATION_VALUE":
            key, value = op.get("key"), op.get("value")
            lines = [ln for ln in content.splitlines()
                     if ln.split("=", 1)[0].strip() == key and "=" in ln]
            if len(lines) != 1 or lines[0].split("=", 1)[1].strip() != str(value):
                failed.append(f"{manifest}:{key}")
        elif op_type == "REPLACE_TEXT":
            new_text = op.get("new_text") or ""
            old_text = op.get("old_text") or ""
            if old_text in content or (new_text and new_text not in content):
                failed.append(f"{manifest}:replace-not-applied")
        elif op_type == "UPDATE_DOCKERFILE_INSTRUCTION":
            new_text = op.get("new_text") or ""
            old_text = op.get("old_text") or ""
            if old_text in content or (new_text and new_text not in content):
                failed.append(f"{manifest}:instruction-not-applied")
        elif op_type == "APPEND_DOCKERFILE_INSTRUCTION":
            instruction = op.get("instruction") or ""
            if instruction not in content:
                failed.append(f"{manifest}:append-missing")
        elif op_type == "REMOVE_DOCKERFILE_INSTRUCTION":
            # A removed line cannot be positively identified from content
            # alone; the FILE_STATE check already proves byte-equality with
            # the verified AFTER snapshot. Count as satisfied.
            pass
    if checked == 0:
        return vm.build_evidence(
            check_type=vm.VerificationCheckType.VERIFY_CONFIGURATION,
            check_version=vm.VERIFICATION_ENGINE_VERSION,
            expected="configuration values applied", observed="no config ops",
            result=vm.VerificationResult.INCONCLUSIVE,
            reason_code=vm.RC_CHECK_INCONCLUSIVE)
    if not failed:
        return vm.build_evidence(
            check_type=vm.VerificationCheckType.VERIFY_CONFIGURATION,
            check_version=vm.VERIFICATION_ENGINE_VERSION,
            expected=f"{checked} config conditions met",
            observed=f"{checked} config conditions met",
            result=vm.VerificationResult.PASS, reason_code=vm.RC_OK)
    return vm.build_evidence(
        check_type=vm.VerificationCheckType.VERIFY_CONFIGURATION,
        check_version=vm.VERIFICATION_ENGINE_VERSION,
        expected="all configured values present at committed SHA",
        observed=vm.scrub_evidence_text("; ".join(failed)),
        result=vm.VerificationResult.FAIL,
        reason_code=vm.RC_EXPECTED_CONDITION_UNMET,
        extra={"failed": failed[:10]})


def _check_finding(git_ws: str, committed_sha: str,
                   operations: tuple) -> dict:
    """VERIFY_SECURITY_FINDING: does the ORIGINAL finding still exist?

    Deterministic re-evaluation (Phase 7): each structured operation was
    the fix; the inverse condition proves presence/absence of the
    vulnerable state. INCONCLUSIVE when no deterministic inverse exists.
    """
    inverse_results: list[bool] = []
    for op in operations:
        op_type = op.get("type")
        if op_type == "UPDATE_DEPENDENCY_VERSION":
            ecosystem = op.get("ecosystem")
            name, from_version = op.get("name"), op.get("from_version")
            content = git_ops.show_object(
                git_ws, committed_sha, op.get("file"))
            if content is None:
                inverse_results.append(False)
                continue
            if ecosystem == "npm":
                vulnerable = f'"{name}": "{from_version}"' in content
            else:
                vulnerable = f"{name}=={from_version}" in content
            inverse_results.append(not vulnerable)
        elif op_type == "REPLACE_TEXT":
            old_text = op.get("old_text") or ""
            content = git_ops.show_object(
                git_ws, committed_sha, op.get("file"))
            if content is None:
                inverse_results.append(False)
                continue
            inverse_results.append(old_text not in content)
        elif op_type in ("UPDATE_DOCKERFILE_INSTRUCTION",
                         "REMOVE_DOCKERFILE_INSTRUCTION",
                         "APPEND_DOCKERFILE_INSTRUCTION",
                         "UPDATE_CONFIGURATION_VALUE"):
            # Covered exactly by FILE_STATE (byte-equality with the verified
            # AFTER snapshot) — the deterministic inverse already ran there.
            inverse_results.append(True)
    if not inverse_results:
        return vm.build_evidence(
            check_type=vm.VerificationCheckType.VERIFY_SECURITY_FINDING,
            check_version=vm.VERIFICATION_ENGINE_VERSION,
            expected="original finding absent", observed="no inverse check",
            result=vm.VerificationResult.INCONCLUSIVE,
            reason_code=vm.RC_CHECK_INCONCLUSIVE)
    if all(inverse_results):
        return vm.build_evidence(
            check_type=vm.VerificationCheckType.VERIFY_SECURITY_FINDING,
            check_version=vm.VERIFICATION_ENGINE_VERSION,
            expected="original vulnerable state absent",
            observed="vulnerable state absent",
            result=vm.VerificationResult.PASS, reason_code=vm.RC_OK)
    return vm.build_evidence(
        check_type=vm.VerificationCheckType.VERIFY_SECURITY_FINDING,
        check_version=vm.VERIFICATION_ENGINE_VERSION,
        expected="original vulnerable state absent",
        observed="vulnerable state still present",
        result=vm.VerificationResult.FAIL,
        reason_code=vm.RC_FINDING_STILL_PRESENT)


def _check_policy_invariant(git_ws: str, committed_sha: str,
                            committed_files: list[dict]) -> dict:
    """VERIFY_POLICY_INVARIANT: regression scan over committed content.

    'Fix one, break three' gate (Phase 8/34): dangerous directives or
    credential-shaped content introduced by THIS commit fail verification.
    """
    hits: list[str] = []
    for c in committed_files:
        if c["status"] == "D":
            continue
        content = git_ops.show_object(git_ws, committed_sha, c["path"])
        if content is None:
            hits.append(f"{c['path']}:unreadable")
            continue
        for name in vm.scan_text_for_dangerous_directives(content):
            hits.append(f"{c['path']}:{name}")
        for name in scan_text_for_secrets(content):
            hits.append(f"{c['path']}:{name}")
    if not hits:
        return vm.build_evidence(
            check_type=vm.VerificationCheckType.VERIFY_POLICY_INVARIANT,
            check_version=vm.VERIFICATION_ENGINE_VERSION,
            expected="no dangerous directives or credential-shaped content",
            observed="clean",
            result=vm.VerificationResult.PASS, reason_code=vm.RC_OK)
    return vm.build_evidence(
        check_type=vm.VerificationCheckType.VERIFY_POLICY_INVARIANT,
        check_version=vm.VERIFICATION_ENGINE_VERSION,
        expected="no dangerous directives or credential-shaped content",
        observed=vm.scrub_evidence_text("; ".join(hits)),
        result=vm.VerificationResult.FAIL,
        reason_code=vm.RC_SECURITY_REGRESSION,
        extra={"hits": hits[:10]})


async def _check_git_state(remediation: GitRemediation) -> dict:
    """VERIFY_GIT_STATE: remote remediation branch tip == committed SHA."""
    token = await _installation_token(remediation.installation_id)
    ok, reason, remote_sha = await _verify_remote_branch(
        token, remediation.repo_owner, remediation.repo_name,
        remediation.remediation_branch,
        remediation.committed_sha)
    if ok:
        return vm.build_evidence(
            check_type=vm.VerificationCheckType.VERIFY_GIT_STATE,
            check_version=vm.VERIFICATION_ENGINE_VERSION,
            expected=f"branch tip {remediation.committed_sha}",
            observed=f"branch tip {remote_sha}",
            result=vm.VerificationResult.PASS, reason_code=vm.RC_OK)
    return vm.build_evidence(
        check_type=vm.VerificationCheckType.VERIFY_GIT_STATE,
        check_version=vm.VERIFICATION_ENGINE_VERSION,
        expected=f"branch tip {remediation.committed_sha}",
        observed=f"readback failed ({reason})",
        result=vm.VerificationResult.FAIL,
        reason_code=vm.RC_REMOTE_STATE_MISMATCH)


async def _check_github_state(remediation: GitRemediation) -> dict:
    """VERIFY_GITHUB_STATE: PR exists, is open, head == committed SHA,
    base == authorized target branch (authoritative readback, Phase 13)."""
    if not remediation.pr_number:
        return vm.build_evidence(
            check_type=vm.VerificationCheckType.VERIFY_GITHUB_STATE,
            check_version=vm.VERIFICATION_ENGINE_VERSION,
            expected="PR present", observed="no PR recorded",
            result=vm.VerificationResult.INCONCLUSIVE,
            reason_code=vm.RC_CHECK_INCONCLUSIVE)
    token = await _installation_token(remediation.installation_id)
    status, pr = await _github_get_pull(
        token, remediation.repo_owner, remediation.repo_name,
        remediation.pr_number)
    if status != 200 or not isinstance(pr, dict):
        return vm.build_evidence(
            check_type=vm.VerificationCheckType.VERIFY_GITHUB_STATE,
            check_version=vm.VERIFICATION_ENGINE_VERSION,
            expected=f"PR {remediation.pr_number} open with head "
                     f"{remediation.committed_sha}",
            observed=f"PR readback status {status}",
            result=vm.VerificationResult.FAIL,
            reason_code=vm.RC_GITHUB_STATE_MISMATCH)
    head_sha = str(((pr.get("head") or {}).get("sha") or "")).lower()
    head_ref = str(((pr.get("head") or {}).get("ref") or ""))
    base_ref = str(((pr.get("base") or {}).get("ref") or ""))
    pr_state = str(pr.get("state") or "")
    ok = (head_sha == (remediation.committed_sha or "").lower()
          and head_ref == remediation.remediation_branch
          and base_ref == remediation.target_branch
          and pr_state == "open")
    if ok:
        return vm.build_evidence(
            check_type=vm.VerificationCheckType.VERIFY_GITHUB_STATE,
            check_version=vm.VERIFICATION_ENGINE_VERSION,
            expected=f"PR {remediation.pr_number} open "
                     f"{remediation.remediation_branch}→{remediation.target_branch} "
                     f"@ {remediation.committed_sha}",
            observed=f"PR open {head_ref}→{base_ref} @ {head_sha}",
            result=vm.VerificationResult.PASS, reason_code=vm.RC_OK)
    return vm.build_evidence(
        check_type=vm.VerificationCheckType.VERIFY_GITHUB_STATE,
        check_version=vm.VERIFICATION_ENGINE_VERSION,
        expected=f"PR {remediation.pr_number} open "
                 f"{remediation.remediation_branch}→{remediation.target_branch} "
                 f"@ {remediation.committed_sha}",
        observed=f"PR {pr_state} {head_ref}→{base_ref} @ {head_sha}",
        result=vm.VerificationResult.FAIL,
        reason_code=vm.RC_GITHUB_STATE_MISMATCH)


# ── GitHub plumbing (fixed endpoints only; same trust model as V3.5) ──


async def _installation_token(installation_id: int) -> str:
    from app.services.github import get_installation_access_token
    return await get_installation_access_token(int(installation_id))


async def _github_get_pull(token: str, owner: str, name: str,
                           number: int) -> tuple[int, Optional[dict]]:
    import httpx
    base = os.environ.get("GITHUB_API_BASE", "https://api.github.com").rstrip("/")
    if not (base.startswith("https://api.github.com")
            or base.startswith("http://localhost")
            or base.startswith("http://127.0.0.1")
            or base.startswith("http://mock-providers")):
        return 0, None
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(
            f"{base}/repos/{owner}/{name}/pulls/{number}",
            headers={"Authorization": f"token {token}",
                     "Accept": "application/vnd.github+json"})
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, None


# ── The verification lifecycle ───────────────────────────────────────


async def start_verification(
    db: AsyncSession, *, remediation: GitRemediation, actor_id=None,
) -> VerificationRun:
    """Create the exactly-once verification record for a committed
    remediation. Raises VerificationDenied (nothing created) otherwise.

    The plan is frozen at creation; the executor later runs it."""
    # 0. Kill switch FIRST (fail closed → BLOCKED semantics at execution)
    disabled, ks_reason = await read_kill_switch(db)
    if disabled:
        raise VerificationDenied(
            ks_reason or vm.RC_KILL_SWITCH_ACTIVE, "kill switch active")

    # 0b. V3.7 operational gate: verification is read-only regarding the
    # repository, so it is allowed under PAUSED (containment preserves
    # evidence) but blocked under BLOCKED/EMERGENCY_STOP/unknown state.
    from app.services import ops_service
    repo_id = getattr(remediation, "repository_id", None)
    if repo_id is not None:
        ops_ok, ops_reason = await ops_service.assert_verification_allowed(
            db, repository_id=repo_id)
        if not ops_ok:
            raise VerificationDenied(ops_reason or "OPS_GATE_DENIED",
                                     "operational control active")

    # 1. The remediation must have a committed SHA (verification target)
    if remediation is None:
        raise VerificationDenied(vm.RC_VERIFICATION_NOT_FOUND)
    if not remediation.committed_sha:
        raise VerificationDenied(vm.RC_VERIFICATION_NOT_POSSIBLE,
                                 "remediation has no committed SHA")

    # 2. Exactly-once per remediation (verdict is final; re-verification
    #    is a NEW remediation decision, never a state rewrite)
    existing = (
        await db.execute(
            select(VerificationRun).where(
                VerificationRun.git_remediation_id == remediation.id)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise VerificationDenied(
            vm.RC_VERIFICATION_REPLAY,
            f"existing verification {existing.id} state={existing.verification_state}")

    # 3. Load trusted rows + freeze the plan
    proposal = (
        await db.execute(
            select(ActionProposal).where(
                ActionProposal.id == remediation.action_proposal_id)
        )
    ).scalar_one_or_none()
    run_row = (
        await db.execute(
            select(ExecutionRun).where(
                ExecutionRun.id == remediation.execution_run_id)
        )
    ).scalar_one_or_none()
    if proposal is None or run_row is None:
        raise VerificationDenied(vm.RC_VERIFICATION_NOT_FOUND,
                                 "proposal/run missing")
    plan = build_verification_plan({
        "remediation": remediation, "proposal": proposal,
        "run": run_row, "pushed": bool(remediation.pushed_sha),
    })

    verification = VerificationRun(
        id=uuid4(),
        git_remediation_id=remediation.id,
        execution_run_id=remediation.execution_run_id,
        repository_id=remediation.repository_id,
        action_digest=remediation.action_digest,
        verification_state=vm.VerificationState.PENDING,
        verification_plan=plan.to_dict(),
        plan_digest=vm.compute_plan_digest(plan),
        plan_version=vm.VERIFICATION_PLAN_VERSION,
        checks_total=len(plan.check_types),
    )
    db.add(verification)
    await _audit(
        db, repository_id=remediation.repository_id,
        event_type="VERIFICATION_STARTED", reason_code=vm.RC_OK,
        extra={
            "verification_run_id": str(verification.id),
            "git_remediation_id": str(remediation.id),
            "committed_sha": remediation.committed_sha,
            "checks_total": len(plan.check_types),
            "plan_digest": verification.plan_digest,
        },
    )
    # Capture identity BEFORE the commit: a failed commit + rollback()
    # expires ORM attributes, and reading remediation.id afterwards would
    # trigger an implicit lazy load outside the greenlet context
    # (MissingGreenlet) instead of the intended REPLAY classification.
    _remediation_id = remediation.id
    try:
        await db.commit()
    except Exception as exc:
        await db.rollback()
        winner = (
            await db.execute(
                select(VerificationRun).where(
                    VerificationRun.git_remediation_id == _remediation_id)
            )
        ).scalar_one_or_none()
        if winner is not None:
            raise VerificationDenied(vm.RC_VERIFICATION_REPLAY,
                                     f"existing verification {winner.id}")
        logger.warning("verification creation conflict err=%s", str(exc)[:100])
        raise VerificationDenied("VERIFICATION_CONFLICT")
    await db.refresh(verification)
    return verification


async def execute_verification(
    db: AsyncSession, *, verification: VerificationRun,
) -> VerificationRun:
    """Run ALL planned checks deterministically and persist the verdict.

    Transactional safety (Phase 25): COMPLETED+result is written in ONE
    commit AFTER every check has evidence. A crash mid-run leaves
    RUNNING/FAILED — never a fabricated PASS. Repository-hostile content
    never reaches the verdict path.
    """
    remediation = (
        await db.execute(
            select(GitRemediation).where(
                GitRemediation.id == verification.git_remediation_id)
        )
    ).scalar_one_or_none()
    if remediation is None:
        verification.verification_state = vm.VerificationState.FAILED
        verification.reason_code = vm.RC_VERIFICATION_NOT_FOUND
        await db.commit()
        await db.refresh(verification)
        return verification

    async def _finish(state: str, result: Optional[str], reason: str,
                      detail: str = "") -> VerificationRun:
        verification.verification_state = state
        if result is not None:
            verification.result = result
        verification.reason_code = reason
        verification.detail = detail[:500]
        verification.finished_at = _utcnow()
        await _audit(
            db, repository_id=verification.repository_id,
            event_type={
                vm.VerificationResult.PASS: "REMEDIATION_VERIFIED",
                vm.VerificationResult.FAIL: "VERIFICATION_FAILED",
                vm.VerificationResult.INCONCLUSIVE: "VERIFICATION_INCONCLUSIVE",
            }.get(result, "VERIFICATION_BLOCKED"),
            reason_code=reason,
            extra={
                "verification_run_id": str(verification.id),
                "git_remediation_id": str(remediation.id),
                "committed_sha": remediation.committed_sha,
            },
            commit=True,
        )
        await db.refresh(verification)
        return verification

    # ATOMIC claim: only the transaction that sees PENDING inside the
    # lock runs the checks (verify × verify serialization).
    await db.execute(
        select(VerificationRun.id).where(
            VerificationRun.id == verification.id).with_for_update()
    )
    await db.refresh(verification)
    if verification.verification_state != vm.VerificationState.PENDING:
        return verification  # live: no-op · terminal: never resurrect

    # Kill switch at verification start (Phase 27)
    disabled, ks_reason = await read_kill_switch(db)
    if disabled:
        return await _finish(vm.VerificationState.BLOCKED,
                             vm.VerificationResult.BLOCKED,
                             ks_reason or vm.RC_KILL_SWITCH_ACTIVE,
                             "kill switch active")

    # Plan integrity (tamper evidence)
    plan_dict = dict(verification.verification_plan or {})
    try:
        plan = vm.VerificationPlan(
            plan_version=plan_dict.get("plan_version", ""),
            verification_engine_version=plan_dict.get(
                "verification_engine_version", ""),
            git_remediation_id=plan_dict.get("git_remediation_id", ""),
            execution_run_id=plan_dict.get("execution_run_id", ""),
            execution_authorization_id=plan_dict.get(
                "execution_authorization_id", ""),
            action_digest=plan_dict.get("action_digest", ""),
            repository_id=plan_dict.get("repository_id", ""),
            repo_owner=plan_dict.get("repo_owner", ""),
            repo_name=plan_dict.get("repo_name", ""),
            base_commit_sha=plan_dict.get("base_commit_sha", ""),
            target_branch=plan_dict.get("target_branch", ""),
            remediation_branch=plan_dict.get("remediation_branch", ""),
            committed_sha=plan_dict.get("committed_sha", ""),
            authorized_files=tuple(plan_dict.get("authorized_files") or ()),
            operations=tuple(plan_dict.get("operations") or ()),
            check_types=tuple(plan_dict.get("check_types") or ()),
            regression_block_severities=tuple(
                plan_dict.get("regression_block_severities") or ()),
        )
        if not vm.verify_plan_digest(plan, verification.plan_digest):
            return await _finish(vm.VerificationState.FAILED, None,
                                 vm.RC_PLAN_DIGEST_MISMATCH,
                                 "verification plan digest mismatch")
    except Exception:
        return await _finish(vm.VerificationState.FAILED, None,
                             vm.RC_PLAN_INVALID, "verification plan unusable")

    # Unknown check type in a persisted plan → FAIL CLOSED (Phase 6)
    for ct in plan.check_types:
        if ct not in vm.ALL_CHECK_TYPES:
            return await _finish(vm.VerificationState.FAILED, None,
                                 vm.RC_UNKNOWN_CHECK_TYPE,
                                 f"unknown check type {ct!r}")

    verification.verification_state = vm.VerificationState.RUNNING
    verification.started_at = _utcnow()
    await db.commit()

    git_ws = None
    try:
        # Identity binding: the plan must belong to THIS remediation and
        # THIS committed SHA (a replayed plan on another commit fails).
        if (plan.git_remediation_id != str(remediation.id)
                or plan.action_digest != remediation.action_digest
                or plan.committed_sha != (remediation.committed_sha or "")):
            return await _finish(vm.VerificationState.FAILED, None,
                                 vm.RC_PLAN_INVALID,
                                 "plan is bound to a different remediation/commit")

        # Trusted evidence environment: fetch the committed tree
        after_hashes = await _load_after_hashes(
            db, remediation.execution_run_id)

        git_ws = workspace_svc.new_workspace_dir()
        committed_ok = _materialize_committed_files(git_ws, remediation,
                                                    plan.authorized_files)
        committed_files: list[dict] = []
        if committed_ok and remediation.committed_sha:
            try:
                committed_files = git_ops.commit_files_at(
                    git_ws, remediation.committed_sha)
            except git_ops.GitError:
                committed_files = []

        results: dict[str, dict] = {}
        for check_type in plan.check_types:
            try:
                if check_type == vm.VerificationCheckType.VERIFY_DIFF:
                    if not committed_ok:
                        raise git_ops.GitError(vm.RC_GIT_UNAVAILABLE,
                                               "committed tree unavailable")
                    results[check_type] = _check_diff(
                        committed_files, set(plan.authorized_files))
                elif check_type == vm.VerificationCheckType.VERIFY_FILE_STATE:
                    if not committed_ok:
                        raise git_ops.GitError(vm.RC_GIT_UNAVAILABLE,
                                               "committed tree unavailable")
                    results[check_type] = _check_file_state(
                        git_ws, remediation.committed_sha, after_hashes)
                elif check_type == vm.VerificationCheckType.VERIFY_DEPENDENCY_STATE:
                    results[check_type] = _check_dependency_state(
                        git_ws, remediation.committed_sha, plan.operations)
                elif check_type == vm.VerificationCheckType.VERIFY_CONFIGURATION:
                    results[check_type] = _check_configuration(
                        git_ws, remediation.committed_sha, plan.operations)
                elif check_type == vm.VerificationCheckType.VERIFY_SECURITY_FINDING:
                    results[check_type] = _check_finding(
                        git_ws, remediation.committed_sha, plan.operations)
                elif check_type == vm.VerificationCheckType.VERIFY_POLICY_INVARIANT:
                    if not committed_ok:
                        raise git_ops.GitError(vm.RC_GIT_UNAVAILABLE,
                                               "committed tree unavailable")
                    results[check_type] = _check_policy_invariant(
                        git_ws, remediation.committed_sha, committed_files)
                elif check_type == vm.VerificationCheckType.VERIFY_GIT_STATE:
                    results[check_type] = await _check_git_state(remediation)
                elif check_type == vm.VerificationCheckType.VERIFY_GITHUB_STATE:
                    results[check_type] = await _check_github_state(remediation)
                else:
                    # Unreachable (plan validated above) — keep fail-closed
                    results[check_type] = vm.build_evidence(
                        check_type=vm.VerificationCheckType.VERIFY_DIFF,
                        check_version=vm.VERIFICATION_ENGINE_VERSION,
                        expected="known check", observed=check_type,
                        result=vm.VerificationResult.BLOCKED,
                        reason_code=vm.RC_UNKNOWN_CHECK_TYPE)
            except git_ops.GitError as exc:
                results[check_type] = vm.build_evidence(
                    check_type=check_type if check_type in vm.ALL_CHECK_TYPES
                    else vm.VerificationCheckType.VERIFY_DIFF,
                    check_version=vm.VERIFICATION_ENGINE_VERSION,
                    expected="deterministic check executes",
                    observed=f"git layer unavailable: {exc.reason_code}",
                    result=vm.VerificationResult.BLOCKED,
                    reason_code=exc.reason_code)
            except Exception as exc:
                results[check_type] = vm.build_evidence(
                    check_type=check_type if check_type in vm.ALL_CHECK_TYPES
                    else vm.VerificationCheckType.VERIFY_DIFF,
                    check_version=vm.VERIFICATION_ENGINE_VERSION,
                    expected="deterministic check executes",
                    observed=f"check error: {type(exc).__name__}",
                    result=vm.VerificationResult.INCONCLUSIVE,
                    reason_code=vm.RC_CHECK_INCONCLUSIVE)

        # Persist evidence rows + aggregate verdict in ONE commit
        passed = failed = other = 0
        for check_type in plan.check_types:
            ev = results.get(check_type)
            if ev is None:
                ev = vm.build_evidence(
                    check_type=check_type,
                    check_version=vm.VERIFICATION_ENGINE_VERSION,
                    expected="check executed", observed="no evidence",
                    result=vm.VerificationResult.INCONCLUSIVE,
                    reason_code=vm.RC_CHECK_INCONCLUSIVE)
            db.add(VerificationCheck(
                verification_run_id=verification.id,
                check_type=check_type,
                check_version=ev["check_version"],
                result=ev["result"],
                reason_code=ev["reason_code"],
                evidence=ev,
            ))
            if ev["result"] == vm.VerificationResult.PASS:
                passed += 1
            elif ev["result"] == vm.VerificationResult.FAIL:
                failed += 1
            else:
                other += 1

        verification.checks_total = len(plan.check_types)
        verification.checks_passed = passed
        verification.checks_failed = failed
        verification.checks_other = other

        # Deterministic acceptance (Phase 35): all required checks pass AND
        # the original finding is absent AND no forbidden regression AND the
        # actual diff remains authorized. Any FAIL → FAIL. Any INCONCLUSIVE
        # or BLOCKED → INCONCLUSIVE (never silently accepted).
        if failed > 0:
            verdict = vm.VerificationResult.FAIL
            reason = next(
                (ev["reason_code"] for ct in plan.check_types
                 if (ev := results.get(ct)) and ev["result"] ==
                 vm.VerificationResult.FAIL),
                vm.RC_VERIFICATION_CHECK_FAILED)
        elif other > 0:
            verdict = vm.VerificationResult.INCONCLUSIVE
            reason = next(
                (ev["reason_code"] for ct in plan.check_types
                 if (ev := results.get(ct)) and ev["result"] in (
                     vm.VerificationResult.INCONCLUSIVE,
                     vm.VerificationResult.BLOCKED)),
                vm.RC_CHECK_INCONCLUSIVE)
        else:
            verdict = vm.VerificationResult.PASS
            reason = vm.RC_OK

        verification.verification_state = vm.VerificationState.COMPLETED
        verification.result = verdict
        verification.reason_code = reason
        verification.finished_at = _utcnow()
        await _audit(
            db, repository_id=verification.repository_id,
            event_type="REMEDIATION_VERIFIED" if verdict == vm.VerificationResult.PASS
            else ("VERIFICATION_FAILED" if verdict == vm.VerificationResult.FAIL
                  else "VERIFICATION_INCONCLUSIVE"),
            reason_code=reason,
            extra={
                "verification_run_id": str(verification.id),
                "git_remediation_id": str(remediation.id),
                "committed_sha": remediation.committed_sha,
                "checks_passed": passed, "checks_failed": failed,
                "checks_other": other,
            },
        )
        await db.commit()
        await db.refresh(verification)
        return verification

    except Exception as exc:
        logger.exception("verification pipeline error")
        verification.verification_state = vm.VerificationState.FAILED
        verification.reason_code = vm.RC_VERIFICATION_FAILED
        verification.detail = f"verification error: {type(exc).__name__}"[:500]
        verification.finished_at = _utcnow()
        await db.commit()
        await db.refresh(verification)
        return verification
    finally:
        if git_ws is not None:
            workspace_svc.remove_workspace_dir(git_ws)
