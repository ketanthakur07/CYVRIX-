"""V3.7 environment certification driver — REAL stack scenario.

Runs against the real Docker stack (Postgres 5433 / Redis 6380 /
mock-provider git transport 8100). Uses the SERVER's own services and
models (no re-implementations). Verifies, with evidence:

  Phase 6   NORMAL grants execution; PAUSED/EMERGENCY_STOP/DRAINING deny
  Phase 7   kill switch fail-closed (missing control row)
  Phase 10  single-active lease; cross-worker takeover denied
  Phase 12  reconciliation classifies remote branch state via REAL
            `git ls-remote` (GITHUB_API_BASE -> mock git server)
  Phase 16  emergency stop: execution + credential issuance denied
  Phase 17  one-way door (ES -> NORMAL refused); reconciled resume
  Phase 18  orphan workspace cleanup (active workspace protected)

Usage (from repo root, real stack up):
  RUN_INTEGRATION_TESTS=1 \
  DATABASE_URL=postgresql+asyncpg://cyvrix_test:cyvrix_test_password@localhost:5433/cyvrix_test \
  REDIS_URL=redis://localhost:6380/0 \
  SECRET_KEY=test-secret-key-for-integration-only-not-for-production-32chars! \
  ENVIRONMENT=development \
  python tests/cert_v37_real_stack.py
"""
import asyncio
import os
import shutil
import sys
import tempfile
import uuid as uuid_mod
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession, async_sessionmaker, create_async_engine,
)

from app.models import (
    CircuitBreaker, ExecutionRun, GitRemediation, GithubInstallation,
    Repository, SystemControl, User,
)
from app.services import ops_model as om
from app.services import ops_service, reconciliation_service

RESULTS = []


def record(name: str, ok: bool, evidence: str) -> None:
    RESULTS.append((name, ok, evidence))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  |  {evidence}")


def make_run(repo_id, state="EXECUTING", auth_id=None, proposal_id=None):
    return ExecutionRun(
        execution_authorization_id=auth_id,
        action_proposal_id=proposal_id,
        repository_id=repo_id,
        action_digest="d" * 64,
        contract_digest="c" * 64,
        run_state=state,
        execution_profile="STANDARD",
        resource_profile={},
    )


def make_remediation(repo_id, state, committed_sha, user_id, run_id,
                     auth_id, proposal_id, branch="cyvrix/remediation/cert"):
    """A remediation row attached to a REAL parent chain (all FKs real)."""
    return GitRemediation(
        execution_run_id=run_id,
        execution_authorization_id=auth_id,
        action_proposal_id=proposal_id,
        repository_id=repo_id,
        action_digest="d" * 64,
        remediation_contract={},
        remediation_contract_digest="x" * 64,
        contract_version="1",
        repo_owner="test-org",
        repo_name="vulnerable-node-app",
        installation_id=12345,
        base_commit_sha="b" * 40,
        source_branch="main",
        target_branch=branch,
        remediation_state=state,
        remediation_branch=branch,
        committed_sha=committed_sha,
        stage_ceiling="PR_ALLOWED",
        created_by_user_id=user_id,
    )


async def seed_chain(SF, repo_id, user_id):
    """Seed Scan→Finding→Recommendation→Proposal→Approval→Authorization→
    ExecutionRun so remediation rows satisfy every real FK."""
    from app.models import (
        ActionProposal, Approval, ExecutionAuthorization, ExecutionRun,
        Finding, Recommendation, Scan,
    )
    from datetime import datetime, timedelta, timezone as tz
    digest = "d" * 64
    async with SF() as s:
        scan = Scan(id=uuid_mod.uuid4(), repository_id=repo_id,
                    status="COMPLETED", trigger="manual", commit_sha="b" * 40)
        s.add(scan)
        await s.flush()
        finding = Finding(id=uuid_mod.uuid4(), scan_id=scan.id,
                          repository_id=repo_id, fingerprint=f"cert-{uuid_mod.uuid4().hex[:10]}",
                          scanner="dependency", source_type="DEPENDENCY",
                          vulnerability_id="GHSA-cert", package_name="lodash",
                          package_version="4.17.19", title="cert",
                          severity="HIGH", status="OPEN", evidence={})
        s.add(finding)
        await s.flush()
        rec = Recommendation(id=uuid_mod.uuid4(), finding_id=finding.id,
                             status="COMPLETED", trust_level="SUPPORTED",
                             title="cert", change="c", validation_state="VALIDATED")
        s.add(rec)
        await s.flush()
        proposal = ActionProposal(
            id=uuid_mod.uuid4(), finding_id=finding.id, recommendation_id=rec.id,
            repository_id=repo_id, created_by=user_id,
            action_type="DEPENDENCY_UPGRADE", status="APPROVED",
            base_commit_sha="b" * 40, target_branch="cyvrix/remediation/cert",
            files=["package.json"], operations=[], expected_diff="d",
            rationale="cert", risk_score=45, risk_level="MEDIUM",
            recommendation_trust="SUPPORTED", validation_state="VALIDATED",
            policy_version="3.1", policy_decision="REQUIRE_APPROVAL",
            policy_reason_code="MEDIUM_RISK_REQUIRES_APPROVAL",
            policy_matched_rule="POL-027", action_digest=digest,
            expires_at=datetime.now(tz.utc) + timedelta(hours=1))
        s.add(proposal)
        await s.flush()
        approval = Approval(
            id=uuid_mod.uuid4(), action_proposal_id=proposal.id,
            action_digest=digest, approver_user_id=user_id,
            approval_state="APPROVED", policy_version="3.1",
            policy_decision="REQUIRE_APPROVAL",
            approved_at=datetime.now(tz.utc),
            expires_at=datetime.now(tz.utc) + timedelta(hours=1))
        s.add(approval)
        await s.flush()
        auth = ExecutionAuthorization(
            id=uuid_mod.uuid4(), action_proposal_id=proposal.id,
            approval_id=approval.id, action_digest=digest,
            repository_id=repo_id, base_commit_sha="b" * 40,
            target_branch="cyvrix/remediation/cert", policy_version="3.1",
            policy_decision="REQUIRE_APPROVAL", authorization_state="AUTHORIZED",
            contract={}, contract_digest="c" * 64, contract_version="1",
            authorized_by_user_id=user_id)
        s.add(auth)
        await s.flush()
        run = ExecutionRun(
            id=uuid_mod.uuid4(), execution_authorization_id=auth.id,
            action_proposal_id=proposal.id, repository_id=repo_id,
            action_digest=digest, contract_digest="c" * 64,
            run_state="COMPLETED", execution_profile="STANDARD",
            resource_profile={})
        s.add(run)
        await s.commit()
        return run.id, auth.id, proposal.id


async def main() -> int:
    from app.config import get_settings
    settings = get_settings()
    assert "postgresql" in settings.database_url, "certification requires real PostgreSQL"
    engine = create_async_engine(settings.database_url, echo=False)
    SF = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    import time
    tag = int(time.time()) % 1_000_000  # unique per run (idempotent re-runs)

    async with SF() as s:
        user = User(id=uuid_mod.uuid4(), email=f"v37cert-{tag}@cyvrix.local",
                    github_id=90_000_000 + tag, role=om.Role.OPERATOR)
        s.add(user)
        await s.flush()
        inst = GithubInstallation(id=uuid_mod.uuid4(), user_id=user.id,
                                  installation_id=9_100_000 + tag,
                                  account_login="test-org", account_type="Organization")
        s.add(inst)
        await s.flush()
        # Reuse the mock-served repository row if a previous run created it
        # (uq_owner_name); the git transport needs this exact identity.
        repo = (await s.execute(select(Repository).where(
            Repository.owner == "test-org",
            Repository.name == "vulnerable-node-app"))).scalar_one_or_none()
        if repo is None:
            repo = Repository(id=uuid_mod.uuid4(), installation_id=inst.id,
                              github_repo_id=9_200_000 + tag, owner="test-org",
                              name="vulnerable-node-app", default_branch="main",
                              is_active=True)
            s.add(repo)
        await s.commit()
        repo_id, user_id = repo.id, user.id

    async def seed_state(value):
        async with SF() as s:
            row = (await s.execute(select(SystemControl).where(
                SystemControl.key == "operational_state"))).scalar_one()
            row.value = value
            await s.commit()

    # ── Phase 6: operational state matrix ────────────────────────────
    async with SF() as s:
        ok, reason = await ops_service.assert_execution_allowed(
            s, repository_id=repo_id, scope="EXECUTION")
        record("P6 NORMAL grants execution", ok, f"reason={reason}")
    for st, expected_rc in (("PAUSED", om.RC_SYSTEM_PAUSED),
                            ("DRAINING", om.RC_SYSTEM_DRAINING),
                            ("EMERGENCY_STOP", om.RC_EMERGENCY_STOP)):
        await seed_state(st)
        async with SF() as s:
            ok, reason = await ops_service.assert_execution_allowed(
                s, repository_id=repo_id, scope="EXECUTION")
            record(f"P6 {st} denies execution", (not ok and reason == expected_rc),
                   f"reason={reason}")
        await seed_state("NORMAL")

    # ── Phase 7: kill switch fail-closed (missing control row) ───────
    async with SF() as s:
        ks = (await s.execute(select(SystemControl).where(
            SystemControl.key == "execution_disabled"))).scalar_one()
        await s.delete(ks)
        await s.commit()
    async with SF() as s:
        ok, reason = await ops_service.assert_execution_allowed(
            s, repository_id=repo_id, scope="EXECUTION")
        record("P7 missing kill-switch row fail-closed",
               (not ok), f"reason={reason}")
    async with SF() as s:
        s.add(SystemControl(key="execution_disabled", value="false"))
        await s.commit()

    # ── Phase 10: leases — single owner, no cross-worker takeover ────
    sid = uuid_mod.uuid4()
    async with SF() as s:
        ok, fail, lease = await ops_service.acquire_lease(
            s, subject_type="GIT_REMEDIATION", subject_id=sid,
            repository_id=repo_id, owner_id="worker-A", ttl_seconds=120)
        await s.commit()  # the caller owns the transaction (service contract)
        record("P10 worker-A acquires lease", ok and lease.lease_state == "ACTIVE",
               f"owner={lease.lease_owner_id}")
    async with SF() as s:
        ok, fail, _ = await ops_service.acquire_lease(
            s, subject_type="GIT_REMEDIATION", subject_id=sid,
            repository_id=repo_id, owner_id="worker-B", ttl_seconds=120)
        record("P10 worker-B takeover denied",
               (not ok and fail == om.RC_LEASE_NOT_OWNED), f"reason={fail}")

    # ── Phase 12: reconciliation with REAL git ls-remote ─────────────
    # The mock GitHub (provider boundary) serves test-org/vulnerable-node-app.
    base_url = os.environ.get("GITHUB_REMOTE_BASE", "http://localhost:8100")
    import subprocess
    remote = f"{base_url}/test-org/vulnerable-node-app.git"
    out = subprocess.run(["git", "ls-remote", remote, "refs/heads/main"],
                         capture_output=True, text=True, timeout=30)
    real_sha = out.stdout.split()[0] if out.returncode == 0 and out.stdout else None
    record("P12 real git ls-remote reachable", bool(real_sha),
           f"main={str(real_sha)[:12]}...")

    os.environ["GITHUB_REMOTE_BASE"] = base_url
    # The local mock git transport speaks http; production default allows
    # https only (SSRF defense). This is the same test-transport exception
    # the repo's race suites use (tests/test_git_remediation_races.py).
    from app.services import git_ops
    git_ops.GIT_ALLOWED_PROTOCOLS = "https:http"

    # Push a dedicated branch to the REAL remote (git receive-pack via the
    # provider boundary) from a TEMP CLONE — exactly as a remediation
    # worker would. Unique-per-run name avoids the live-branch index.
    br_pushed = f"cert-{tag}-pushed"
    br_ambig = f"cert-{tag}-ambig"
    tmp_ws = tempfile.mkdtemp(prefix="cyvrix-cert-push-")
    clone = os.path.join(tmp_ws, "clone")
    c1 = subprocess.run(["git", "clone", "--bare", remote, clone],
                        capture_output=True, text=True, timeout=120)
    assert c1.returncode == 0, f"clone failed: {c1.stderr[:200]}"
    p = subprocess.run(
        ["git", "push", remote, f"refs/heads/main:refs/heads/{br_pushed}",
         f"refs/heads/main:refs/heads/{br_ambig}"],
        cwd=clone, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, f"push failed: {p.stderr[:200]}"
    shutil.rmtree(tmp_ws, ignore_errors=True)
    # Read back the authoritative sha of the pushed branch (never assume).
    out2 = subprocess.run(["git", "ls-remote", remote, f"refs/heads/{br_pushed}"],
                          capture_output=True, text=True, timeout=30)
    pushed_sha = out2.stdout.split()[0] if out2.returncode == 0 and out2.stdout else None
    assert pushed_sha, "pushed branch sha could not be read back"

    run_id, auth_id, proposal_id = await seed_chain(SF, repo_id, user_id)
    # Branch br_pushed exists on the remote with sha == pushed_sha (read
    # back from the remote): a remediation stuck in PUSHING whose
    # committed sha matches the authoritative remote -> PUSHED.
    rem = make_remediation(repo_id, "PUSHING", pushed_sha, user_id,
                           run_id, auth_id, proposal_id, branch=br_pushed)
    async with SF() as s:
        s.add(rem)
        await s.commit()
    async with SF() as s:
        rec = await reconciliation_service.run_reconciliation(s, trigger="CERT")
        rem_db = (await s.execute(select(GitRemediation).where(
            GitRemediation.id == rem.id))).scalar_one()
    record("P12 reconciliation PUSHED (sha matches remote)",
           rec.status == "COMPLETED" and rem_db.remediation_state == "PUSHED"
           and rem_db.pushed_sha == pushed_sha,
           f"state={rem_db.remediation_state} status={rec.status}")

    run_id2, auth_id2, proposal_id2 = await seed_chain(SF, repo_id, user_id)
    # br_ambig exists on the remote but the local committed sha differs:
    # ambiguous outcome -> INCONSISTENT, never guessed.
    rem2 = make_remediation(repo_id, "PUSHING", "f" * 40, user_id,
                            run_id2, auth_id2, proposal_id2, branch=br_ambig)
    async with SF() as s:
        s.add(rem2)
        await s.commit()
    async with SF() as s:
        await reconciliation_service.run_reconciliation(s, trigger="CERT")
        rem2_db = (await s.execute(select(GitRemediation).where(
            GitRemediation.id == rem2.id))).scalar_one()
    record("P12 ambiguous remote state never guessed (INCONSISTENT)",
           rem2_db.remediation_state == "INCONSISTENT"
           and rem2_db.fail_reason_code == "GITHUB_STATE_MISMATCH",
           f"state={rem2_db.remediation_state} rc={rem2_db.fail_reason_code}")

    # Real repo, absent branch -> ls-remote returns no ref -> NOT_PUSHED
    # (an absent REPO would be UNKNOWN -> INCONSISTENT: fail closed,
    # because 'repo missing' is ambiguous, not proof of absence).
    run_id3, auth_id3, proposal_id3 = await seed_chain(SF, repo_id, user_id)
    rem3 = make_remediation(repo_id, "PUSHING", "a" * 40, user_id,
                            run_id3, auth_id3, proposal_id3,
                            branch=f"cert-{tag}-absent")
    async with SF() as s:
        s.add(rem3)
        await s.commit()
    async with SF() as s:
        await reconciliation_service.run_reconciliation(s, trigger="CERT")
        rem3_db = (await s.execute(select(GitRemediation).where(
            GitRemediation.id == rem3.id))).scalar_one()
    record("P12 absent remote branch -> NOT_PUSHED (FAILED)",
           rem3_db.remediation_state == "FAILED"
           and rem3_db.fail_reason_code == "PUSH_NOT_PERFORMED",
           f"state={rem3_db.remediation_state} rc={rem3_db.fail_reason_code}")

    # ── Phase 16: emergency stop blocks execution + credential gate ──
    await seed_state("EMERGENCY_STOP")
    async with SF() as s:
        ok, reason = await ops_service.assert_execution_allowed(
            s, repository_id=repo_id, scope="EXECUTION")
        record("P16 emergency stop denies execution",
               (not ok and reason == om.RC_EMERGENCY_STOP), f"reason={reason}")
        state, fail = await ops_service.read_operational_state(s)
        record("P16 credential issuance blocked (non-NORMAL)",
               (not om.credential_issuance_allowed(state)), f"state={state}")

    # ── Phase 17: one-way door + reconciled resume ───────────────────
    async with SF() as s:
        ok, fail = await ops_service.set_operational_state(
            s, target="NORMAL", actor=None)
        record("P17 ES->NORMAL refused (one-way door)",
               (not ok and fail == om.RC_OPS_TRANSITION_INVALID), f"reason={fail}")
    async with SF() as s:
        ok, fail = await ops_service.set_operational_state(
            s, target="PAUSED", actor=None)
        record("P17 ES->PAUSED (reconciled resume path)", ok, f"reason={fail}")
    async with SF() as s:
        ok, fail = await ops_service.set_operational_state(
            s, target="NORMAL", actor=None)
        record("P17 PAUSED->NORMAL (clean state)", ok, f"reason={fail}")

    # ── Phase 18: orphan workspace cleanup protects live runs ────────
    ws_root = tempfile.mkdtemp(prefix="cyvrix-cert-ws-")
    run_id4, auth_id4, proposal_id4 = await seed_chain(SF, repo_id, user_id)
    run_id5, auth_id5, proposal_id5 = await seed_chain(SF, repo_id, user_id)
    live_run = make_run(repo_id, state="EXECUTING", auth_id=auth_id4,
                        proposal_id=proposal_id4)
    # dead_run IS chain #5's own run (seed_chain inserts it COMPLETED) —
    # one terminal run per authorization (uq_execution_runs_done).
    async with SF() as s:
        s.add(live_run)
        await s.commit()
    live_ws = os.path.join(ws_root, f"ws-{live_run.id.hex}")
    dead_ws = os.path.join(ws_root, f"ws-{run_id5.hex}")
    stranger = os.path.join(ws_root, "not-cyvrix-dir")
    for d in (live_ws, dead_ws, stranger):
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "f.txt"), "w") as fh:
            fh.write("x")
    os.environ["CYVRIX_SANDBOX_WORKSPACE_ROOT"] = ws_root
    async with SF() as s:
        removed = await reconciliation_service._cleanup_orphan_workspaces(
            s, None, [], datetime.now(timezone.utc))
    ok = (removed == 1 and not os.path.exists(dead_ws)
          and os.path.exists(live_ws) and os.path.exists(stranger))
    record("P18 orphan cleanup: only provably-terminal workspaces removed",
           ok, f"removed={removed} live_kept={os.path.exists(live_ws)} "
               f"stranger_kept={os.path.exists(stranger)}")
    shutil.rmtree(ws_root, ignore_errors=True)

    await engine.dispose()
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n== V3.7 real-stack scenario: {len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed ==")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
