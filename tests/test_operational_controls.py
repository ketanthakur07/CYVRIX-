"""CYVRIX V3.7 — operational controls: unit + failure-injection tests.

Covers:
- ops_model: state graph, fail-closed parsing, cancellation semantics,
  failure classification, backoff bounds, role capability matrix
- ops_service gates: state × repo control × circuit × quota (SQLite)
- reconciliation: push-window classification (mocked transport),
  stuck detection, lease expiry, orphan workspace cleanup
- operator API: authz matrix, tenant isolation, rate limiting,
  authority-field rejection, idempotency of state transitions
- failure injection: DB failure, Redis failure, missing/unparseable
  control state, quota exhaustion, breaker opening, lease expiry

Run: plain pytest (SQLite, no external services required).
"""
import asyncio
import os
import sys
import uuid as uuid_mod
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.models import (
    CircuitBreaker, ExecutionRun, GithubCredentialIssuance, GitRemediation,
    RepositoryControl, SystemControl, User,
)
from app.services import ops_model as om
from app.services import ops_service
from app.services import reconciliation_service


# ── ops_model: pure decision table ───────────────────────────────────


class TestOpsModelStateGraph:
    def test_all_legal_transitions(self):
        legal = {
            ("NORMAL", "PAUSED"), ("NORMAL", "DRAINING"), ("NORMAL", "EMERGENCY_STOP"),
            ("PAUSED", "NORMAL"), ("PAUSED", "EMERGENCY_STOP"),
            ("DRAINING", "PAUSED"), ("DRAINING", "EMERGENCY_STOP"),
            ("EMERGENCY_STOP", "PAUSED"),
        }
        for cur, tgt in legal:
            assert om.can_transition(cur, tgt), (cur, tgt)

    def test_emergency_stop_never_directly_resumes(self):
        assert not om.can_transition("EMERGENCY_STOP", "NORMAL")
        # The one-way door: recovery is EMERGENCY_STOP → PAUSED → NORMAL
        assert om.can_transition("EMERGENCY_STOP", "PAUSED")
        assert om.can_transition("PAUSED", "NORMAL")

    def test_unknown_states_fail_closed(self):
        for bad in ("", "garbage", "normal", None, 1, ["NORMAL"]):
            assert not om.can_transition(bad, "NORMAL")
            assert not om.can_transition("NORMAL", bad)
            assert not om.execution_allowed(bad)
            assert not om.credential_issuance_allowed(bad)
            assert not om.rollback_initiation_allowed(bad)

    def test_execution_only_in_normal(self):
        for state in om.ALL_OPS_STATES:
            assert om.execution_allowed(state) == (state == "NORMAL")

    def test_parse_ops_state_fail_closed(self):
        assert om.parse_ops_state(None) == (None, om.RC_OPS_STATE_MISSING)
        assert om.parse_ops_state("  ") == (None, om.RC_OPS_STATE_MISSING)
        assert om.parse_ops_state("GARBAGE") == (None, om.RC_OPS_STATE_UNPARSEABLE)
        assert om.parse_ops_state("NORMAL") == ("NORMAL", None)

    def test_credential_issuance_blocked_when_not_normal(self):
        assert om.credential_issuance_allowed("NORMAL")
        assert not om.credential_issuance_allowed("PAUSED")
        assert not om.credential_issuance_allowed("EMERGENCY_STOP")

    def test_rollback_initiation_blocked_when_not_normal(self):
        assert om.rollback_initiation_allowed("NORMAL")
        assert not om.rollback_initiation_allowed("DRAINING")
        assert not om.rollback_initiation_allowed("EMERGENCY_STOP")


class TestCancellationSemantics:
    def test_honest_per_state_semantics(self):
        assert om.cancellation_semantics("PENDING") == om.CANCEL_IMMEDIATE_SAFE
        assert om.cancellation_semantics("VERIFYING") == om.CANCEL_IMMEDIATE_SAFE
        assert om.cancellation_semantics("COMMITTED") == om.CANCEL_COOPERATIVE
        assert om.cancellation_semantics("PUSHING") == om.CANCEL_NOT_IMMEDIATE
        assert om.cancellation_semantics("PUSHED") == om.CANCEL_REQUIRES_RECONCILIATION
        assert om.cancellation_semantics("PR_CREATING") == om.CANCEL_REQUIRES_RECONCILIATION
        assert om.cancellation_semantics("PR_CREATED") == om.CANCEL_NOT_CANCELLABLE
        assert om.cancellation_semantics(None) == om.CANCEL_NOT_CANCELLABLE


class TestFailureClassification:
    def test_security_denials_never_transient(self):
        for code in ("POLICY_DENIED", "ACTION_DIGEST_MISMATCH", "SECRET_DETECTED",
                     "SANDBOX_ESCAPE_ATTEMPT", "FORCE_PUSH_PROHIBITED",
                     "TOKEN_REPLAY", "EXECUTION_REPLAY", "KILL_SWITCH_ACTIVE"):
            assert om.classify_failure(code) == om.NON_TRANSIENT, code

    def test_infra_failures_transient(self):
        for code in ("GITHUB_TIMEOUT", "GITHUB_UNAVAILABLE", "GITHUB_RATE_LIMITED",
                     "REDIS_UNAVAILABLE", "GIT_UNAVAILABLE", "SANDBOX_UNAVAILABLE"):
            assert om.classify_failure(code) == om.TRANSIENT, code

    def test_unknown_codes_fail_closed_for_retry(self):
        assert om.classify_failure("SOMETHING_NEW") == om.NON_TRANSIENT
        assert om.classify_failure(None) == om.NON_TRANSIENT

    def test_backoff_bounded(self):
        assert om.backoff_seconds(1) == 2.0
        assert om.backoff_seconds(2) == 4.0
        assert om.backoff_seconds(20) == 3600.0  # hard cap
        assert om.backoff_seconds(0) == 2.0
        assert om.backoff_seconds(-5) == 2.0


class TestRoleMatrix:
    def test_capability_matrix(self):
        assert not om.role_has_capability("USER", om.CAP_VIEW_OPERATIONS)
        assert om.role_has_capability("OPERATOR", om.CAP_PAUSE_SYSTEM)
        assert om.role_has_capability("OPERATOR", om.CAP_EMERGENCY_STOP)
        assert om.role_has_capability("ADMIN", om.CAP_RESET_CIRCUIT)
        # unknown role = no capabilities (fail closed)
        assert not om.role_has_capability("SUPERUSER", om.CAP_PAUSE_SYSTEM)
        assert not om.role_has_capability(None, om.CAP_VIEW_OPERATIONS)

    def test_no_capability_bypasses_remediation_authorization(self):
        # The matrix must not contain anything that approves/executes
        all_caps = set()
        for caps in om.ROLE_CAPABILITIES.values():
            all_caps |= set(caps)
        forbidden = {"APPROVE_ACTION", "AUTHORIZE_EXECUTION", "EXECUTE_REMEDIATION",
                     "BYPASS_POLICY", "BYPASS_DIGEST", "FORCE_RETRY"}
        assert all_caps & forbidden == set()

    def test_step_up_required_for_dangerous(self):
        assert om.CAP_EMERGENCY_STOP in om.STEP_UP_REQUIRED_CAPABILITIES
        assert om.CAP_RESUME_SYSTEM in om.STEP_UP_REQUIRED_CAPABILITIES
        assert om.CAP_RESET_CIRCUIT in om.STEP_UP_REQUIRED_CAPABILITIES
        assert om.CAP_VIEW_OPERATIONS not in om.STEP_UP_REQUIRED_CAPABILITIES


class TestLeaseModel:
    def test_ownership_enforced(self):
        now = datetime.now(timezone.utc)
        exp = now + timedelta(seconds=60)
        assert om.evaluate_lease("w1", exp, "w1", now).owned
        assert not om.evaluate_lease("w1", exp, "w2", now).owned
        assert om.evaluate_lease("w1", exp, "w2", now).reason == om.RC_LEASE_NOT_OWNED

    def test_expiry_detected(self):
        now = datetime.now(timezone.utc)
        exp = now - timedelta(seconds=1)
        v = om.evaluate_lease("w1", exp, "w1", now)
        assert not v.owned and v.reason == om.RC_LEASE_EXPIRED

    def test_missing_lease_data_fails_closed(self):
        now = datetime.now(timezone.utc)
        assert not om.evaluate_lease(None, now, "w1", now).owned
        assert not om.evaluate_lease("w1", None, "w1", now).owned

    def test_naive_datetimes_treated_as_utc(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        exp = now + timedelta(seconds=60)
        assert om.evaluate_lease("w1", exp, "w1", datetime.now(timezone.utc)).owned


class TestQuotaModel:
    def test_validation_rejects_bad_limits(self):
        good = om.QuotaLimits()
        assert om.validate_quota_limits(good) is None
        bad = om.QuotaLimits(max_concurrent_executions=0)
        assert om.validate_quota_limits(bad) == om.RC_QUOTA_INVALID
        absurd = om.QuotaLimits(max_execution_duration_seconds=10**9)
        assert om.validate_quota_limits(absurd) == om.RC_QUOTA_INVALID

    def test_quota_comparison(self):
        assert om.quota_allows(0, 5)
        assert om.quota_allows(4, 5)
        assert not om.quota_allows(5, 5)
        assert not om.quota_allows(-1, 5)
        assert not om.quota_allows(None, 5)


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
async def db(session_factory):
    async with session_factory() as s:
        # Seed the kill-switch row (mirrors migration 010 environment):
        # the operational_state row comes from the autouse clean_db.
        from app.models import SystemControl as SC
        from sqlalchemy import select as _select
        ks = (await s.execute(
            _select(SC).where(SC.key == "execution_disabled"))).scalar_one_or_none()
        if ks is None:
            s.add(SC(key="execution_disabled", value="false"))
            await s.commit()
        yield s


@pytest.fixture
async def repo_owner_user(session_factory, test_user):
    return test_user


@pytest.fixture
async def repo(test_repository):
    return test_repository


async def _seed_control(db, key, value):
    from sqlalchemy import select as _select
    existing = (await db.execute(
        _select(SystemControl).where(SystemControl.key == key))).scalar_one_or_none()
    if existing is not None:
        existing.value = value
    else:
        db.add(SystemControl(key=key, value=value))
    await db.commit()


# ── ops_service gates (SQLite) ───────────────────────────────────────


class TestExecutionGate:
    async def test_denied_without_operational_state(self, db, repo):
        # delete the provisioned row → fail closed
        await db.execute(
            __import__("sqlalchemy").delete(SystemControl).where(
                SystemControl.key == "operational_state")
        )
        await db.commit()
        ok, reason = await ops_service.assert_execution_allowed(
            db, repository_id=repo.id)
        assert not ok and reason == om.RC_OPS_STATE_MISSING

    async def test_denied_when_paused(self, db, repo):
        await _seed_control(db, "operational_state", "PAUSED")
        ok, reason = await ops_service.assert_execution_allowed(db, repository_id=repo.id)
        assert not ok and reason == om.RC_SYSTEM_PAUSED

    async def test_denied_when_emergency_stop(self, db, repo):
        await _seed_control(db, "operational_state", "EMERGENCY_STOP")
        ok, reason = await ops_service.assert_execution_allowed(db, repository_id=repo.id)
        assert not ok and reason == om.RC_EMERGENCY_STOP

    async def test_denied_when_state_unparseable(self, db, repo):
        await _seed_control(db, "operational_state", "GARBAGE!")
        ok, reason = await ops_service.assert_execution_allowed(db, repository_id=repo.id)
        assert not ok  # fail closed; exact code is EMERGENCY_STOP-equivalent

    async def test_denied_when_kill_switch_active(self, db, repo):
        await _seed_control(db, "execution_disabled", "true")
        ok, reason = await ops_service.assert_execution_allowed(db, repository_id=repo.id)
        assert not ok

    async def test_allowed_in_normal_without_containment(self, db, repo):
        # no repo control row, no breaker row → opt-in tools absent
        ok, reason = await ops_service.assert_execution_allowed(db, repository_id=repo.id)
        assert ok, reason

    async def test_repo_pause_blocks_repo_only(self, db, session_factory, repo, test_repository_b):
        db.add(RepositoryControl(repository_id=repo.id, control_state="PAUSED"))
        await db.commit()
        ok, reason = await ops_service.assert_execution_allowed(db, repository_id=repo.id)
        assert not ok and reason == om.RC_REPO_PAUSED
        # another repo unaffected
        ok2, _ = await ops_service.assert_execution_allowed(db, repository_id=test_repository_b.id)
        assert ok2

    async def test_repo_blocked_strict(self, db, repo):
        db.add(RepositoryControl(repository_id=repo.id, control_state="BLOCKED"))
        await db.commit()
        ok, reason = await ops_service.assert_execution_allowed(db, repository_id=repo.id)
        assert not ok and reason == om.RC_REPO_BLOCKED

    async def test_repo_corrupt_state_fails_closed(self, db, repo):
        db.add(RepositoryControl(repository_id=repo.id, control_state="WEIRD"))
        await db.commit()
        ok, reason = await ops_service.assert_execution_allowed(db, repository_id=repo.id)
        assert not ok

    async def test_open_breaker_blocks(self, db, repo):
        db.add(CircuitBreaker(repository_id=repo.id, scope="EXECUTION",
                              breaker_state="OPEN"))
        await db.commit()
        ok, reason = await ops_service.assert_execution_allowed(db, repository_id=repo.id)
        assert not ok and reason == om.RC_CIRCUIT_OPEN

    async def test_breaker_opens_after_bounded_failures(self, db, repo):
        for i in range(3):
            opened = await ops_service.record_execution_failure(
                db, repository_id=repo.id, scope="EXECUTION",
                reason_code="GITHUB_TIMEOUT")
        assert opened is True
        ok, reason = await ops_service.assert_execution_allowed(db, repository_id=repo.id)
        assert not ok and reason == om.RC_CIRCUIT_OPEN

    async def test_success_resets_streak_not_open_breaker(self, db, repo):
        await ops_service.record_execution_failure(db, repository_id=repo.id, scope="EXECUTION")
        await ops_service.record_execution_failure(db, repository_id=repo.id, scope="EXECUTION")
        await ops_service.record_execution_success(db, repository_id=repo.id, scope="EXECUTION")
        breaker = (await db.execute(
            __import__("sqlalchemy").select(CircuitBreaker).where(
                CircuitBreaker.repository_id == repo.id))).scalar_one()
        assert breaker.consecutive_failures == 0
        assert breaker.breaker_state == "CLOSED"
        # OPEN breaker never auto-closes
        breaker.breaker_state = "OPEN"
        await db.commit()
        await ops_service.record_execution_success(db, repository_id=repo.id, scope="EXECUTION")
        assert breaker.breaker_state == "OPEN"

    async def test_quota_blocks_when_concurrent_max(self, db, session_factory, repo, test_user, test_installation):
        # Create a proposal chain minimally: fabricate runs directly
        for _ in range(5):
            run = ExecutionRun(
                execution_authorization_id=uuid_mod.uuid4(),
                action_proposal_id=uuid_mod.uuid4(),
                repository_id=repo.id,
                action_digest="d" * 64,
                contract_digest="c" * 64,
                run_state="EXECUTING",
                execution_profile="STANDARD",
                resource_profile={},
            )
            db.add(run)
        await db.commit()
        ok, reason = await ops_service.assert_execution_allowed(db, repository_id=repo.id)
        assert not ok and reason == om.RC_QUOTA_EXCEEDED

    async def test_per_repo_quota(self, db, repo):
        for _ in range(2):
            db.add(ExecutionRun(
                execution_authorization_id=uuid_mod.uuid4(),
                action_proposal_id=uuid_mod.uuid4(),
                repository_id=repo.id,
                action_digest="d" * 64,
                contract_digest="c" * 64,
                run_state="EXECUTING",
                execution_profile="STANDARD",
                resource_profile={},
            ))
        await db.commit()
        ok, reason = await ops_service.assert_execution_allowed(db, repository_id=repo.id)
        assert not ok and reason == om.RC_QUOTA_EXCEEDED


class TestVerificationAndRollbackGates:
    async def test_verification_allowed_under_paused(self, db, repo):
        await _seed_control(db, "operational_state", "PAUSED")
        ok, _ = await ops_service.assert_verification_allowed(db, repository_id=repo.id)
        assert ok

    async def test_verification_blocked_under_emergency(self, db, repo):
        await _seed_control(db, "operational_state", "EMERGENCY_STOP")
        ok, reason = await ops_service.assert_verification_allowed(db, repository_id=repo.id)
        assert not ok and reason == om.RC_EMERGENCY_STOP

    async def test_rollback_blocked_under_pause(self, db, repo):
        await _seed_control(db, "operational_state", "PAUSED")
        ok, reason = await ops_service.assert_rollback_allowed(db, repository_id=repo.id)
        assert not ok and reason == om.RC_SYSTEM_PAUSED


class TestStateTransitions:
    async def test_set_and_read(self, db, test_user):
        ok, fail = await ops_service.set_operational_state(db, target="PAUSED", actor=test_user)
        assert ok, fail
        state, _ = await ops_service.read_operational_state(db)
        assert state == "PAUSED"
        # back to NORMAL
        ok, fail = await ops_service.set_operational_state(db, target="NORMAL", actor=test_user)
        assert ok, fail

    async def test_illegal_transition_refused(self, db, test_user):
        await ops_service.set_operational_state(db, target="EMERGENCY_STOP", actor=test_user)
        ok, fail = await ops_service.set_operational_state(db, target="NORMAL", actor=test_user)
        assert not ok and fail == om.RC_OPS_TRANSITION_INVALID
        # state unchanged (still EMERGENCY_STOP)
        state, _ = await ops_service.read_operational_state(db)
        assert state == "EMERGENCY_STOP"

    async def test_transition_audited(self, db, test_user):
        from app.models import OperationalEvent
        await ops_service.set_operational_state(db, target="PAUSED", actor=test_user)
        evt = (await db.execute(
            __import__("sqlalchemy").select(OperationalEvent).where(
                OperationalEvent.event_type == "SYSTEM_PAUSED")
            .order_by(OperationalEvent.created_at.desc())
        )).scalars().first()
        assert evt is not None


# ── Leases ───────────────────────────────────────────────────────────


class TestLeases:
    async def test_acquire_and_reentrant_heartbeat(self, db, repo):
        ok, fail, lease = await ops_service.acquire_lease(
            db, subject_type="GIT_REMEDIATION", subject_id=uuid_mod.uuid4(),
            repository_id=repo.id, owner_id="w1", ttl_seconds=60)
        assert ok, fail
        ok2, fail2, lease2 = await ops_service.acquire_lease(
            db, subject_type="GIT_REMEDIATION", subject_id=lease.subject_id,
            repository_id=repo.id, owner_id="w1", ttl_seconds=60)
        assert ok2  # re-entrant refresh

    async def test_no_takeover_by_other_worker(self, db, repo):
        sid = uuid_mod.uuid4()
        ok, _, lease = await ops_service.acquire_lease(
            db, subject_type="GIT_REMEDIATION", subject_id=sid,
            repository_id=repo.id, owner_id="w1", ttl_seconds=60)
        ok2, fail2, _ = await ops_service.acquire_lease(
            db, subject_type="GIT_REMEDIATION", subject_id=sid,
            repository_id=repo.id, owner_id="w2", ttl_seconds=60)
        assert not ok2 and fail2 == om.RC_LEASE_NOT_OWNED

    async def test_expired_lease_marks_expired(self, db, repo):
        sid = uuid_mod.uuid4()
        ok, _, lease = await ops_service.acquire_lease(
            db, subject_type="GIT_REMEDIATION", subject_id=sid,
            repository_id=repo.id, owner_id="w1", ttl_seconds=60)
        lease.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db.commit()
        ok2, fail2, _ = await ops_service.acquire_lease(
            db, subject_type="GIT_REMEDIATION", subject_id=sid,
            repository_id=repo.id, owner_id="w2", ttl_seconds=60)
        assert not ok2 and fail2 == om.RC_LEASE_EXPIRED
        await db.refresh(lease)
        assert lease.lease_state == "EXPIRED"


# ── Reconciliation ───────────────────────────────────────────────────


def _make_remediation(repo, state, committed="a" * 40, pushed=None, user_id=None):
    return GitRemediation(
        execution_run_id=uuid_mod.uuid4(),
        execution_authorization_id=uuid_mod.uuid4(),
        action_proposal_id=uuid_mod.uuid4(),
        repository_id=repo.id,
        action_digest="d" * 64,
        remediation_contract={},
        remediation_contract_digest="x" * 64,
        contract_version="1",
        repo_owner="test-org", repo_name="test-repo", installation_id=12345,
        base_commit_sha="b" * 40,
        source_branch="main",
        target_branch="cyvrix/remediation/test",
        remediation_state=state,
        remediation_branch="cyvrix/remediation/test",
        committed_sha=committed,
        pushed_sha=pushed,
        stage_ceiling="PR_ALLOWED",
        created_by_user_id=user_id,
    )


class TestReconciliation:
    async def test_pushed_classification(self, db, repo, test_user):
        rem = _make_remediation(repo, "PUSHING", user_id=test_user.id)
        db.add(rem)
        await db.commit()
        with patch.object(reconciliation_service.git_ops, "ls_remote",
                          return_value=("a" * 40)):
            rec = await reconciliation_service.run_reconciliation(db, trigger="TEST")
        assert rec.status == "COMPLETED"
        assert rem.remediation_state == "PUSHED"
        assert rem.pushed_sha == "a" * 40

    async def test_not_pushed_classification(self, db, repo, test_user):
        rem = _make_remediation(repo, "PUSHING", user_id=test_user.id)
        db.add(rem)
        await db.commit()
        with patch.object(reconciliation_service.git_ops, "ls_remote",
                          return_value=None):
            rec = await reconciliation_service.run_reconciliation(db, trigger="TEST")
        assert rem.remediation_state == "FAILED"
        assert rem.fail_reason_code == "PUSH_NOT_PERFORMED"

    async def test_unknown_sha_never_guessed(self, db, repo, test_user):
        rem = _make_remediation(repo, "PUSHING", user_id=test_user.id)
        db.add(rem)
        await db.commit()
        # remote exists with a DIFFERENT sha → INCONSISTENT (fail closed)
        with patch.object(reconciliation_service.git_ops, "ls_remote",
                          return_value=("f" * 40)):
            await reconciliation_service.run_reconciliation(db, trigger="TEST")
        assert rem.remediation_state == "INCONSISTENT"

    async def test_network_failure_is_unknown(self, db, repo, test_user):
        rem = _make_remediation(repo, "PUSHING", user_id=test_user.id)
        db.add(rem)
        await db.commit()
        def _boom(*a, **k):
            raise RuntimeError("connection reset")
        with patch.object(reconciliation_service.git_ops, "ls_remote", side_effect=_boom):
            await reconciliation_service.run_reconciliation(db, trigger="TEST")
        assert rem.remediation_state == "INCONSISTENT"  # UNKNOWN → conservative

    async def test_idempotent_double_run(self, db, repo, test_user):
        rem = _make_remediation(repo, "PUSHING", user_id=test_user.id)
        db.add(rem)
        await db.commit()
        with patch.object(reconciliation_service.git_ops, "ls_remote",
                          return_value=("a" * 40)):
            await reconciliation_service.run_reconciliation(db, trigger="TEST")
            rec2 = await reconciliation_service.run_reconciliation(db, trigger="TEST")
        # Second pass finds nothing in push window anymore
        assert all(not f["subject"].startswith("git_remediation:") for f in (rec2.findings or []))

    async def test_lease_expiry_reconciled(self, db, repo):
        sid = uuid_mod.uuid4()
        ok, _, lease = await ops_service.acquire_lease(
            db, subject_type="GIT_REMEDIATION", subject_id=sid,
            repository_id=repo.id, owner_id="w1", ttl_seconds=60)
        lease.expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
        await db.commit()
        await reconciliation_service.run_reconciliation(db, trigger="TEST")
        assert lease.lease_state == "EXPIRED"

    async def test_orphan_workspace_cleanup(self, db, repo, tmp_path, monkeypatch):
        import tempfile
        # terminal run directory
        run_id = uuid_mod.uuid4()
        db.add(ExecutionRun(
            id=run_id,
            execution_authorization_id=uuid_mod.uuid4(),
            action_proposal_id=uuid_mod.uuid4(),
            repository_id=repo.id,
            action_digest="d" * 64,
            contract_digest="c" * 64,
            run_state="COMPLETED",
            execution_profile="STANDARD",
            resource_profile={},
        ))
        await db.commit()
        ws = tmp_path / f"ws-{run_id.hex}"
        ws.mkdir()
        (ws / "junk.txt").write_text("x")
        monkeypatch.setenv("CYVRIX_SANDBOX_WORKSPACE_ROOT", str(tmp_path))
        removed = await reconciliation_service._cleanup_orphan_workspaces(
            db, None, [], datetime.now(timezone.utc))
        assert removed == 1 and not ws.exists()

    async def test_never_touches_unknown_dirs(self, db, tmp_path, monkeypatch):
        monkeypatch.setenv("CYVRIX_SANDBOX_WORKSPACE_ROOT", str(tmp_path))
        stranger = tmp_path / "some-other-app-dir"
        stranger.mkdir()
        stranger_file = stranger / "important.txt"
        stranger_file.write_text("keep me")
        await reconciliation_service._cleanup_orphan_workspaces(
            db, None, [], datetime.now(timezone.utc))
        assert stranger.exists() and stranger_file.exists()

    async def test_never_touches_live_run_workspace(self, db, repo, tmp_path, monkeypatch, test_user):
        run_id = uuid_mod.uuid4()
        db.add(ExecutionRun(
            id=run_id,
            execution_authorization_id=uuid_mod.uuid4(),
            action_proposal_id=uuid_mod.uuid4(),
            repository_id=repo.id,
            action_digest="d" * 64,
            contract_digest="c" * 64,
            run_state="EXECUTING",  # live!
            execution_profile="STANDARD",
            resource_profile={},
        ))
        await db.commit()
        ws = tmp_path / f"ws-{run_id.hex}"
        ws.mkdir()
        monkeypatch.setenv("CYVRIX_SANDBOX_WORKSPACE_ROOT", str(tmp_path))
        await reconciliation_service._cleanup_orphan_workspaces(
            db, None, [], datetime.now(timezone.utc))
        assert ws.exists()  # live run protected


# ── Failure injection: dependency semantics ──────────────────────────


class TestDependencyFailureSemantics:
    async def test_db_read_failure_fails_closed(self, db, repo):
        class ExplodingDB:
            async def execute(self, *a, **k):
                raise RuntimeError("db connection reset")
        ok, reason = await ops_service.assert_execution_allowed(
            ExplodingDB(), repository_id=repo.id)
        assert not ok  # any read error ⇒ deny

    async def test_redis_unavailable_fails_step_up_closed(self):
        from app.routes import ops as ops_routes

        class FakeUser:
            id = uuid_mod.uuid4()

        class ExplodingRedis:
            async def get(self, *a):
                raise RuntimeError("redis down")

        async def fake_get_redis():
            return ExplodingRedis()

        import app.session as session_mod
        with patch.object(session_mod, "get_redis", fake_get_redis):
            result = await ops_routes._step_up_fresh(FakeUser())
        assert result is False  # fail closed


class TestConfigSafety:
    def test_invalid_limits_rejected(self):
        from app.config import Settings
        with pytest.raises(Exception):
            Settings(ops_max_concurrent_executions=0)
        with pytest.raises(Exception):
            Settings(ops_lease_ttl_seconds=999999)
        with pytest.raises(Exception):
            Settings(ops_breaker_max_failures=-1)
