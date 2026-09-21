"""CYVRIX V3.6 — Verification + rollback integration tests.

Real git transport (in-process mock provider — the same receive-pack /
branch / PR endpoints used by the e2e stack), real pipeline code, fake
container only (deterministic in-process executor).

Scenarios (Phase 39):
1. successful remediation → verification PASS (checks + evidence rows)
2. failed verification (injected) → FAIL verdict, no rollback needed flag
3. successful rollback (revert branch + revert commit + push + readback)
4. rollback conflict: remote remediation branch moved → CONFLICT
5. duplicate rollback attempt → replay refusal (idempotency key)
6. verification of a remediation whose PR was mutated → GitHub readback FAIL
"""
import json
import os
import subprocess
import sys
import tempfile
from uuid import UUID, uuid4

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from sqlalchemy import select

from app.main import app
from app.models import (
    ActionProposal, ExecutionRun, GitRemediation, SystemControl,
    VerificationCheck, VerificationRun, RollbackRun,
)
from app.routes.approvals import check_approval_rate_limit
from app.routes.execution_authorization import check_execution_auth_rate_limit
from app.routes.git_remediation import check_remediation_rate_limit
from app.routes.verification_rollback import (
    check_rollback_rate_limit, check_verification_rate_limit,
)

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(__file__))
from test_git_remediation import (  # noqa: E402
    EXECUTOR_TOKEN, _auth_headers, _inproc_mock_remote, _remote_main_sha,
    _verified_run,
)
from test_execution_runs_api import kill_switch_off, step_up_ok  # noqa: E402, F401


@pytest.fixture
def mock_remote():
    remote = _inproc_mock_remote({
        "package.json": '{\n  "lodash": "4.17.19"\n}\n',
        "README.md": "# test-repo\n",
    })
    yield remote
    remote.stop()


@pytest.fixture
def remote_env(mock_remote, monkeypatch):
    import app.services.github as github_svc
    monkeypatch.setenv("GITHUB_API_BASE", mock_remote.api_base)
    monkeypatch.setattr(github_svc, "GITHUB_API", mock_remote.api_base)
    monkeypatch.setattr(github_svc, "_create_jwt", lambda: "mock-jwt")
    monkeypatch.setenv("GITHUB_REMOTE_BASE", mock_remote.api_base)
    from app.services import git_ops
    monkeypatch.setattr(git_ops, "GIT_ALLOWED_PROTOCOLS", "https:http")
    return mock_remote


@pytest.fixture
def executor_service(monkeypatch):
    """Same V3.5 executor service-identity fixture (local copy — the
    original lives in test_git_remediation.py)."""
    from app.config import get_settings
    import app.routes.execution_runs as exec_runs
    import app.routes.git_remediation as rem_routes
    s = get_settings()
    monkeypatch.setattr(s, "executor_service_token", EXECUTOR_TOKEN)

    async def _allow(key, max_requests, window_seconds):
        return True, {}

    monkeypatch.setattr(exec_runs, "check_rate_limit", _allow)
    monkeypatch.setattr(rem_routes, "check_rate_limit", _allow)
    return s


@pytest.fixture
def vrb_auth_client(authenticated_client, test_user):
    async def override():
        return test_user
    app.dependency_overrides[check_verification_rate_limit] = override
    app.dependency_overrides[check_rollback_rate_limit] = override
    app.dependency_overrides[check_remediation_rate_limit] = override
    app.dependency_overrides[check_execution_auth_rate_limit] = override
    app.dependency_overrides[check_approval_rate_limit] = override
    yield authenticated_client
    for dep in (check_verification_rate_limit, check_rollback_rate_limit,
                check_remediation_rate_limit,
                check_execution_auth_rate_limit, check_approval_rate_limit):
        app.dependency_overrides.pop(dep, None)


async def _rebind_to_remote_base(session_factory, seeded, base_sha):
    """Bind proposal+run to the REAL remote base SHA (digest rebinds)."""
    async with session_factory() as session:
        p = (await session.execute(
            select(ActionProposal).where(
                ActionProposal.id == UUID(str(seeded["proposal"].id)))
        )).scalar_one()
        run = (await session.execute(
            select(ExecutionRun).where(
                ExecutionRun.id == UUID(seeded["run"]["id"]))
        )).scalar_one()
        p.base_commit_sha = base_sha
        p.target_branch = "main"  # mock remote serves only main
        from app.services.action_digest import compute_action_digest
        p.action_digest = compute_action_digest({
            "action_type": p.action_type,
            "repository_id": str(p.repository_id),
            "base_commit_sha": p.base_commit_sha,
            "target_branch": p.target_branch,
            "files": p.files,
            "operations": p.operations,
            "expected_diff": p.expected_diff,
        })
        run.action_digest = p.action_digest
        await session.commit()


async def _run_full_remediation(vrb_auth_client, session_factory,
                                test_repository, test_user, monkeypatch,
                                tmp_path, mock_remote, remote_env):
    """Verified run → remediation → push → PR. Returns (remediation dict,
    base_sha)."""
    base_sha = _remote_main_sha(mock_remote.api_base, "test-org", "test-repo")
    seeded = await _verified_run(vrb_auth_client, session_factory,
                                 test_repository, test_user, monkeypatch,
                                 tmp_path)
    await _rebind_to_remote_base(session_factory, seeded, base_sha)
    r = vrb_auth_client.post(
        f"/api/actions/runs/{seeded['run']['id']}/remediation", json={})
    assert r.status_code == 201, r.text
    rem = r.json()
    r = vrb_auth_client.post(
        f"/api/executor/remediations/{rem['id']}/execute",
        headers=_auth_headers())
    assert r.status_code == 200, r.text
    rem = r.json()
    assert rem["remediation_state"] == "PR_CREATED", json.dumps(rem, indent=1)
    return rem, base_sha


class TestVerificationIntegration:
    @pytest.mark.asyncio
    async def test_remediation_verification_pass_end_to_end(
        self, vrb_auth_client, executor_service, session_factory,
        test_repository, test_user, step_up_ok, kill_switch_off,
        monkeypatch, tmp_path, mock_remote, remote_env,
    ):
        """Golden path: PR_CREATED remediation verifies PASS with real
        committed content from the real pushed branch."""
        rem, base_sha = await _run_full_remediation(
            vrb_auth_client, session_factory, test_repository, test_user,
            monkeypatch, tmp_path, mock_remote, remote_env)

        r = vrb_auth_client.post(
            f"/api/remediations/{rem['id']}/verification", json={})
        assert r.status_code == 201, r.text
        v = r.json()
        assert v["verification_state"] == "PENDING"
        assert v["plan_digest"]
        assert "VERIFY_GITHUB_STATE" in v["verification_plan"]["check_types"]

        r = vrb_auth_client.post(
            f"/api/executor/verifications/{v['id']}/execute",
            headers=_auth_headers())
        assert r.status_code == 200, r.text
        result = r.json()
        assert result["verification_state"] == "COMPLETED", result
        assert result["result"] == "PASS", result["reason_code"]
        assert result["checks_failed"] == 0
        assert result["checks_other"] == 0

        # Per-check evidence persisted and scrubbed
        r = vrb_auth_client.get(f"/api/verifications/{v['id']}/checks")
        assert r.status_code == 200
        checks = {c["check_type"]: c for c in r.json()}
        assert checks["VERIFY_FILE_STATE"]["result"] == "PASS"
        assert checks["VERIFY_SECURITY_FINDING"]["result"] == "PASS"
        assert checks["VERIFY_GITHUB_STATE"]["result"] == "PASS"
        ev = checks["VERIFY_GITHUB_STATE"]["evidence"]
        # Evidence carries conditions, never raw repository output
        assert len(json.dumps(ev)) < 10000

        # Re-verification is refused (verdict is final)
        r = vrb_auth_client.post(
            f"/api/remediations/{rem['id']}/verification", json={})
        assert r.status_code == 409
        assert r.json()["detail"]["reason_code"] == "VERIFICATION_REPLAY"

    @pytest.mark.asyncio
    async def test_forged_remediation_fails_verification(
        self, vrb_auth_client, executor_service, session_factory,
        test_repository, test_user, step_up_ok, kill_switch_off,
        monkeypatch, tmp_path, mock_remote, remote_env,
    ):
        """A pushed branch whose committed content does NOT match the run's
        verified AFTER snapshot → intent mismatch → verification FAIL."""
        rem, base_sha = await _run_full_remediation(
            vrb_auth_client, session_factory, test_repository, test_user,
            monkeypatch, tmp_path, mock_remote, remote_env)

        # Simulate content drift on the remote branch (attacker force-push
        # equivalent via direct receive-pack from a throwaway clone)
        tmp = tempfile.mkdtemp(prefix="v36-forge-")
        subprocess.run(
            ["git", "clone", "-q",
             f"{mock_remote.api_base}/test-org/test-repo.git", tmp],
            capture_output=True)
        subprocess.run(["git", "-C", tmp, "fetch", "-q", "origin",
                        rem["remediation_branch"]], capture_output=True)
        subprocess.run(["git", "-C", tmp, "checkout", "-q",
                        rem["remediation_branch"]], capture_output=True)
        # Note: mock remote denies non-fast-forwards; append a commit is
        # a fast-forward — but then the branch tip differs from
        # pushed_sha, which VERIFY_GIT_STATE catches. That is exactly the
        # readback fail-closed behavior under test.
        with open(os.path.join(tmp, "README.md"), "a",
                  encoding="utf-8", newline="") as fh:
            fh.write("\ndrift\n")
        subprocess.run(["git", "-C", tmp, "add", "."], capture_output=True)
        subprocess.run(
            ["git", "-C", tmp, "-c", "user.name=A", "-c", "user.email=a@a",
             "commit", "-qm", "drift"], capture_output=True)
        subprocess.run(["git", "-C", tmp, "push", "-q", "origin",
                        f"{rem['remediation_branch']}:" +
                        rem["remediation_branch"]], capture_output=True)

        r = vrb_auth_client.post(
            f"/api/remediations/{rem['id']}/verification", json={})
        assert r.status_code == 201, r.text
        v = r.json()
        r = vrb_auth_client.post(
            f"/api/executor/verifications/{v['id']}/execute",
            headers=_auth_headers())
        assert r.status_code == 200, r.text
        result = r.json()
        assert result["verification_state"] == "COMPLETED"
        assert result["result"] == "FAIL", result["reason_code"]

        checks = {}
        async with session_factory() as session:
            rows = (await session.execute(
                select(VerificationCheck).where(
                    VerificationCheck.verification_run_id
                    == UUID(v["id"])))).scalars().all()
            for c in rows:
                checks[c.check_type] = c
        git_state = checks["VERIFY_GIT_STATE"]
        assert git_state.result == "FAIL"
        assert git_state.reason_code == "REMOTE_STATE_MISMATCH"


class TestRollbackIntegration:
    @pytest.mark.asyncio
    async def test_rollback_success_end_to_end(
        self, vrb_auth_client, executor_service, session_factory,
        test_repository, test_user, step_up_ok, kill_switch_off,
        monkeypatch, tmp_path, mock_remote, remote_env,
    ):
        """Pushed remediation → rollback → revert branch + revert commit
        pushed without force → PR created → post-rollback readback."""
        rem, base_sha = await _run_full_remediation(
            vrb_auth_client, session_factory, test_repository, test_user,
            monkeypatch, tmp_path, mock_remote, remote_env)

        r = vrb_auth_client.post(
            f"/api/remediations/{rem['id']}/rollback", json={})
        assert r.status_code == 201, r.text
        rb = r.json()
        # Target is SERVER-DERIVED: the frozen contract's base SHA
        assert rb["rollback_target_sha"] == base_sha
        assert rb["expected_branch_sha"] == rem["pushed_sha"]
        assert rb["revert_branch"].startswith("cyvrix/remediation/")
        assert rb["rollback_state"] == "PENDING"

        r = vrb_auth_client.post(
            f"/api/executor/rollbacks/{rb['id']}/execute",
            headers=_auth_headers())
        assert r.status_code == 200, r.text
        result = r.json()
        assert result["rollback_state"] == "COMPLETED", json.dumps(result, indent=1)
        assert result["revert_sha"], result
        assert result["revert_pr_number"] >= 1
        assert result["cleanup_status"] == "COMPLETED"

        # Remote readback: revert branch exists at the revert SHA
        out = subprocess.run(
            ["git", "ls-remote",
             f"{mock_remote.api_base}/test-org/test-repo.git",
             f"refs/heads/{result['revert_branch']}"],
            capture_output=True)
        assert out.returncode == 0
        assert result["revert_sha"] in out.stdout.decode()

        # Revert PR readback
        import httpx
        async with httpx.AsyncClient() as hc:
            pr = (await hc.get(
                f"{mock_remote.api_base}/repos/test-org/test-repo/pulls/"
                f"{result['revert_pr_number']}")).json()
        assert pr["head"]["ref"] == result["revert_branch"]
        assert pr["head"]["sha"] == result["revert_sha"]
        assert pr["base"]["ref"] == "main"

        # Duplicate rollback → replay refusal (idempotency key)
        r = vrb_auth_client.post(
            f"/api/remediations/{rem['id']}/rollback", json={})
        assert r.status_code == 409
        assert r.json()["detail"]["reason_code"] == "ROLLBACK_REPLAY"

    @pytest.mark.asyncio
    async def test_rollback_conflict_when_branch_moved(
        self, vrb_auth_client, executor_service, session_factory,
        test_repository, test_user, step_up_ok, kill_switch_off,
        monkeypatch, tmp_path, mock_remote, remote_env,
    ):
        """Developer push moved the remediation branch after remediation →
        CONFLICT, no revert, no unrelated changes destroyed."""
        rem, base_sha = await _run_full_remediation(
            vrb_auth_client, session_factory, test_repository, test_user,
            monkeypatch, tmp_path, mock_remote, remote_env)

        # Move the remediation branch on the remote (fast-forward dev push)
        tmp = tempfile.mkdtemp(prefix="v36-move-")
        subprocess.run(
            ["git", "clone", "-q",
             f"{mock_remote.api_base}/test-org/test-repo.git", tmp],
            capture_output=True)
        subprocess.run(["git", "-C", tmp, "fetch", "-q", "origin",
                        rem["remediation_branch"]], capture_output=True)
        subprocess.run(["git", "-C", tmp, "checkout", "-q", "-b", "work",
                        "origin/" + rem["remediation_branch"]],
                       capture_output=True)
        with open(os.path.join(tmp, "dev.txt"), "w") as fh:
            fh.write("developer change")
        subprocess.run(["git", "-C", tmp, "add", "."], capture_output=True)
        subprocess.run(
            ["git", "-C", tmp, "-c", "user.name=D", "-c", "user.email=d@d",
             "commit", "-qm", "dev push"], capture_output=True)
        subprocess.run(["git", "-C", tmp, "push", "-q", "origin",
                        f"work:{rem['remediation_branch']}"],
                       capture_output=True)

        r = vrb_auth_client.post(
            f"/api/remediations/{rem['id']}/rollback", json={})
        assert r.status_code == 201, r.text
        rb = r.json()
        r = vrb_auth_client.post(
            f"/api/executor/rollbacks/{rb['id']}/execute",
            headers=_auth_headers())
        assert r.status_code == 200, r.text
        result = r.json()
        assert result["rollback_state"] == "CONFLICT", result
        assert result["fail_reason_code"] == "ROLLBACK_STATE_MISMATCH"
        assert result["revert_sha"] is None  # nothing was pushed

        # Re-rollback after CONFLICT is refused (exactly-once stands)
        r = vrb_auth_client.post(
            f"/api/remediations/{rem['id']}/rollback", json={})
        assert r.status_code == 409

    @pytest.mark.asyncio
    async def test_rollback_conflict_when_base_moved(
        self, vrb_auth_client, executor_service, session_factory,
        test_repository, test_user, step_up_ok, kill_switch_off,
        monkeypatch, tmp_path, mock_remote, remote_env,
    ):
        """Target branch advanced past the authorized base → CONFLICT (the
        revert would no longer describe reality)."""
        rem, base_sha = await _run_full_remediation(
            vrb_auth_client, session_factory, test_repository, test_user,
            monkeypatch, tmp_path, mock_remote, remote_env)

        # Advance main (developer push, fast-forward)
        tmp = tempfile.mkdtemp(prefix="v36-basemove-")
        subprocess.run(
            ["git", "clone", "-q",
             f"{mock_remote.api_base}/test-org/test-repo.git", tmp],
            capture_output=True)
        subprocess.run(["git", "-C", tmp, "checkout", "-q", "-b", "devwork",
                        "origin/main"], capture_output=True)
        with open(os.path.join(tmp, "other.txt"), "w") as fh:
            fh.write("unrelated")
        subprocess.run(["git", "-C", tmp, "add", "."], capture_output=True)
        subprocess.run(
            ["git", "-C", tmp, "-c", "user.name=D", "-c", "user.email=d@d",
             "commit", "-qm", "advance main"], capture_output=True)
        subprocess.run(["git", "-C", tmp, "push", "-q", "origin", "devwork:main"],
                       capture_output=True)

        r = vrb_auth_client.post(
            f"/api/remediations/{rem['id']}/rollback", json={})
        assert r.status_code == 201, r.text
        rb = r.json()
        r = vrb_auth_client.post(
            f"/api/executor/rollbacks/{rb['id']}/execute",
            headers=_auth_headers())
        assert r.status_code == 200, r.text
        result = r.json()
        assert result["rollback_state"] == "CONFLICT", result
        assert result["fail_reason_code"] == "ROLLBACK_CONFLICT"


class TestVerificationRollbackApiSecurity:
    @pytest.mark.asyncio
    async def test_cross_tenant_hiding_and_unknown_ids(
        self, vrb_auth_client, executor_service, session_factory,
        test_repository, test_user, step_up_ok, kill_switch_off,
        monkeypatch, tmp_path, mock_remote, remote_env,
    ):
        rem, _ = await _run_full_remediation(
            vrb_auth_client, session_factory, test_repository, test_user,
            monkeypatch, tmp_path, mock_remote, remote_env)
        # Unknown/foreign IDs are 404 (never 403 — no existence leak)
        r = vrb_auth_client.get(f"/api/verifications/{uuid4()}")
        assert r.status_code == 404
        r = vrb_auth_client.get(f"/api/rollbacks/{uuid4()}")
        assert r.status_code == 404
        r = vrb_auth_client.get(
            f"/api/remediations/{uuid4()}/verification")
        assert r.status_code == 404
        r = vrb_auth_client.post(
            f"/api/remediations/{uuid4()}/rollback", json={})
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_user_cannot_execute_verification_or_rollback(
        self, vrb_auth_client, executor_service, session_factory,
        test_repository, test_user, step_up_ok, kill_switch_off,
        monkeypatch, tmp_path, mock_remote, remote_env,
    ):
        rem, _ = await _run_full_remediation(
            vrb_auth_client, session_factory, test_repository, test_user,
            monkeypatch, tmp_path, mock_remote, remote_env)
        r = vrb_auth_client.post(
            f"/api/remediations/{rem['id']}/verification", json={})
        assert r.status_code == 201, r.text
        v = r.json()
        # USER token cannot run the executor boundary (no service token)
        r = vrb_auth_client.post(
            f"/api/executor/verifications/{v['id']}/execute")
        assert r.status_code == 401
        # And a user cannot even create a rollback for a verification-only
        # flow without a pushed SHA is impossible here (this rem pushed),
        # but the executor boundary must reject user tokens:
        r = vrb_auth_client.post(
            f"/api/remediations/{rem['id']}/rollback", json={})
        assert r.status_code == 201, r.text
        rb = r.json()
        r = vrb_auth_client.post(
            f"/api/executor/rollbacks/{rb['id']}/execute")
        assert r.status_code == 401
        # Wrong service token also fails closed
        r = vrb_auth_client.post(
            f"/api/executor/rollbacks/{rb['id']}/execute",
            headers={"Authorization": "Bearer not-the-token"})
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_kill_switch_blocks_verification_start(
        self, vrb_auth_client, executor_service, session_factory,
        test_repository, test_user, step_up_ok, kill_switch_off,
        monkeypatch, tmp_path, mock_remote, remote_env,
    ):
        rem, _ = await _run_full_remediation(
            vrb_auth_client, session_factory, test_repository, test_user,
            monkeypatch, tmp_path, mock_remote, remote_env)
        async with session_factory() as session:
            from sqlalchemy import update
            await session.execute(
                update(SystemControl).where(
                    SystemControl.key == "execution_disabled")
                .values(value="true"))
            await session.commit()
        r = vrb_auth_client.post(
            f"/api/remediations/{rem['id']}/verification", json={})
        assert r.status_code == 409
        assert r.json()["detail"]["reason_code"] == "KILL_SWITCH_ACTIVE"
        r = vrb_auth_client.post(
            f"/api/remediations/{rem['id']}/rollback", json={})
        assert r.status_code == 409
        assert r.json()["detail"]["reason_code"] == "KILL_SWITCH_ACTIVE"
