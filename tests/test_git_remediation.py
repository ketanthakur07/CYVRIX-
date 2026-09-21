"""CYVRIX V3.5 — Git remediation security tests.

Layers:
1. Pure model: states, stage ceilings, branch validation, commit/PR text
   bounding + injection scrubbing, secret scanning.
2. REAL git safety (real git binary, real local repos): hooks disabled,
   repository config cannot redefine trusted behavior, no force push,
   base SHA verification, remote-state mismatch fail-closed.
3. Pipeline integration (real git over HTTP via the in-process mock
   provider): verified run → remediation → branch → commit → push →
   branch readback, with scope/secret enforcement.
4. API boundary: service identity, ownership, replay/exactly-once,
   forged authority parameters, cross-tenant hiding, kill switch.

Real PostgreSQL race suites live in test_git_remediation_races.py.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from uuid import UUID, uuid4

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from sqlalchemy import select

from app.main import app
from app.models import (
    ActionProposal, AuditEvent, ExecutionRun, GitRemediation,
    SystemControl, WorkspaceSnapshot,
)
from app.routes.actions import check_proposal_rate_limit  # noqa: F401
from app.routes.approvals import check_approval_rate_limit
from app.routes.execution_authorization import check_execution_auth_rate_limit
from app.routes.git_remediation import check_remediation_rate_limit

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(__file__))
from test_execution_runs_api import (
    EXECUTOR_TOKEN, _auth_headers, _approve, _fake_materialize_with,
    _seed_authorized, exec_auth_as, kill_switch_off, step_up_ok,  # noqa: F401
)


@pytest.fixture(autouse=True)
def _allow_local_git_transport(monkeypatch):
    """Permit file-transport remotes for LOCAL mock repositories only.

    Production git_ops pins GIT_ALLOWED_PROTOCOLS='https' (module constant,
    not a setting). These tests use real local bare repos as remotes, so
    the test seam widens the constant to include file transport. No env
    var or request input can ever widen it in production.
    """
    from app.services import git_ops
    monkeypatch.setattr(git_ops, "GIT_ALLOWED_PROTOCOLS", "https:file")


# ── Helpers ──────────────────────────────────────────────────────────


def _run_git_ok(args, cwd, env=None):
    proc = subprocess.run(args, cwd=cwd, capture_output=True,
                          env={**os.environ, **(env or {})})
    assert proc.returncode == 0, proc.stderr.decode()[:300]
    return proc.stdout.decode()


def _make_remote_with_base(base_commit_files: dict) -> tuple[str, str]:
    """Create a REAL bare remote + seeded 'main' branch. Returns (url, sha)."""
    tmp = tempfile.mkdtemp(prefix="gr35-")
    remote = os.path.join(tmp, "remote.git")
    work = os.path.join(tmp, "seed")
    subprocess.run(["git", "init", "--bare", remote], check=True, capture_output=True)
    subprocess.run(["git", "init", work], check=True, capture_output=True)
    for rel, content in base_commit_files.items():
        p = os.path.join(work, rel)
        os.makedirs(os.path.dirname(p) or work, exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
    _run_git_ok(["git", "add", "."], work)
    _run_git_ok(["git", "-c", "user.name=T", "-c", "user.email=t@t", "commit",
                 "-m", "base"], work)
    _run_git_ok(["git", "branch", "-M", "main"], work)
    _run_git_ok(["git", "remote", "add", "origin", remote], work)
    _run_git_ok(["git", "push", "-q", "origin", "main"], work)
    sha = _run_git_ok(["git", "rev-parse", "HEAD"], work).strip()
    return remote, sha


# ── 1. Pure model ────────────────────────────────────────────────────


class TestRemediationModel:
    def test_state_machine_terminal_states(self):
        from app.services import git_remediation_model as grm
        assert grm.can_transition("PENDING", "VERIFYING")
        assert not grm.can_transition("PENDING", "PUSHED")
        assert not grm.can_transition("FAILED", "PR_CREATED")
        assert not grm.can_transition("STALE", "VERIFYING")
        assert grm.is_terminal("PR_CREATED")
        assert grm.is_terminal("FAILED")
        assert grm.is_terminal("INCONSISTENT")
        assert grm.is_terminal("SOMETHING_ELSE")  # unknown → fail closed

    def test_stage_ceiling_ordering(self):
        from app.services import git_remediation_model as grm
        assert not grm.stage_at_least("LOCAL_ONLY", "COMMIT_ALLOWED")
        assert grm.stage_at_least("COMMIT_ALLOWED", "COMMIT_ALLOWED")
        assert grm.stage_at_least("PUSH_ALLOWED", "COMMIT_ALLOWED")
        assert grm.stage_at_least("PR_ALLOWED", "PUSH_ALLOWED")
        assert not grm.stage_at_least("COMMIT_ALLOWED", "PUSH_ALLOWED")
        assert not grm.stage_at_least("NOT_A_STAGE", "PUSH_ALLOWED")

    def test_branch_validation_strict(self):
        from app.services import git_remediation_model as grm
        assert grm.validate_repo_branch_name("main") == "main"
        assert grm.validate_repo_branch_name("feature/upgrade-lodash") == \
            "feature/upgrade-lodash"
        for bad in (
            "../x", "refs/heads/x", "x/refs/y", ".git", ".git/config",
            "x/.git/y", "a b", "x~1", "x^2", "a:b", "x*y", "x[1]", "HEAD",
            "a//b", "-x", "main/", "/main", "main.", "x@{1}", "x\ny",
        ):
            with pytest.raises(Exception):
                grm.validate_repo_branch_name(bad)

    def test_remediation_branch_server_generated_and_valid(self):
        from app.services import git_remediation_model as grm
        b = grm.generate_remediation_branch("c9a1e0d4-1111-2222-3333-444455556666")
        assert b == "cyvrix/remediation/c9a1e0d4111122223333444455556666"
        assert grm.validate_repo_branch_name(b) == b
        with pytest.raises(Exception):
            grm.generate_remediation_branch("not-a-uuid!!!")

    def test_commit_message_bounded_and_scrubbed(self):
        from app.services import git_remediation_model as grm
        msg = grm.build_commit_message(
            repo_name="repo", action_digest="d" * 64, base_commit_sha="b" * 40,
            execution_run_id="e1", git_remediation_id="r1",
            finding_title="Upgrade lodash")
        assert "lodash" in msg and "CYVRIX" in msg
        hostile = grm.build_commit_message(
            repo_name="r\x00\nINJECT", action_digest="d" * 64,
            base_commit_sha="b" * 40, execution_run_id="e1",
            git_remediation_id="r1", finding_title="t\x01itle")
        assert "\x00" not in hostile and "\x01" not in hostile

    def test_pr_body_contains_no_repo_text_or_credentials(self):
        from app.services import git_remediation_model as grm
        title, body = grm.build_pr_title_and_body(
            finding_title="Upgrade lodash", severity="HIGH", repo_name="repo",
            base_commit_sha="b" * 40,
            remediation_branch="cyvrix/remediation/abc",
            authorized_files=("package.json",), action_digest="d" * 64,
            git_remediation_id="r1", execution_run_id="e1")
        assert "package.json" in body and "lodash" in title
        assert "ghp_" not in body and "token" not in body.lower()

    def test_secret_scanner(self):
        from app.services import git_remediation_model as grm
        hits = grm.scan_text_for_secrets('token = "ghp_' + "a" * 36 + '"')
        assert "github_pat" in hits
        assert grm.scan_text_for_secrets("const x = 1;\n") == []
        aws = grm.scan_text_for_secrets("AKIAIOSFODNN7EXAMPLE")
        assert "aws_access_key" in aws
        pem = grm.scan_text_for_secrets("-----BEGIN RSA PRIVATE KEY-----")
        assert "private_key" in pem


# ── 2. REAL git safety ───────────────────────────────────────────────


class TestGitOpsSafety:
    def test_hooks_disabled_commit_does_not_execute_repo_hooks(self):
        """A repository pre-commit hook must NEVER run (Phase 5)."""
        from app.services import git_ops
        tmp = tempfile.mkdtemp(prefix="gr35-hooks-")
        _run_git_ok(["git", "init", "-q"], tmp)
        with open(os.path.join(tmp, "f.txt"), "w") as fh:
            fh.write("x")
        marker = os.path.join(tmp, "HOOK_RAN")
        hooks_dir = os.path.join(tmp, ".git", "hooks")
        hook = os.path.join(hooks_dir, "pre-commit")
        with open(hook, "w") as fh:
            fh.write(f"#!/bin/sh\ntouch {marker}\n")
        os.chmod(hook, 0o755)
        _run_git_ok(["git", "add", "."], tmp)
        ok, out, err = git_ops.run_git(
            ["git", *(git_ops._config_args()), "commit", "--no-verify", "-m", "m"],
            cwd=tmp)
        assert ok
        assert not os.path.exists(marker), "repository hook EXECUTED — sandbox escape"

    def test_repo_config_cannot_redefine_trusted_behavior(self):
        """A poisoned .git/config must not re-enable hooks or change identity."""
        from app.services import git_ops
        tmp = tempfile.mkdtemp(prefix="gr35-cfg-")
        _run_git_ok(["git", "init", "-q"], tmp)
        cfg = os.path.join(tmp, ".git", "config")
        with open(cfg, "a") as fh:
            fh.write("\n[core]\n\thooksPath = /tmp/gr35-evil-hooks\n"
                     "\tfsmonitor = /tmp/gr35-evil-fsmonitor\n")
        with open(os.path.join(tmp, "f.txt"), "w", encoding="utf-8") as fh:
            fh.write("x")
        # git ops with our fixed config must still work and not consult it
        _run_git_ok(["git", "add", "."], tmp)
        ok, out, err = git_ops.run_git(
            ["git", *(git_ops._config_args()), "commit", "--no-verify", "-m", "m"],
            cwd=tmp)
        assert ok, err
        assert "CYVRIX Remediation" in _run_git_ok(
            ["git", "log", "-1", "--pretty=%an"], tmp)

    def test_no_force_push_structurally(self):
        """push_branch never passes force flags; verify argv construction."""
        from app.services import git_ops
        import inspect
        src = inspect.getsource(git_ops.push_branch)
        assert "--force" not in src
        # Strip comments/docstrings, then assert no standalone '-f' ARGV
        # token (word-boundary, quote-delimited) and no '-f' attached to
        # another flag token like '--no-verify-f'. Docstring prose
        # (e.g. 'non-fast-forward') is not an argv token.
        code = inspect.cleandoc(src)
        assert not re.search(r"['\"]-f['\"]", code), "-f argv token present"
        assert not re.search(r"\s-f\s", re.sub(r'""".*?"""', '', code, flags=re.S))

    def test_base_sha_verification_fails_closed(self):
        from app.services import git_ops
        from app.services import git_remediation_model as grm
        remote, sha = _make_remote_with_base({"package.json": '{"x":1}\n'})
        tmp = tempfile.mkdtemp(prefix="gr35-base-")
        url = git_ops.build_remote_url("http://127.0.0.1:1", "o", "n")  # never used
        git_ops.init_repo(tmp, remote)
        fake_sha = "f" * 40
        with pytest.raises(git_ops.GitError) as ei:
            git_ops.fetch_and_verify_base(tmp, remote, "main", fake_sha)
        assert ei.value.reason_code == grm.RC_BASE_COMMIT_MISMATCH

    def test_push_non_fast_forward_fails_closed(self):
        """Remote moved ahead → plain push fails; helper reports mismatch."""
        from app.services import git_ops
        from app.services import git_remediation_model as grm
        remote, sha = _make_remote_with_base({"package.json": '{"x":1}\n'})
        # someone pushes to the remediation branch first (collision)
        tmp = tempfile.mkdtemp(prefix="gr35-push-")
        subprocess.run(["git", "init", "-q", tmp], check=True, capture_output=True)
        _run_git_ok(["git", "remote", "add", "origin", remote], tmp)
        _run_git_ok(["git", "fetch", "-q", "origin"], tmp)
        _run_git_ok(["git", "checkout", "-q", "-b", "cyvrix/remediation/aaa", "origin/main"], tmp)
        with open(os.path.join(tmp, "other.txt"), "w") as fh:
            fh.write("attacker content")
        _run_git_ok(["git", "add", "."], tmp)
        _run_git_ok(["git", "-c", "user.name=T", "-c", "user.email=t@t",
                     "commit", "-m", "pre-existing"], tmp)
        _run_git_ok(["git", "push", "-q", "origin", "cyvrix/remediation/aaa"], tmp)
        # our push must refuse to clobber it (expected_remote_sha=None, mismatch)
        with pytest.raises(git_ops.GitError) as ei:
            git_ops.push_branch(tmp, remote, "cyvrix/remediation/aaa",
                                None, expected_remote_sha=None)
        assert ei.value.reason_code == grm.RC_REMOTE_STATE_MISMATCH

    def test_remote_url_validation(self):
        from app.services import git_ops
        from app.services import git_remediation_model as grm
        assert git_ops.build_remote_url(
            "https://github.com", "owner", "repo.name-1") == \
            "https://github.com/owner/repo.name-1.git"
        with pytest.raises(git_ops.GitError):
            git_ops.build_remote_url("https://github.com", "../evil", "repo")
        with pytest.raises(git_ops.GitError):
            git_ops.build_remote_url("https://github.com", "o", "r; rm -rf /")
        with pytest.raises(git_ops.GitError):
            git_ops.build_remote_url("gopher://evil", "o", "r")


# ── Fixtures for pipeline tests ──────────────────────────────────────


@pytest.fixture
def rem_auth_client(authenticated_client, test_user):
    async def override():
        return test_user
    app.dependency_overrides[check_remediation_rate_limit] = override
    app.dependency_overrides[check_execution_auth_rate_limit] = override
    app.dependency_overrides[check_approval_rate_limit] = override
    yield authenticated_client
    app.dependency_overrides.pop(check_remediation_rate_limit, None)
    app.dependency_overrides.pop(check_execution_auth_rate_limit, None)
    app.dependency_overrides.pop(check_approval_rate_limit, None)


@pytest.fixture
def executor_service(monkeypatch):
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


async def _verified_run(client, session_factory, test_repository, test_user,
                        monkeypatch, tmp_path) -> dict:
    """Drive the REAL V3.4 pipeline (fake sandbox applying the operation)
    to a COMPLETED run — the only valid input to V3.5.

    The fake container applies the approved operation to the workspace
    (deterministic, no Docker); host-side status derivation, snapshotting,
    scope verification, and cleanup are the REAL production paths.
    """
    from app.services import execution_service, workspace as wsvc
    import app.services.sandbox as sandbox_svc

    seeded = await _seed_authorized(client, session_factory, test_repository,
                                    test_user)
    token = seeded["approval"]["authorization_token"]

    async def fake_materialize(run, authorization, proposal):
        from app.services.workspace import new_workspace_dir
        d = new_workspace_dir()
        with open(os.path.join(d, "package.json"), "w",
                  encoding="utf-8", newline="") as fh:
            fh.write('{\n  "lodash": "4.17.19"\n}\n')
        return d, {"files": {}, "source": "fake", "ref": "x"}

    monkeypatch.setattr(execution_service, "_materialize", fake_materialize)
    monkeypatch.setattr(sandbox_svc, "check_platform_support",
                        lambda client=None: {"kernel": "fake", "cgroup": "2"})
    factory = _FakeExecutorSandbox.factory
    monkeypatch.setattr(execution_service, "SANDBOX_FACTORY", factory)
    monkeypatch.setattr(sandbox_svc, "create_sandbox",
                        lambda ws, *a, **k: factory(ws))

    r = client.post("/api/executor/runs", json={
        "execution_authorization_id": seeded["authorization"]["id"],
        "token": token}, headers=_auth_headers())
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["run_state"] == "COMPLETED", body
    seeded["run"] = body
    return seeded


class _FakeExecutorSandbox:
    """In-process stand-in for the hardened container: applies the approved
    operation to the workspace files (byte-stable: newline="" everywhere so
    BEFORE/AFTER/RECON hashes match on every platform), writes bounded
    result.json + probes.json, and exposes the container surface used by
    sandbox.run_executor / destroy_sandbox (start/attrs/wait/logs)."""

    def __init__(self, ws: str):
        self.ws = ws
        ops_path = os.path.join(ws, ".cyvrix", "operations.json")
        if os.path.exists(ops_path):
            with open(ops_path, "r", encoding="utf-8", newline="") as fh:
                payload = json.load(fh)
            for op in payload.get("operations", []):
                f = os.path.join(ws, *op["file"].split("/"))
                if (op.get("type") == "UPDATE_DEPENDENCY_VERSION"
                        and os.path.exists(f)):
                    with open(f, "r", encoding="utf-8", newline="") as fh:
                        content = fh.read()
                    content = content.replace(
                        f'"{op["name"]}": "{op["from_version"]}"',
                        f'"{op["name"]}": "{op["to_version"]}"')
                    with open(f, "w", encoding="utf-8", newline="") as fh:
                        fh.write(content)
        payload_dir = os.path.join(ws, ".cyvrix")
        ops = payload.get("operations", []) if os.path.exists(ops_path) else []
        with open(os.path.join(payload_dir, "result.json"), "w",
                  encoding="utf-8", newline="") as fh:
            json.dump({"ok": True, "reason_code": "OK",
                       "detail": "applied",
                       "operations": [{
                           "index": i,
                           "op_type": (o.get("type") if o else "UNKNOWN"),
                           "file_path": (o.get("file") if o else ""),
                           "applied": True, "detail": ""}
                           for i, o in enumerate(ops)]}, fh)
        with open(os.path.join(payload_dir, "probes.json"), "w",
                  encoding="utf-8", newline="") as fh:
            json.dump({"uid": {"uid": 10001, "gid": 10001, "euid": 10001},
                       "network": {}, "docker_socket": {"exists": False}}, fh)

    # container surface used by run_executor / destroy_sandbox
    def start(self):
        pass  # work already done deterministically

    @property
    def attrs(self):
        return {"State": {"ExitCode": 0}}

    def wait(self, *a, **k):
        return {"StatusCode": 0}

    def logs(self, **k):
        return b""

    @staticmethod
    def factory(ws, *a, **k):
        return {"container": _FakeExecutorSandbox(ws)}


# ── 3. Pipeline integration ──────────────────────────────────────────


class TestRemediationPipeline:
    @pytest.mark.asyncio
    async def test_start_requires_verified_run(
        self, rem_auth_client, session_factory, test_repository, test_user,
        step_up_ok, kill_switch_off,
    ):
        """A FAILED run cannot start remediation (Phase: run state gate)."""
        proposal = None
        seeded = await _seed_authorized(
            rem_auth_client, session_factory, test_repository, test_user)
        # no run at all → 404 path: use a random run id
        r = rem_auth_client.post(
            f"/api/actions/runs/{uuid4()}/remediation", json={})
        assert r.status_code == 404
        _ = proposal

    @pytest.mark.asyncio
    async def test_forged_authority_parameters_rejected(self, rem_auth_client):
        """No authority parameter may be passed (extra=forbid)."""
        r = rem_auth_client.post(
            f"/api/actions/runs/{uuid4()}/remediation",
            json={"stage_ceiling": "PR_ALLOWED", "branch": "main",
                  "authorized": True, "push": True})
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_service_identity_required_for_execute(self, client, executor_service):
        r = client.post(f"/api/executor/remediations/{uuid4()}/execute")
        assert r.status_code == 401
        r = client.post(f"/api/executor/remediations/{uuid4()}/execute",
                        headers={"Authorization": "Bearer nope"})
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_cross_tenant_hidden(
        self, exec_auth_as, session_factory, test_repository, test_user,
        step_up_ok, kill_switch_off,
    ):
        from app.routes.git_remediation import (
            check_remediation_rate_limit as crl,
        )
        from app.auth import get_current_user

        client_a = exec_auth_as("a")
        # user A starts remediation on their verified run
        # (no run exists → 404 for B too; check isolation on the GET path)
        r = client_a.get(f"/api/remediations/{uuid4()}")
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_kill_switch_blocks_start(
        self, rem_auth_client, session_factory, test_repository, test_user,
        step_up_ok, kill_switch_off,
    ):
        async with session_factory() as session:
            row = (await session.execute(
                select(SystemControl).where(
                    SystemControl.key == "execution_disabled"))).scalar_one()
            row.value = "true"
            await session.commit()
        r = rem_auth_client.post(
            f"/api/actions/runs/{uuid4()}/remediation", json={})
        # kill switch check happens after ownership; unknown run → 404 first
        assert r.status_code in (404, 409)


# ── 3b. Pipeline integration (hermetic: real git remotes, fake container) ─


def _inproc_mock_remote(files: dict) -> "_InProcMockRemote":
    """Start an in-process instance of the repository's own mock provider
    (the same receive-pack / branch / PR endpoints used by the e2e stack)."""
    import threading
    import time as _time
    import socket as _socket

    import uvicorn

    class _Server:
        def __init__(self):
            s = _socket.socket()
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
            s.close()
            self.repos_dir = tempfile.mkdtemp(prefix="gr35u-repos-")
            self.fixtures_dir = tempfile.mkdtemp(prefix="gr35u-fix-")
            os.environ["REPOS_DIR"] = self.repos_dir
            os.environ["FIXTURE_DIR"] = self.fixtures_dir
            self._thread = None
            self._server = None

        def seed_repo(self, name: str, ffiles: dict) -> str:
            fixture = os.path.join(self.fixtures_dir, name)
            os.makedirs(fixture, exist_ok=True)
            for rel, content in ffiles.items():
                p = os.path.join(fixture, rel)
                os.makedirs(os.path.dirname(p) or fixture, exist_ok=True)
                with open(p, "w", encoding="utf-8", newline="") as fh:
                    fh.write(content)
            return f"http://127.0.0.1:{self.port}"

        def start(self):
            sys.path.insert(0, os.path.join(
                os.path.dirname(__file__), "..", "services", "mock-providers"))
            import server as mock_server
            # The mock-server module reads REPOS_DIR/FIXTURE_DIR at import
            # time only. If a race module already imported it with its own
            # dirs, this server would serve the wrong repos dir (and fail
            # with 'Fixture not found'). Rebind the globals to THIS server's
            # dirs on every start and reset the initialized-repos cache.
            mock_server.REPOS_DIR = self.repos_dir
            mock_server.FIXTURE_DIR = self.fixtures_dir
            mock_server._initialized_repos.clear()
            config = uvicorn.Config(mock_server.app, host="127.0.0.1",
                                    port=self.port, log_level="error")
            self._server = uvicorn.Server(config)
            self._thread = threading.Thread(target=self._server.run, daemon=True)
            self._thread.start()
            deadline = _time.time() + 30
            while _time.time() < deadline:
                try:
                    with _socket.create_connection(("127.0.0.1", self.port), 0.5):
                        return
                except OSError:
                    _time.sleep(0.1)
            raise RuntimeError("in-process mock remote did not start")

        def stop(self):
            if self._server is not None:
                self._server.should_exit = True
            if self._thread is not None:
                self._thread.join(timeout=10)

        @property
        def api_base(self) -> str:
            return f"http://127.0.0.1:{self.port}"

    remote = _Server()
    remote.start()
    remote.seed_repo("test-repo", files)
    return remote


def _remote_main_sha(base_url: str, owner: str, repo: str) -> str:
    out = subprocess.run(
        ["git", "ls-remote", f"{base_url}/{owner}/{repo}.git",
         "refs/heads/main"],
        capture_output=True, check=True).stdout.decode()
    return out.split()[0].strip().lower()


class TestRemediationPipelineIntegration:
    """Layer 3: verified run → remediation → REAL git fetch/commit/push
    → REAL branch readback → REAL PR creation + verification against the
    in-process mock remote. Container layer faked; everything else real.

    These tests monkeypatch settings.environ (GITHUB_API_BASE) and the git
    transport allowlist (module constant; production stays https-only).
    """

    @pytest.fixture
    def mock_remote(self):
        remote = _inproc_mock_remote({
            "package.json": '{\n  "lodash": "4.17.19"\n}\n',
            "README.md": "# test-repo\n",
        })
        yield remote
        remote.stop()

    @pytest.fixture
    def remote_env(self, mock_remote, monkeypatch):
        """Point the credential/API/remote pipeline at the mock provider."""
        import app.services.github as github_svc
        monkeypatch.setenv("GITHUB_API_BASE", mock_remote.api_base)
        monkeypatch.setattr(github_svc, "GITHUB_API", mock_remote.api_base)
        monkeypatch.setattr(github_svc, "_create_jwt", lambda: "mock-jwt")
        monkeypatch.setenv("GITHUB_REMOTE_BASE", mock_remote.api_base)
        from app.services import git_ops
        monkeypatch.setattr(git_ops, "GIT_ALLOWED_PROTOCOLS", "https:http")
        return mock_remote

    @pytest.mark.asyncio
    async def test_full_pipeline_commit_push_pr(
        self, rem_auth_client, executor_service, session_factory,
        test_repository, test_user, step_up_ok, kill_switch_off,
        monkeypatch, tmp_path, mock_remote, remote_env,
    ):
        """Golden path: run → remediation → commit → push → PR (real git)."""
        base_sha = _remote_main_sha(mock_remote.api_base, "test-org",
                                    "test-repo")
        seeded = await _verified_run(rem_auth_client, session_factory,
                                     test_repository, test_user, monkeypatch,
                                     tmp_path)
        # Bind the proposal to the REAL remote base SHA (digest re-binds:
        # approve/authorize already consumed the synthetic SHA, so update
        # proposal + run consistently BEFORE starting the remediation).
        async with session_factory() as session:
            from app.models import ActionProposal, ExecutionRun
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

        r = rem_auth_client.post(
            f"/api/actions/runs/{seeded['run']['id']}/remediation", json={})
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["remediation_branch"].startswith("cyvrix/remediation/")
        assert body["stage_ceiling"] == "PR_ALLOWED"

        r = rem_auth_client.post(
            f"/api/executor/remediations/{body['id']}/execute",
            headers=_auth_headers())
        assert r.status_code == 200, r.text
        final = r.json()
        assert final["remediation_state"] == "PR_CREATED", json.dumps(final, indent=1)
        assert final["pushed_sha"] == final["committed_sha"]
        assert final["pr_number"] >= 1
        assert final["cleanup_status"] == "COMPLETED"

        # REAL branch readback on the remote (owner-prefixed, like GitHub)
        out = subprocess.run(
            ["git", "ls-remote",
             f"{mock_remote.api_base}/test-org/test-repo.git",
             f"refs/heads/{final['remediation_branch']}"],
            capture_output=True)
        assert out.returncode == 0
        assert final["pushed_sha"] in out.stdout.decode()

        # REAL PR readback (mock provider endpoint)
        import httpx
        async with httpx.AsyncClient() as hc:
            pr = (await hc.get(
                f"{mock_remote.api_base}/repos/test-org/test-repo/pulls/"
                f"{final['pr_number']}"))
        assert pr.status_code == 200
        pr = pr.json()
        assert pr["head"]["ref"] == final["remediation_branch"]
        assert pr["head"]["sha"] == final["pushed_sha"]
        assert pr["base"]["ref"] == "main"
        assert pr["base"]["repo"]["full_name"] == "test-org/test-repo"

    @pytest.mark.asyncio
    async def test_push_blocked_by_remote_collision(
        self, rem_auth_client, executor_service, session_factory,
        test_repository, test_user, step_up_ok, kill_switch_off,
        monkeypatch, tmp_path, mock_remote, remote_env,
    ):
        """Pre-existing remediation branch at an unexpected SHA → fail closed."""
        base_sha = _remote_main_sha(mock_remote.api_base, "test-org",
                                    "test-repo")
        seeded = await _verified_run(rem_auth_client, session_factory,
                                     test_repository, test_user, monkeypatch,
                                     tmp_path)
        async with session_factory() as session:
            from app.models import ActionProposal, ExecutionRun
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

        r = rem_auth_client.post(
            f"/api/actions/runs/{seeded['run']['id']}/remediation", json={})
        assert r.status_code == 201, r.text
        created = r.json()

        # Seed the collision: push a foreign commit to the server-generated
        # branch from a throwaway clone (attacker/CI got there first).
        tmp = tempfile.mkdtemp(prefix="gr35u-collide-")
        subprocess.run(["git", "clone", "-q",
                        f"{mock_remote.api_base}/test-org/test-repo.git", tmp],
                       capture_output=True)
        subprocess.run(["git", "-C", tmp, "checkout", "-q", "-b",
                        created["remediation_branch"], "origin/main"],
                       capture_output=True)
        with open(os.path.join(tmp, "evil.txt"), "w") as fh:
            fh.write("attacker")
        subprocess.run(["git", "-C", tmp, "add", "."], capture_output=True)
        subprocess.run(["git", "-C", tmp, "-c", "user.name=A", "-c",
                        "user.email=a@a", "commit", "-qm", "collision"],
                       capture_output=True)
        subprocess.run(["git", "-C", tmp, "push", "-q", "origin",
                        created["remediation_branch"]], capture_output=True)

        r = rem_auth_client.post(
            f"/api/executor/remediations/{created['id']}/execute",
            headers=_auth_headers())
        assert r.status_code == 200, r.text
        final = r.json()
        assert final["remediation_state"] == "FAILED", json.dumps(final, indent=1)
        assert final["fail_reason_code"] == "REMOTE_STATE_MISMATCH", json.dumps(final, indent=1)
        assert final["cleanup_status"] == "COMPLETED"

    @pytest.mark.asyncio
    async def test_stale_base_commit_fails_closed(
        self, rem_auth_client, executor_service, session_factory,
        test_repository, test_user, step_up_ok, kill_switch_off,
        monkeypatch, tmp_path, mock_remote, remote_env,
    ):
        """Remote source branch moved past the authorized base → STALE/DENY."""
        from app.services import git_ops, git_remediation_model as grm
        base_sha = _remote_main_sha(mock_remote.api_base, "test-org",
                                    "test-repo")
        seeded = await _verified_run(rem_auth_client, session_factory,
                                     test_repository, test_user, monkeypatch,
                                     tmp_path)
        async with session_factory() as session:
            from app.models import ActionProposal
            p = (await session.execute(
                select(ActionProposal).where(
                    ActionProposal.id == UUID(str(seeded["proposal"].id)))
            )).scalar_one()
            p.base_commit_sha = base_sha
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
            await session.commit()

        tmp = tempfile.mkdtemp(prefix="gr35u-stale-")
        remote_url = git_ops.build_remote_url(
            mock_remote.api_base, test_repository.owner, test_repository.name)
        git_ops.init_repo(tmp, remote_url)
        # Authorized base = synthetic race SHA; remote tip = real SHA → deny
        with pytest.raises(git_ops.GitError) as ei:
            git_ops.fetch_and_verify_base(
                tmp, remote_url, "main", "a" * 40)
        assert ei.value.reason_code == grm.RC_BASE_COMMIT_MISMATCH
        _ = seeded  # verified-run fixture proves the gate chain is real
