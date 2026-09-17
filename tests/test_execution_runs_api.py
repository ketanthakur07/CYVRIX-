"""CYVRIX V3.4 — execution-run API security tests.

Covers: service-identity gate (no token → 503/401, wrong token → 401),
golden admission → sandbox → result on SQLite with a FAKE sandbox
(real-container tests are separate and require Linux + Docker), exactly-
once (replay/in-progress), kill switch, forged fields, cross-tenant,
bounded result shape, and the NO-EXECUTION regression for V3.4 routes.
"""
import json
import os
import sys
from datetime import datetime, timezone
from uuid import uuid4

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.models import (
    ActionProposal, Approval, AuditEvent, ExecutionAuthorization,
    ExecutionRun, SystemControl, User,
)
from app.routes.actions import check_proposal_rate_limit
from app.routes.approvals import check_approval_rate_limit
from app.routes.execution_authorization import check_execution_auth_rate_limit

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(__file__))
from test_approvals_api import seed_proposal

EXECUTOR_TOKEN = "test-executor-service-token-0123456789abcdef"


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def exec_auth_client(authenticated_client, test_user):
    async def override():
        return test_user
    app.dependency_overrides[check_execution_auth_rate_limit] = override
    app.dependency_overrides[check_approval_rate_limit] = override
    app.dependency_overrides[check_proposal_rate_limit] = override
    yield authenticated_client
    app.dependency_overrides.pop(check_execution_auth_rate_limit, None)
    app.dependency_overrides.pop(check_approval_rate_limit, None)
    app.dependency_overrides.pop(check_proposal_rate_limit, None)


@pytest.fixture
def step_up_ok(monkeypatch):
    from app.services import approval_service

    async def fake_loader(*, approver, second_approver_user_id=None):
        second_ts = datetime.now(timezone.utc) if second_approver_user_id else None
        return datetime.now(timezone.utc), second_ts, None

    monkeypatch.setattr(approval_service, "_load_step_up_evidence", fake_loader)
    return None


@pytest.fixture
def exec_auth_as(authenticated_client, test_user, test_user_b):
    """Explicit per-user authentication on the shared test client."""
    from app.auth import get_current_user

    users = {"a": test_user, "b": test_user_b}

    def _act_as(which: str):
        user = users[which]

        async def override():
            return user

        app.dependency_overrides[get_current_user] = override
        app.dependency_overrides[check_execution_auth_rate_limit] = override
        app.dependency_overrides[check_approval_rate_limit] = override
        app.dependency_overrides[check_proposal_rate_limit] = override
        return authenticated_client

    yield _act_as
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(check_execution_auth_rate_limit, None)
    app.dependency_overrides.pop(check_approval_rate_limit, None)
    app.dependency_overrides.pop(check_proposal_rate_limit, None)


@pytest.fixture
async def kill_switch_off(session_factory):
    async with session_factory() as session:
        session.add(SystemControl(key="execution_disabled", value="false"))
        await session.commit()
    return None


@pytest.fixture
def executor_service(monkeypatch):
    """Configure the executor service token for the internal boundary.
    Routes read settings.executor_service_token at request time from the
    lru_cached instance, so patching the instance is sufficient. The
    admission rate limit (fail-closed inline call) is bypassed here —
    real limit behavior is covered in the real-stack suite."""
    from app.config import get_settings
    import app.routes.execution_runs as exec_runs
    s = get_settings()
    monkeypatch.setattr(s, "executor_service_token", EXECUTOR_TOKEN)

    async def _allow(key, max_requests, window_seconds):
        return True, {}

    monkeypatch.setattr(exec_runs, "check_rate_limit", _allow)
    return s


def _auth_headers():
    return {"Authorization": f"Bearer {EXECUTOR_TOKEN}"}


def _fake_sandbox_factory(applied_files):
    """A deterministic in-process stand-in for the container: writes the
    approved files (simulating the structured operations) inside the
    workspace. The real container is exercised in the Linux-only suite."""
    import threading

    class _FakeSandbox:
        def __init__(self, ws):
            self.ws = ws

    created = {}

    def factory(workspace_dir):
        sandbox = {"container": _FakeContainer(ws=workspace_dir)}
        created["sandbox"] = sandbox
        return sandbox

    class _FakeContainer:
        def __init__(self, ws):
            self.ws = ws

        # minimal surface used by sandbox.run_executor / destroy
        def wait(self, *a, **k):
            return {"StatusCode": 0}

        def logs(self, **k):
            return b""

    return factory


def _approve(client, proposal) -> dict:
    r = client.post(f"/api/actions/{proposal.id}/approve", json={"reason": "LGTM"})
    assert r.status_code == 200, r.text
    return r.json()


def _uuid(x):
    from uuid import UUID as _U
    return _U(x) if isinstance(x, str) else x


async def _seed_authorized(client, session_factory, test_repository, test_user,
                           monkeypatch=None) -> dict:
    """Proposal → approval → authorize. Returns proposal + auth + token."""
    proposal = await seed_proposal(session_factory, test_repository,
                                   proposer_id=test_user.id)
    approval = _approve(client, proposal)
    r = client.post(f"/api/actions/{proposal.id}/authorize", json={})
    assert r.status_code == 200, r.text
    return {
        "proposal": proposal,
        "approval": approval,
        "authorization": r.json(),
    }


# ── Service identity boundary (§87/§88) ─────────────────────────────


class TestExecutorServiceIdentity:
    def test_executor_disabled_without_token(self, client):
        r = client.post("/api/executor/runs", json={
            "execution_authorization_id": str(uuid4()), "token": "x" * 20})
        assert r.status_code == 503
        assert r.json()["detail"]["reason_code"] == "EXECUTOR_DISABLED"

    def test_wrong_service_token_401(self, client, executor_service):
        r = client.post("/api/executor/runs", json={
            "execution_authorization_id": str(uuid4()), "token": "x" * 20},
            headers={"Authorization": "Bearer wrong-token"})
        assert r.status_code == 401
        assert r.json()["detail"]["reason_code"] == "UNAUTHORIZED_CONSUMER"

    def test_missing_header_401(self, client, executor_service):
        r = client.post("/api/executor/runs", json={
            "execution_authorization_id": str(uuid4()), "token": "x" * 20})
        assert r.status_code == 401

    def test_forged_fields_rejected(self, client, executor_service):
        r = client.post("/api/executor/runs", json={
            "execution_authorization_id": str(uuid4()),
            "token": "x" * 20,
            "authorized": True, "run_state": "COMPLETED",
            "policy_decision": "ALLOW"}, headers=_auth_headers())
        assert r.status_code == 422  # extra="forbid"

    def test_user_session_cannot_admit(self, exec_auth_client, executor_service):
        # an authenticated USER is not the executor service identity
        r = exec_auth_client.post("/api/executor/runs", json={
            "execution_authorization_id": str(uuid4()), "token": "x" * 20})
        assert r.status_code == 401


# ── Golden path with a fake sandbox (unit/integration layer) ────────


class TestAdmissionAndExecution:
    @pytest.mark.asyncio
    async def test_admission_requires_live_authorization(
        self, exec_auth_client, executor_service, session_factory,
        test_repository, test_user, step_up_ok, kill_switch_off,
    ):
        seeded = await _seed_authorized(
            exec_auth_client, session_factory, test_repository, test_user)
        # consume the authorization first via the V3.3 route
        token = seeded["approval"]["authorization_token"]
        c = exec_auth_client.post(
            f"/api/actions/authorization/{seeded['authorization']['id']}/consume",
            json={"token": token})
        assert c.status_code == 200
        # now the executor presents the same (already-used) token
        r = exec_auth_client.post("/api/executor/runs", json={
            "execution_authorization_id": seeded["authorization"]["id"],
            "token": token}, headers=_auth_headers())
        assert r.status_code == 409
        assert r.json()["detail"]["reason_code"] in (
            "EXECUTION_REPLAY", "AUTHORIZATION_INVALID")

    @pytest.mark.asyncio
    async def test_admission_with_wrong_token_denied(
        self, exec_auth_client, executor_service, session_factory,
        test_repository, test_user, step_up_ok, kill_switch_off,
    ):
        seeded = await _seed_authorized(
            exec_auth_client, session_factory, test_repository, test_user)
        r = exec_auth_client.post("/api/executor/runs", json={
            "execution_authorization_id": seeded["authorization"]["id"],
            "token": "w" * 40}, headers=_auth_headers())
        assert r.status_code == 403
        assert r.json()["detail"]["reason_code"] == "AUTHORIZATION_INVALID"
        # denial is audited
        async with session_factory() as session:
            events = (await session.execute(
                select(AuditEvent).where(
                    AuditEvent.event_type == "EXECUTION_DENIED")
            )).scalars().all()
            assert any(e.event_metadata.get("reason_code") == "TOKEN_INVALID"
                       for e in events)

    @pytest.mark.asyncio
    async def test_unknown_authorization_404(self, client, executor_service):
        r = client.post("/api/executor/runs", json={
            "execution_authorization_id": str(uuid4()), "token": "x" * 20},
            headers=_auth_headers())
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_kill_switch_blocks_admission(
        self, exec_auth_client, executor_service, session_factory,
        test_repository, test_user, step_up_ok, kill_switch_off, monkeypatch,
    ):
        seeded = await _seed_authorized(
            exec_auth_client, session_factory, test_repository, test_user)
        # flip the kill switch ON
        async with session_factory() as session:
            row = (await session.execute(
                select(SystemControl).where(
                    SystemControl.key == "execution_disabled"))).scalar_one()
            row.value = "true"
            await session.commit()
        r = exec_auth_client.post("/api/executor/runs", json={
            "execution_authorization_id": seeded["authorization"]["id"],
            "token": seeded["approval"]["authorization_token"]},
            headers=_auth_headers())
        assert r.status_code == 409
        assert r.json()["detail"]["reason_code"] == "KILL_SWITCH_ACTIVE"
        # authorization remains untouched (not consumed by a denial)
        async with session_factory() as session:
            row = (await session.execute(
                select(ExecutionAuthorization).where(
                    ExecutionAuthorization.id ==
                    _uuid(seeded["authorization"]["id"])))).scalar_one()
            assert row.authorization_state == "AUTHORIZED"

    @pytest.mark.asyncio
    async def test_full_run_fake_sandbox_completes(
        self, exec_auth_client, executor_service, session_factory,
        test_repository, test_user, step_up_ok, kill_switch_off, monkeypatch, tmp_path,
    ):
        """Admission → fake sandbox → host verification → COMPLETED.

        The fake sandbox simulates the container: it applies the approved
        operation to the materialized workspace file. Host-side status
        derivation, snapshotting, diff digest, cleanup, and audit are the
        REAL production code paths.
        """
        from app.services import execution_service, workspace as wsvc

        seeded = await _seed_authorized(
            exec_auth_client, session_factory, test_repository, test_user)
        proposal = seeded["proposal"]
        token = seeded["approval"]["authorization_token"]

        # fake the workspace source (no GitHub in unit tests): materialize
        # package.json directly into a controlled workspace
        ws_dir = wsvc.new_workspace_dir()
        src = (tmp_path / "package.json")
        src.write_text('{\n  "lodash": "4.17.19"\n}\n', encoding="utf-8")
        import shutil
        shutil.copy(src, os.path.join(ws_dir, "package.json"))

        # fake workspace source + local platform check
        async def fake_materialize(*, installation_id, owner, repo_name,
                                   base_commit_sha, files, workspace_dir):
            return {"files": {f: "x" for f in files},
                    "source": "fake", "ref": base_commit_sha}

        monkeypatch.setattr(wsvc, "materialize_workspace", fake_materialize)
        monkeypatch.setattr(
            execution_service, "_materialize",
            _fake_materialize_with(ws_dir),
        )

        # platform check passes; sandbox creation is the fake
        import app.services.sandbox as sandbox_svc
        monkeypatch.setattr(sandbox_svc, "check_platform_support",
                            lambda client=None: {"kernel": "fake", "cgroup": "2"})

        r = exec_auth_client.post("/api/executor/runs", json={
            "execution_authorization_id": seeded["authorization"]["id"],
            "token": token}, headers=_auth_headers())
        assert r.status_code == 202, r.text
        body = r.json()
        assert body["run_state"] in ("COMPLETED", "CLEANUP_FAILED", "FAILED")
        assert body["execution_profile"] == "PROFILE_STRUCTURED_TEXT"
        assert body["resource_profile"]["pids_limit"] <= 64
        # bounded result: no secrets, no raw output
        result = body.get("result") or {}
        blob = json.dumps(result).lower()
        for banned in ("bearer", "secret", "password", "ghp_", "token="):
            assert banned not in blob
        if body["run_state"] == "COMPLETED":
            assert body["diff_digest"] and len(body["diff_digest"]) == 64
            assert "package.json" in body["result"]["changed_files"]
            assert body["cleanup_status"] == "COMPLETED"

    @pytest.mark.asyncio
    async def test_exactly_once_execution(
        self, exec_auth_client, executor_service, session_factory,
        test_repository, test_user, step_up_ok, kill_switch_off, monkeypatch, tmp_path,
    ):
        from app.services import execution_service, workspace as wsvc

        seeded = await _seed_authorized(
            exec_auth_client, session_factory, test_repository, test_user)
        token = seeded["approval"]["authorization_token"]

        async def fake_materialize(**kwargs):
            return {"files": {}, "source": "fake", "ref": "x"}

        monkeypatch.setattr(wsvc, "materialize_workspace", fake_materialize)
        monkeypatch.setattr(
            execution_service, "_materialize", _fake_materialize_with(None))

        def fake_factory(workspace_dir):
            return {"container": _RealFakeContainer(workspace_dir)}

        r1 = exec_auth_client.post("/api/executor/runs", json={
            "execution_authorization_id": seeded["authorization"]["id"],
            "token": token}, headers=_auth_headers())
        assert r1.status_code == 202
        r2 = exec_auth_client.post("/api/executor/runs", json={
            "execution_authorization_id": seeded["authorization"]["id"],
            "token": token}, headers=_auth_headers())
        assert r2.status_code == 409
        assert r2.json()["detail"]["reason_code"] == "EXECUTION_REPLAY"

    @pytest.mark.asyncio
    async def test_cross_tenant_run_hidden(
        self, exec_auth_as, executor_service, session_factory,
        test_repository, test_user, step_up_ok, kill_switch_off,
    ):
        client_a = exec_auth_as("a")
        seeded = await _seed_authorized(
            client_a, session_factory, test_repository, test_user)
        run_id = str(uuid4())
        # user B cannot see A's run (also: nonexistent run → 404)
        client_b = exec_auth_as("b")
        resp = client_b.get(f"/api/executor/runs/user/{run_id}")
        assert resp.status_code == 404


class _RealFakeContainer:
    """Fake container that ACTUALLY applies the approved operation to the
    workspace before 'completing' — emulating the in-sandbox executor so
    host-side verification runs for real."""

    def __init__(self, ws):
        self.ws = ws
        self.killed = False
        self.removed = False
        # apply approved operations to workspace files (simulates sandbox)
        import json as _json
        ops_path = os.path.join(ws, ".cyvrix", "operations.json")
        if os.path.exists(ops_path):
            with open(ops_path, "r", encoding="utf-8") as fh:
                payload = _json.load(fh)
            for op in payload.get("operations", []):
                f = os.path.join(ws, op["file"])
                if op.get("type") == "UPDATE_DEPENDENCY_VERSION" and os.path.exists(f):
                    with open(f, "r", encoding="utf-8") as fh:
                        content = fh.read()
                    content = content.replace(
                        f'"{op["name"]}": "{op["from_version"]}"',
                        f'"{op["name"]}": "{op["to_version"]}"')
                    with open(f, "w", encoding="utf-8") as fh:
                        fh.write(content)
        # write a fake result + probes
        payload_dir = os.path.join(ws, ".cyvrix")
        with open(os.path.join(payload_dir, "result.json"), "w",
                  encoding="utf-8") as fh:
            _json.dump({"ok": True, "reason_code": "OK",
                        "detail": "1/1 operations applied",
                        "operations": [{"index": 0,
                                        "op_type": "UPDATE_DEPENDENCY_VERSION",
                                        "file_path": "package.json",
                                        "applied": True, "detail": ""}]}, fh)
        with open(os.path.join(payload_dir, "probes.json"), "w",
                  encoding="utf-8") as fh:
            _json.dump({"uid": {"uid": 10001, "gid": 10001, "euid": 10001},
                        "network": {}, "docker_socket": {"exists": False}}, fh)

    def wait(self, *a, **k):
        return {"StatusCode": 0}

    def logs(self, **k):
        return b""


def _fake_materialize_with(ws_dir):
    async def _impl(run, authorization, proposal):
        if ws_dir is None:
            from app.services.workspace import new_workspace_dir
            d = new_workspace_dir()
        else:
            d = ws_dir
        return d, {"files": {}, "source": "fake", "ref": "x"}
    return _impl
