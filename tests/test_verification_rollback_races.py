"""CYVRIX V3.6 — verification/rollback races and real-remote integration.

Real PostgreSQL, real Redis, REAL git transport (git-over-HTTP against an
in-process instance of the repository's own mock provider — the same
receive-pack / branch-readback / PR endpoints used by the e2e stack). Only
the container layer is faked (deterministic in-process executor); every
other code path (plan freezing, credential issuance, git fetch/push,
remote verification, PR creation/verification, state machine, audit) is
the REAL production code.

Race classes (release gate ≥10 reps each):
- verification start × verification start    (exactly-once verdict record)
- verification execute × verification execute (single serialized verdict)
- rollback start × rollback start            (exactly-once rollback record)
- rollback start × kill-switch flip          (fail closed)
- rollback start × verification start        (mixed-op race, no corruption)
- rollback execute × rollback execute        (single pipeline; no duplicate
                                              revert branch/commit)
- rollback execute × remote branch movement  (CONFLICT; revert branch must
                                              never be created)

Gated behind RUN_INTEGRATION_TESTS=1 (same pattern as V3.2–V3.5 races).
"""
import asyncio
import subprocess
import sys
import os
import tempfile
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION_TESTS") != "1",
    reason="V3.6 races require RUN_INTEGRATION_TESTS=1 and a dedicated real PostgreSQL/Redis",
)

from sqlalchemy import select, func, update
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import get_settings
from app.models import (
    ExecutionRun, GitRemediation, RollbackRun, SystemControl,
    VerificationCheck, VerificationRun,
)

# Reuse the (now real-environment-proven) V3.5 harness: mock remote,
# simultaneous-fire helper, full-chain seeding, and digest computation.
from test_git_remediation_races import (  # noqa: E402
    _ExecutorSandbox, _MockGitRemote, _fire_simultaneous, _remote_main_sha,
    _seed_authorized_run,
)
from test_git_remediation import EXECUTOR_TOKEN  # noqa: E402

REPETITIONS = 10
REP_IDS = list(range(REPETITIONS))

REPO_FILES = {
    "package.json": '{\n  "lodash": "4.17.19"\n}\n',
    "README.md": "# race6\n",
}


# ── Real-PG / real-Redis fixtures (same pattern as V3.5 races) ───────


@pytest.fixture(scope="module")
async def real_engine():
    settings = get_settings()
    if "sqlite" in settings.database_url:
        pytest.skip("PostgreSQL required for race tests")
    if not settings.secret_key:
        pytest.skip("SECRET_KEY required for race tests")
    eng = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
    yield eng
    await eng.dispose()


@pytest.fixture
async def session_factory(real_engine):
    return async_sessionmaker(real_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture
async def clean_db(real_engine):
    from app.database import Base

    async with real_engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(table.delete())
        await conn.execute(
            SystemControl.__table__.insert().values(
                key="execution_disabled", value="false"
            )
        )
        # V3.7: provision the operational_state row exactly as migration
        # 010 does in production (fail-closed parity; the ops gate's
        # missing/unreadable fail-closed behavior has dedicated tests).
        await conn.execute(
            SystemControl.__table__.insert().values(
                key="operational_state", value="NORMAL"
            )
        )
    yield


@pytest.fixture
async def redis_client():
    import redis.asyncio as aioredis

    r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    try:
        await r.ping()
    except Exception:
        await r.aclose()
        pytest.skip("Redis required for race tests")
    yield r
    await r.aclose()


@pytest.fixture(autouse=True)
async def _reset_redis_pool():
    import app.session as session_module
    session_module._redis_pool = None
    yield
    session_module._redis_pool = None


@pytest.fixture(scope="module")
def git_remote():
    remote = _MockGitRemote()
    remote.start()
    # The mock server module reads REPOS_DIR/FIXTURE_DIR at import time;
    # if another race module already imported it with different dirs,
    # rebind the globals so this module's repos are served.
    sys.path.insert(0, os.path.join(
        os.path.dirname(__file__), "..", "services", "mock-providers"))
    import server as mock_server
    mock_server.REPOS_DIR = remote.repos_dir
    mock_server.FIXTURE_DIR = remote.fixtures_dir
    mock_server._initialized_repos.clear()
    yield remote
    remote.stop()


def pipeline_env(monkeypatch, git_remote):
    """Fake the container layer only; keep every git/credential path real.

    Mirrors the V3.5 races: point the GitHub API + remote base at the
    in-process mock provider (patching app.services.github's import-time
    module global) and widen the git transport allowlist for local http.
    """
    from app.services import execution_service, git_ops
    import app.services.sandbox as sandbox_svc
    import app.services.github as github_svc
    import app.services.git_remediation_service as rem_svc

    async def fake_materialize_run(run, authorization, proposal):
        from app.services.workspace import new_workspace_dir
        return new_workspace_dir(), {"files": {}, "source": "fake", "ref": "x"}

    monkeypatch.setenv("GITHUB_API_BASE", git_remote.api_base)
    monkeypatch.setenv("GITHUB_REMOTE_BASE", git_remote.api_base)
    monkeypatch.setattr(github_svc, "GITHUB_API", git_remote.api_base)
    monkeypatch.setattr(github_svc, "_create_jwt", lambda: "mock-jwt")
    monkeypatch.setattr(git_ops, "GIT_ALLOWED_PROTOCOLS", "https:http")
    monkeypatch.setattr(execution_service, "_materialize", fake_materialize_run)
    monkeypatch.setattr(sandbox_svc, "check_platform_support",
                        lambda client=None: {"kernel": "fake", "cgroup": "2"})
    monkeypatch.setattr(sandbox_svc, "create_sandbox",
                        lambda ws, *a, **k: {"container": _ExecutorSandbox(ws)})
    monkeypatch.setattr(rem_svc, "GITHUB_REMOTE_BASE", None, raising=False)
    return None


@pytest.fixture
async def owners(clean_db, session_factory, redis_client):
    from app.models import GithubInstallation, Repository, User

    async with session_factory() as session:
        ua = User(email=f"race6-a-{uuid4_hex()[:8]}@test.com", github_id=8_600_001)
        ub = User(email=f"race6-b-{uuid4_hex()[:8]}@test.com", github_id=8_600_002)
        session.add_all([ua, ub])
        await session.flush()
        inst = GithubInstallation(
            user_id=ua.id, installation_id=8_650_001,
            account_login="race6-org", account_type="Organization",
        )
        session.add(inst)
        await session.flush()
        repo = Repository(
            installation_id=inst.id, github_repo_id=8_660_001,
            owner="race6-org", name="race6-repo", default_branch="main",
            is_active=True,
        )
        session.add(repo)
        await session.commit()
        await session.refresh(repo)
        data = {"a": ua, "b": ub, "repo": repo, "a_id": str(ua.id),
                "b_id": str(ub.id)}

    now = str(int(datetime.now(timezone.utc).timestamp()))
    await redis_client.set(f"stepup:{data['a_id']}", now)
    await redis_client.set(f"stepup:{data['b_id']}", now)
    yield data
    await redis_client.delete(f"stepup:{data['a_id']}", f"stepup:{data['b_id']}")


def uuid4_hex() -> str:
    from uuid import uuid4
    return uuid4().hex


@pytest.fixture
async def api_client(owners):
    """Real ASGI app + real-PG sessions; owner A authenticated."""
    from httpx import ASGITransport, AsyncClient

    import app.session as app_session
    import app.routes.actions as actions_routes
    import app.routes.approvals as approvals_routes
    import app.routes.execution_authorization as ea_routes
    import app.routes.git_remediation as rem_routes
    import app.routes.execution_runs as exec_runs
    import app.routes.verification_rollback as vrb_routes
    from app.auth import get_current_user
    from app.database import get_db
    from app.main import app

    app_session._redis_pool = None
    engine = create_async_engine(get_settings().database_url, echo=False,
                                 poolclass=NullPool)
    SessionLocal = async_sessionmaker(engine, class_=AsyncSession,
                                      expire_on_commit=False)

    async def override_get_db():
        async with SessionLocal() as session:
            yield session

    async def raw_rate_limit(key, max_requests, window_seconds):
        return True, {}

    settings = get_settings()
    prev_token = settings.executor_service_token
    settings.executor_service_token = EXECUTOR_TOKEN
    headers = {"Authorization": f"Bearer {EXECUTOR_TOKEN}"}

    approver = owners["a"]

    async def override_get_current_user():
        return approver

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user
    # Patch each route module's check_rate_limit reference (wrappers keep
    # running and keep returning the User — see V3.5 race fix).
    patched = []
    for mod in (actions_routes, approvals_routes, ea_routes, rem_routes,
                exec_runs, vrb_routes):
        patched.append((mod, mod.check_rate_limit))
        mod.check_rate_limit = raw_rate_limit

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver",
                           headers=headers) as c:
        yield c

    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_current_user, None)
    for mod, real in patched:
        mod.check_rate_limit = real
    settings.executor_service_token = prev_token
    app_session._redis_pool = None
    await engine.dispose()


@pytest.fixture
def pipeline(monkeypatch, git_remote):
    return pipeline_env(monkeypatch, git_remote)


# ── Shared pipeline: verified run → remediation → push → PR ──────────


async def _pushed_remediation(api_client, session_factory, owners,
                              git_remote) -> tuple[dict, str]:
    base_url = git_remote.seed_repo("race6-repo", REPO_FILES)
    base_sha = _remote_main_sha(base_url, "race6-repo")
    chain = await _seed_authorized_run(api_client, session_factory,
                                       owners["repo"], owners["a"].id,
                                       base_commit_sha=base_sha)
    r = await api_client.post(
        f"/api/actions/runs/{chain['run_id']}/remediation", json={})
    assert r.status_code == 201, r.text
    rem_id = r.json()["id"]
    r = await api_client.post(f"/api/executor/remediations/{rem_id}/execute")
    assert r.status_code == 200, r.text
    rem = r.json()
    assert rem["remediation_state"] == "PR_CREATED", rem
    return rem, base_sha


async def _start_verification(api_client, remediation_id: str):
    return await api_client.post(
        f"/api/remediations/{remediation_id}/verification", json={})


async def _start_rollback(api_client, remediation_id: str):
    return await api_client.post(
        f"/api/remediations/{remediation_id}/rollback", json={})


async def _flip_kill_switch(session_factory, value: str) -> None:
    async with session_factory() as session:
        await session.execute(
            update(SystemControl)
            .where(SystemControl.key == "execution_disabled")
            .values(value=value))
        await session.commit()


# ── Race 1: verification start × verification start ──────────────────


@pytest.mark.parametrize("rep", REP_IDS)
@pytest.mark.asyncio
async def test_verification_start_race_exactly_one(
    rep, api_client, session_factory, owners, pipeline, git_remote,
):
    rem, _ = await _pushed_remediation(api_client, session_factory, owners,
                                       git_remote)
    results = await _fire_simultaneous([
        lambda: _start_verification(api_client, rem["id"]) for _ in range(6)
    ])
    created = [r for r in results if r.status_code == 201]
    assert len(created) == 1, [r.status_code for r in results]
    for r in results:
        if r.status_code != 201:
            assert r.status_code == 409, r.text
            assert r.json()["detail"].get("reason_code") == "VERIFICATION_REPLAY"
    async with session_factory() as session:
        total = (await session.execute(
            select(func.count()).select_from(VerificationRun).where(
                VerificationRun.git_remediation_id ==
                __import__("uuid").UUID(rem["id"])))).scalar()
        assert total == 1


# ── Race 2: verification execute × verification execute ──────────────


@pytest.mark.parametrize("rep", REP_IDS)
@pytest.mark.asyncio
async def test_verification_execute_race_single_verdict(
    rep, api_client, session_factory, owners, pipeline, git_remote,
):
    rem, _ = await _pushed_remediation(api_client, session_factory, owners,
                                       git_remote)
    r = await _start_verification(api_client, rem["id"])
    assert r.status_code == 201, r.text
    v = r.json()

    results = await _fire_simultaneous([
        lambda: api_client.post(
            f"/api/executor/verifications/{v['id']}/execute")
        for _ in range(5)
    ])
    for r in results:
        assert r.status_code == 200, r.text
    # The verdict is written exactly once and never rewritten
    async with session_factory() as session:
        row = (await session.execute(
            select(VerificationRun).where(
                VerificationRun.id == __import__("uuid").UUID(v["id"]))
        )).scalar_one()
        assert row.verification_state == "COMPLETED", row.verification_state
        assert row.result in ("PASS", "FAIL"), row.result
        final_result = row.result
        checks = (await session.execute(
            select(VerificationCheck.check_type).where(
                VerificationCheck.verification_run_id == row.id)
        )).scalars().all()
        assert len(checks) == len(set(checks)), "duplicate check rows"
        assert row.checks_total == len(checks)
    # Every loser observes the same final verdict (never a stale PASS)
    for r in results:
        body = r.json()
        if body.get("verification_state") == "COMPLETED":
            assert body["result"] == final_result


# ── Race 3: rollback start × rollback start ──────────────────────────


@pytest.mark.parametrize("rep", REP_IDS)
@pytest.mark.asyncio
async def test_rollback_start_race_exactly_one(
    rep, api_client, session_factory, owners, pipeline, git_remote,
):
    rem, _ = await _pushed_remediation(api_client, session_factory, owners,
                                       git_remote)
    results = await _fire_simultaneous([
        lambda: _start_rollback(api_client, rem["id"]) for _ in range(6)
    ])
    created = [r for r in results if r.status_code == 201]
    assert len(created) == 1, [r.status_code for r in results]
    for r in results:
        if r.status_code != 201:
            assert r.status_code == 409, r.text
            assert r.json()["detail"].get("reason_code") == "ROLLBACK_REPLAY"
    async with session_factory() as session:
        total = (await session.execute(
            select(func.count()).select_from(RollbackRun).where(
                RollbackRun.git_remediation_id ==
                __import__("uuid").UUID(rem["id"])))).scalar()
        assert total == 1
        # Server-derived target: the frozen contract's base SHA
        row = (await session.execute(select(RollbackRun))).scalar_one()
        assert row.rollback_target_sha == rem["base_commit_sha"]
        assert row.expected_branch_sha == rem["pushed_sha"]


# ── Race 4: rollback start × kill-switch flip ────────────────────────


@pytest.mark.parametrize("rep", REP_IDS)
@pytest.mark.asyncio
async def test_rollback_start_vs_kill_switch(
    rep, api_client, session_factory, owners, pipeline, git_remote,
):
    rem, _ = await _pushed_remediation(api_client, session_factory, owners,
                                       git_remote)

    async def _flip():
        await _flip_kill_switch(session_factory, "true")

    results = await _fire_simultaneous([
        lambda: _start_rollback(api_client, rem["id"]),
        lambda: _flip(),
    ])
    responses = [r for r in results if r is not None
                 and not isinstance(r, Exception)]
    created = any(r.status_code == 201 for r in responses)
    denied = any(r.status_code == 409
                 and r.json()["detail"].get("reason_code") == "KILL_SWITCH_ACTIVE"
                 for r in responses)
    assert created != denied or (not created and not denied), results
    async with session_factory() as session:
        rows = (await session.execute(select(RollbackRun))).scalars().all()
        assert len(rows) <= 1
        if rows and denied and not created:
            assert False, "rollback created despite kill switch winning"


# ── Race 5: rollback start × verification start (mixed-op) ───────────


@pytest.mark.parametrize("rep", REP_IDS)
@pytest.mark.asyncio
async def test_rollback_start_vs_verification_start(
    rep, api_client, session_factory, owners, pipeline, git_remote,
):
    rem, _ = await _pushed_remediation(api_client, session_factory, owners,
                                       git_remote)
    results = await _fire_simultaneous([
        lambda: _start_verification(api_client, rem["id"]),
        lambda: _start_rollback(api_client, rem["id"]),
    ])
    for r in results:
        assert r.status_code in (201, 409), r.text
    async with session_factory() as session:
        v_total = (await session.execute(
            select(func.count()).select_from(VerificationRun))).scalar()
        rb_total = (await session.execute(
            select(func.count()).select_from(RollbackRun))).scalar()
        assert v_total <= 1 and rb_total <= 1
        # Both records may coexist; neither may be terminal from a start
        for row in (await session.execute(
                select(VerificationRun))).scalars().all():
            assert row.verification_state == "PENDING"
        for row in (await session.execute(
                select(RollbackRun))).scalars().all():
            assert row.rollback_state == "PENDING"


# ── Race 6: rollback execute × rollback execute ──────────────────────


@pytest.mark.parametrize("rep", REP_IDS)
@pytest.mark.asyncio
async def test_rollback_execute_race_single_pipeline(
    rep, api_client, session_factory, owners, pipeline, git_remote,
):
    rem, _ = await _pushed_remediation(api_client, session_factory, owners,
                                       git_remote)
    r = await _start_rollback(api_client, rem["id"])
    assert r.status_code == 201, r.text
    rb = r.json()

    results = await _fire_simultaneous([
        lambda: api_client.post(
            f"/api/executor/rollbacks/{rb['id']}/execute")
        for _ in range(4)
    ])
    for r in results:
        assert r.status_code == 200, r.text

    async with session_factory() as session:
        row = (await session.execute(
            select(RollbackRun).where(
                RollbackRun.id == __import__("uuid").UUID(rb["id"]))
        )).scalar_one()
        assert row.rollback_state == "COMPLETED", (
            row.rollback_state, row.fail_reason_code)
        assert row.revert_sha, row
        assert row.cleanup_status == "COMPLETED"

    # Exactly ONE revert branch on the remote, at the revert SHA
    out = subprocess.run(
        ["git", "ls-remote", f"{git_remote.api_base}/race6-org/race6-repo.git",
         f"refs/heads/{row.revert_branch}"], capture_output=True)
    assert out.returncode == 0
    lines = out.stdout.decode().splitlines()
    assert len(lines) == 1, lines
    assert row.revert_sha in lines[0]
    # Revert PR exists and points at the revert branch/SHA
    import httpx
    async with httpx.AsyncClient() as hc:
        pr = (await hc.get(
            f"{git_remote.api_base}/repos/race6-org/race6-repo/pulls/"
            f"{row.revert_pr_number}")).json()
    assert pr["head"]["ref"] == row.revert_branch
    assert pr["head"]["sha"] == row.revert_sha


# ── Race 7: rollback execute × remote branch movement ────────────────


@pytest.mark.parametrize("rep", REP_IDS)
@pytest.mark.asyncio
async def test_rollback_execute_vs_branch_movement(
    rep, api_client, session_factory, owners, pipeline, git_remote,
):
    rem, _ = await _pushed_remediation(api_client, session_factory, owners,
                                       git_remote)
    r = await _start_rollback(api_client, rem["id"])
    assert r.status_code == 201, r.text
    rb = r.json()

    # Developer push moves the remediation branch (fast-forward append)
    tmp = tempfile.mkdtemp(prefix=f"v36race-move-{rep}-")

    def _git(*args, cwd=None):
        out = subprocess.run(["git", *args], cwd=cwd, capture_output=True)
        assert out.returncode == 0, (
            args, out.stdout.decode(errors="replace")[:300],
            out.stderr.decode(errors="replace")[:300])
        return out
        return out

    _git("clone", "-q", f"{git_remote.api_base}/race6-org/race6-repo.git", tmp)
    _git("-C", tmp, "fetch", "-q", "origin", rem["remediation_branch"])
    _git("-C", tmp, "checkout", "-q", "-b", "work",
         "origin/" + rem["remediation_branch"])
    with open(os.path.join(tmp, "dev.txt"), "w") as fh:
        fh.write("developer change")
    _git("-C", tmp, "add", ".")
    _git("-C", tmp, "-c", "user.name=D", "-c", "user.email=d@d",
         "commit", "-qm", "dev push")
    _git("-C", tmp, "push", "-q", "origin",
         f"work:{rem['remediation_branch']}")

    r = await api_client.post(f"/api/executor/rollbacks/{rb['id']}/execute")
    assert r.status_code == 200, r.text
    result = r.json()
    assert result["rollback_state"] == "CONFLICT", result
    assert result["fail_reason_code"] == "ROLLBACK_STATE_MISMATCH"
    assert result["revert_sha"] is None

    # FAIL CLOSED: no revert branch may exist on the remote
    out = subprocess.run(
        ["git", "ls-remote", f"{git_remote.api_base}/race6-org/race6-repo.git",
         f"refs/heads/{rb['revert_branch']}"], capture_output=True)
    assert out.returncode == 0
    assert out.stdout.decode().strip() == "", out.stdout.decode()
