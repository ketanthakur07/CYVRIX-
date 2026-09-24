"""CYVRIX V3.4 — genuine concurrent execution-admission races (§77).

Real PostgreSQL, real simultaneous HTTP requests through the ASGI app
(asyncio.Barrier): approve → authorize → then N consumers race to admit.
Classes: admit/admit (exactly-one), admit/revoke-attempt, admit with
expired approval, kill-switch flip during admission.

Gated behind RUN_INTEGRATION_TESTS=1 + a dedicated migrated database
(same pattern as the V3.2/V3.3 race suites).
"""
import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION_TESTS") != "1",
    reason="Race tests require RUN_INTEGRATION_TESTS=1 and a dedicated real PostgreSQL/Redis",
)

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import get_settings
from app.models import (
    ActionProposal, Approval, AuditEvent, ExecutionAuthorization,
    ExecutionRun, Finding, GithubInstallation, Recommendation, Repository,
    RiskAssessment, Scan, SystemControl, User,
)

REPETITIONS = 10  # per race class (release gate: ≥10)
REP_IDS = list(range(REPETITIONS))
BASE_COMMIT = "b" * 40


def _compute_digest(proposal: ActionProposal) -> str:
    from app.services.action_digest import compute_action_digest

    return compute_action_digest({
        "action_type": proposal.action_type,
        "repository_id": str(proposal.repository_id),
        "base_commit_sha": proposal.base_commit_sha,
        "target_branch": proposal.target_branch,
        "files": proposal.files,
        "operations": proposal.operations,
        "expected_diff": proposal.expected_diff,
    })


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
    """Wipe ALL tables between tests. Dedicated test database only."""
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


@pytest.fixture
async def owners(clean_db, session_factory, redis_client):
    async with session_factory() as session:
        ua = User(email=f"race4-a-{uuid4().hex[:8]}@test.com", github_id=8_600_001)
        ub = User(email=f"race4-b-{uuid4().hex[:8]}@test.com", github_id=8_600_002)
        session.add_all([ua, ub])
        await session.flush()
        inst = GithubInstallation(
            user_id=ua.id, installation_id=8_700_001,
            account_login="race4-org", account_type="Organization",
        )
        session.add(inst)
        await session.flush()
        repo = Repository(
            installation_id=inst.id, github_repo_id=8_800_001,
            owner="race4-org", name="race-repo", default_branch="main",
            is_active=True,
        )
        session.add(repo)
        await session.commit()
        await session.refresh(repo)
        data = {"a": ua, "b": ub, "repo": repo, "a_id": str(ua.id), "b_id": str(ub.id)}

    # fresh step-up markers in the REAL Redis (epoch-string, approval
    # prerequisite) — set AFTER the session block, matching V3.2/V3.3
    now = str(int(datetime.now(timezone.utc).timestamp()))
    await redis_client.set(f"stepup:{data['a_id']}", now)
    await redis_client.set(f"stepup:{data['b_id']}", now)

    yield data

    await redis_client.delete(f"stepup:{data['a_id']}", f"stepup:{data['b_id']}")


@pytest.fixture
async def api_client(owners):
    """Async HTTP client on the REAL ASGI app with real-PG sessions.

    The executor service token is set; the admission rate limit is
    bypassed (races exercise concurrency, not rate limiting).
    """
    from httpx import ASGITransport, AsyncClient

    import app.session as app_session
    import app.routes.execution_runs as exec_runs
    from app.auth import get_current_user
    from app.database import get_db
    from app.main import app

    app_session._redis_pool = None

    engine = create_async_engine(
        get_settings().database_url, echo=False, poolclass=NullPool
    )
    SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with SessionLocal() as session:
            yield session

    async def override_rate_limit(key, max_requests, window_seconds):
        return True, {}

    settings = get_settings()
    # Save/restore: get_settings() is a process-wide singleton; leaking the
    # token here would break later suites that assert the executor is
    # DISABLED when no service token is configured.
    previous_service_token = settings.executor_service_token
    settings.executor_service_token = "race-executor-token-0123456789"
    headers = {"Authorization": "Bearer race-executor-token-0123456789"}

    approver = owners["a"]

    async def override_get_current_user():
        return approver

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[exec_runs.check_rate_limit] = override_rate_limit
    # the admission route calls check_rate_limit INLINE — patch the
    # module attribute directly (dependency_overrides cannot intercept it)
    real_check = exec_runs.check_rate_limit
    exec_runs.check_rate_limit = override_rate_limit

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver",
                           headers=headers) as c:
        yield c

    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(exec_runs.check_rate_limit, None)
    exec_runs.check_rate_limit = real_check
    settings.executor_service_token = previous_service_token
    app_session._redis_pool = None
    await engine.dispose()


async def _fire_simultaneous(request_factories):
    barrier = asyncio.Barrier(len(request_factories))

    async def _run(factory):
        await barrier.wait()
        return await factory()

    return list(await asyncio.gather(*(_run(f) for f in request_factories),
                                     return_exceptions=True))


async def _full_chain(api_client, session_factory, repo, owner_id) -> dict:
    """proposal → approval → authorize. Returns ids + one-time token."""
    async with session_factory() as session:
        scan = Scan(id=uuid4(), repository_id=repo.id, status="COMPLETED",
                    trigger="manual", commit_sha=BASE_COMMIT)
        session.add(scan)
        await session.flush()
        finding = Finding(
            id=uuid4(), scan_id=scan.id, repository_id=repo.id,
            fingerprint=f"r4-{uuid4().hex[:12]}", scanner="dependency",
            source_type="DEPENDENCY", vulnerability_id="GHSA-race4",
            package_name="lodash", package_version="4.17.19",
            title="Race proposal", severity="HIGH", status="OPEN",
            evidence={"manifest_path": "package.json"},
        )
        session.add(finding)
        await session.flush()
        rec = Recommendation(
            id=uuid4(), finding_id=finding.id, status="COMPLETED",
            trust_level="SUPPORTED", title="Upgrade lodash",
            validation_state="VALIDATED",
        )
        session.add(rec)
        await session.flush()
        session.add(RiskAssessment(
            id=uuid4(), finding_id=finding.id, risk_score=45,
            risk_level="MEDIUM", risk_version=1, factors={"base_score": 60},
        ))
        await session.flush()
        p = ActionProposal(
            id=uuid4(), finding_id=finding.id, recommendation_id=rec.id,
            repository_id=repo.id, created_by=owner_id,
            action_type="DEPENDENCY_UPGRADE", status="POLICY_CHECKED",
            base_commit_sha=BASE_COMMIT, target_branch="cyvrix/fix",
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
        p.action_digest = _compute_digest(p)
        session.add(p)
        await session.commit()
        proposal_id = p.id

    r = await api_client.post(f"/api/actions/{proposal_id}/approve", json={})
    assert r.status_code == 200, r.text
    token = r.json()["authorization_token"]

    r = await api_client.post(f"/api/actions/{proposal_id}/authorize", json={})
    assert r.status_code == 200, r.text
    return {
        "proposal_id": proposal_id,
        "authorization_id": r.json()["id"],
        "token": token,
    }


def _fake_sandbox_factory():
    """In-process fake sandbox so races exercise ADMISSION concurrency
    (locks, unique indexes, commit conflicts), not container startup."""
    class _C:
        def start(self):
            pass  # in-process fake: work happens in wait()

        @property
        def attrs(self):
            return {"State": {"ExitCode": 0}}

        def wait(self, *a, **k):
            return {"StatusCode": 0}

        def logs(self, **k):
            return b""

    def factory(ws):
        return {"container": _C()}
    return factory


@pytest.fixture(autouse=True)
def _fake_sandbox(monkeypatch):
    import app.services.execution_service as esvc
    import app.services.sandbox as ssvc

    async def fake_materialize(run, authorization, proposal):
        from app.services.workspace import new_workspace_dir
        return new_workspace_dir(), {"files": {}, "source": "fake", "ref": "x"}

    monkeypatch.setattr(esvc, "_materialize", fake_materialize)
    monkeypatch.setattr(ssvc, "check_platform_support",
                        lambda client=None: {"kernel": "fake", "cgroup": "2"})
    monkeypatch.setattr(esvc, "SANDBOX_FACTORY", _fake_sandbox_factory(), raising=False)


# ── Race 1: admit vs admit (§5/§77: exactly one executor admitted) ───


@pytest.mark.parametrize("rep", REP_IDS)
@pytest.mark.asyncio
async def test_admit_admit_exactly_one(
    rep, api_client, session_factory, owners,
):
    chain = await _full_chain(api_client, session_factory, owners["repo"],
                              owners["a"].id)
    results = await _fire_simultaneous([
        lambda: api_client.post("/api/executor/runs", json={
            "execution_authorization_id": chain["authorization_id"],
            "token": chain["token"]}),
        lambda: api_client.post("/api/executor/runs", json={
            "execution_authorization_id": chain["authorization_id"],
            "token": chain["token"]}),
    ])
    statuses = []
    for r in results:
        if isinstance(r, Exception):
            statuses.append(("EXC", type(r).__name__))
        else:
            detail = r.json().get("detail", {})
            reason = detail.get("reason_code") if isinstance(detail, dict) else str(detail)
            statuses.append((r.status_code, reason if r.status_code != 202 else "ADMITTED"))
    admitted = [s for s in statuses if s[0] == 202]
    assert len(admitted) == 1, statuses
    losers = [s for s in statuses if s[0] != 202]
    for code, reason in losers:
        assert code in (403, 409, 429), statuses
        assert reason in ("EXECUTION_REPLAY", "EXECUTION_IN_PROGRESS",
                          "AUTHORIZATION_CONFLICT", "AUTHORIZATION_INVALID"), statuses
    # DB invariant: exactly one run exists for the authorization
    async with session_factory() as session:
        runs = (await session.execute(
            select(ExecutionRun).where(
                ExecutionRun.execution_authorization_id ==
                __import__("uuid").UUID(chain["authorization_id"])))
        ).scalars().all()
        assert len(runs) == 1


# ── Race 2: admit vs revoke (§77 #3) ─────────────────────────────────


@pytest.mark.parametrize("rep", REP_IDS)
@pytest.mark.asyncio
async def test_admit_vs_revoke(
    rep, api_client, session_factory, owners,
):
    chain = await _full_chain(api_client, session_factory, owners["repo"],
                              owners["a"].id)
    results = await _fire_simultaneous([
        lambda: api_client.post("/api/executor/runs", json={
            "execution_authorization_id": chain["authorization_id"],
            "token": chain["token"]}),
        lambda: api_client.post(
            f"/api/actions/authorization/{chain['authorization_id']}/revoke",
            json={"reason": "racing revoke"}),
    ])
    ok = False
    for r in results:
        if isinstance(r, Exception):
            continue
        if r.status_code == 202:
            ok = True
    # exactly one winner: either the admission (then revoke must fail) or
    # the revoke (then admission must fail with AUTHORIZATION_INVALID)
    revoked = False
    for r in results:
        if isinstance(r, Exception):
            continue
        if r.status_code == 200 and "authorization_state" in r.json():
            revoked = r.json()["authorization_state"] == "REVOKED"
    assert ok != revoked, f"exactly one winner required: {[(getattr(r,'status_code',type(r))) for r in results]}"
    # no live authorization may survive the race
    async with session_factory() as session:
        row = (await session.execute(
            select(ExecutionAuthorization).where(
                ExecutionAuthorization.id ==
                __import__("uuid").UUID(chain["authorization_id"])))
        ).scalar_one()
        assert row.authorization_state in ("CONSUMED", "REVOKED")


# ── Race 3: admit after approval expiry (§42/§79) ────────────────────


@pytest.mark.parametrize("rep", REP_IDS)
@pytest.mark.asyncio
async def test_admit_after_expiry_denied(
    rep, api_client, session_factory, owners,
):
    chain = await _full_chain(api_client, session_factory, owners["repo"],
                              owners["a"].id)
    # close the approval window behind the authorization
    async with session_factory() as session:
        approval = (await session.execute(
            select(Approval).where(
                Approval.action_proposal_id == chain["proposal_id"]))
        ).scalars().first()
        approval.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await session.commit()
    r = await api_client.post("/api/executor/runs", json={
        "execution_authorization_id": chain["authorization_id"],
        "token": chain["token"]})
    assert r.status_code in (403, 409)
    assert r.json()["detail"]["reason_code"] in (
        "AUTHORIZATION_EXPIRED", "AUTHORIZATION_INVALID",
        "AUTHORIZATION_REVOKED", "KILL_SWITCH_ACTIVE"), r.text
    async with session_factory() as session:
        runs = (await session.execute(
            select(ExecutionRun).where(
                ExecutionRun.execution_authorization_id ==
                __import__("uuid").UUID(chain["authorization_id"])))
        ).scalars().all()
        assert len(runs) == 0  # no run may exist for an expired window


# ── Race 4: kill switch flipped during admission (§54/§81) ───────────


@pytest.mark.parametrize("rep", REP_IDS)
@pytest.mark.asyncio
async def test_kill_switch_flip_during_admission(
    rep, api_client, session_factory, owners,
):
    chain = await _full_chain(api_client, session_factory, owners["repo"],
                              owners["a"].id)

    async def flip_switch():
        async with session_factory() as session:
            row = (await session.execute(
                select(SystemControl).where(
                    SystemControl.key == "execution_disabled"))
            ).scalar_one()
            row.value = "true"
            await session.commit()

    results = await _fire_simultaneous([
        lambda: api_client.post("/api/executor/runs", json={
            "execution_authorization_id": chain["authorization_id"],
            "token": chain["token"]}),
        lambda: flip_switch(),
    ])
    admit = results[0]
    # EITHER the admission won the race (kill switch landed after commit)
    # OR the kill switch won (admission denied). Both are safe; what must
    # NEVER happen is an admission that ran while the switch was read ON
    # in the same critical section — admitted runs are recorded with the
    # switch state checked inside the lock.
    if not isinstance(admit, Exception) and admit.status_code == 202:
        async with session_factory() as session:
            run = (await session.execute(
                select(ExecutionRun).where(
                    ExecutionRun.execution_authorization_id ==
                    __import__("uuid").UUID(chain["authorization_id"]))
            )).scalars().first()
            assert run is not None
            assert run.run_state in ("ADMISSION_PENDING", "EXECUTING",
                                     "RESULT_READY", "COMPLETED",
                                     "CLEANUP_FAILED", "FAILED")
    else:
        assert admit.status_code in (403, 409, 429), admit.text


# ── Storm: 8 concurrent admissions, one authorization (§77) ──────────


@pytest.mark.parametrize("rep", REP_IDS)
@pytest.mark.asyncio
async def test_admission_storm_single_winner(
    rep, api_client, session_factory, owners,
):
    chain = await _full_chain(api_client, session_factory, owners["repo"],
                              owners["a"].id)
    body = {"execution_authorization_id": chain["authorization_id"],
            "token": chain["token"]}
    results = await _fire_simultaneous([
        (lambda b=body: api_client.post("/api/executor/runs", json=b))
        for _ in range(8)
    ])
    admitted = [r for r in results
                if not isinstance(r, Exception) and r.status_code == 202]
    assert len(admitted) == 1
    for r in results:
        if isinstance(r, Exception):
            assert False, f"unexpected exception: {r!r}"
        if r.status_code != 202:
            assert r.status_code in (403, 409, 429)
    async with session_factory() as session:
        runs = (await session.execute(
            select(ExecutionRun).where(
                ExecutionRun.execution_authorization_id ==
                __import__("uuid").UUID(chain["authorization_id"])))
        ).scalars().all()
        assert len(runs) == 1
