"""CYVRIX V3.2 — Genuine concurrent approval race tests (real PostgreSQL).

These tests are NOT sequential simulations: two HTTP requests are issued
truly simultaneously (asyncio.gather over a shared barrier) against the
real ASGI app, each with its own PostgreSQL session/transaction, so
server-side concurrency (row locks, partial unique indexes, transaction
isolation, commit races) is genuinely exercised.

Gated behind RUN_INTEGRATION_TESTS=1 + a dedicated migrated database:

    DATABASE_URL=postgresql+asyncpg://cyvrix:cyvrix_dev@localhost:5432/cyvrix_race \\
    REDIS_URL=redis://localhost:6379/0 \\
    SECRET_KEY=<32+ char secret> \\
    RUN_INTEGRATION_TESTS=1 pytest tests/test_approval_races.py

NOTE: these tests WIPE all tables of the configured database between tests.
NEVER point them at a database holding real data.

Documented deterministic outcomes (docs/v3-approval-model.md §7):
- approve vs approve    → exactly one live approval, at most one token
- approve vs reject     → exactly one terminal decision wins; loser gets
                          403/409 or an idempotent mirror; never an
                          APPROVED approval on a REJECTED proposal
- consume vs consume    → exactly one 200; loser gets 403 TOKEN_REPLAY
- revoke vs consume     → terminal state is exactly USED or REVOKED; a
                          revoked approval can never become usable
- approve vs revoke     → no resurrection, no duplicate live approval
"""
import asyncio
import os
import sys
import uuid as uuid_module
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION_TESTS") != "1",
    reason="Race tests require RUN_INTEGRATION_TESTS=1 and a dedicated real PostgreSQL/Redis",
)

from sqlalchemy import select  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession, create_async_engine  # noqa: E402
from sqlalchemy.pool import NullPool  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.models import (  # noqa: E402
    ActionProposal, Approval, AuditEvent, Finding, Recommendation,
    Repository, GithubInstallation, RiskAssessment, Scan, User,
)

REPETITIONS = 10  # per race class (release gate: ≥10)
REP_IDS = list(range(REPETITIONS))


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


# ── Fixtures ─────────────────────────────────────────────────────────


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


@pytest.fixture
async def owners(clean_db, session_factory, redis_client):
    """User A owns repo/proposal; user B exists (off-chain). Step-up fresh."""
    async with session_factory() as session:
        ua = User(email=f"race-a-{uuid4().hex[:8]}@test.com", github_id=8_100_001)
        ub = User(email=f"race-b-{uuid4().hex[:8]}@test.com", github_id=8_100_002)
        session.add_all([ua, ub])
        await session.flush()
        inst = GithubInstallation(
            user_id=ua.id, installation_id=8_200_001,
            account_login="race-org", account_type="Organization",
        )
        session.add(inst)
        await session.flush()
        repo = Repository(
            installation_id=inst.id, github_repo_id=8_300_001,
            owner="race-org", name="repo", default_branch="main", is_active=True,
        )
        session.add(repo)
        await session.commit()
        data = {"a": ua, "b": ub, "a_id": ua.id, "b_id": ub.id, "repo_id": repo.id}

    now = str(int(datetime.now(timezone.utc).timestamp()))
    await redis_client.set(f"stepup:{data['a_id']}", now)
    await redis_client.set(f"stepup:{data['b_id']}", now)

    yield data

    await redis_client.delete(f"stepup:{data['a_id']}", f"stepup:{data['b_id']}")


@pytest.fixture
async def api_client(owners):
    """Async HTTP client on the REAL ASGI app with real-PG sessions.

    Auth is overridden to user A: these tests exercise approval-layer
    concurrency (locks, unique indexes, commit races), not authentication,
    which is covered elsewhere (test_approvals_api.py, real-stack suite).
    """
    from httpx import ASGITransport, AsyncClient

    import app.session as app_session
    from app.auth import get_current_user
    from app.database import get_db
    from app.main import app
    from app.routes.actions import check_proposal_rate_limit
    from app.routes.approvals import check_approval_rate_limit

    # The app caches a module-global Redis pool bound to the creating event
    # loop. pytest-asyncio gives each test a fresh loop, so reset the pool
    # per test (production runs one stable loop and is unaffected).
    app_session._redis_pool = None

    engine = create_async_engine(
        get_settings().database_url, echo=False, poolclass=NullPool
    )
    SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with SessionLocal() as session:
            yield session

    approver = owners["a"]

    async def override_get_current_user():
        return approver

    async def override_rate_limit():
        return approver

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[check_approval_rate_limit] = override_rate_limit
    app.dependency_overrides[check_proposal_rate_limit] = override_rate_limit

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c

    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(check_approval_rate_limit, None)
    app.dependency_overrides.pop(check_proposal_rate_limit, None)
    # Drop the loop-bound pool without aclose (old loop is gone).
    app_session._redis_pool = None
    await engine.dispose()


async def seed_proposal(session_factory, repo_id, owner_id) -> ActionProposal:
    async with session_factory() as session:
        scan = Scan(id=uuid4(), repository_id=repo_id, status="COMPLETED",
                    trigger="manual", commit_sha="a" * 40)
        session.add(scan)
        await session.flush()
        finding = Finding(
            id=uuid4(), scan_id=scan.id, repository_id=repo_id,
            fingerprint=f"race-{uuid4().hex[:12]}", scanner="dependency",
            source_type="DEPENDENCY", vulnerability_id="GHSA-race",
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
            repository_id=repo_id, created_by=owner_id,
            action_type="DEPENDENCY_UPGRADE", status="POLICY_CHECKED",
            base_commit_sha="a" * 40, target_branch="cyvrix/fix",
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
        return p


async def _fire_simultaneous(request_factories):
    """Fire request coroutines at (nearly) the same instant via a barrier."""
    barrier = asyncio.Barrier(len(request_factories))

    async def _run(factory):
        await barrier.wait()
        return await factory()

    return await asyncio.gather(
        *[_run(f) for f in request_factories], return_exceptions=True
    )


def _assert_no_exceptions(results, rep):
    errs = [r for r in results if isinstance(r, BaseException)]
    assert not errs, f"rep {rep}: requests raised {errs!r}"


def _codes(results):
    return sorted(r.status_code for r in results)


# ── Race 1: APPROVE vs APPROVE ───────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("rep", REP_IDS)
async def test_race_approve_approve(api_client, session_factory, owners, rep):
    p = await seed_proposal(session_factory, owners["repo_id"], owners["a_id"])

    results = await _fire_simultaneous([
        lambda: api_client.post(f"/api/actions/{p.id}/approve", json={}),
        lambda: api_client.post(f"/api/actions/{p.id}/approve", json={}),
    ])
    _assert_no_exceptions(results, rep)

    # Deterministic DB outcome: exactly one approval row, live and APPROVED.
    async with session_factory() as session:
        rows = (await session.execute(
            select(Approval).where(Approval.action_proposal_id == p.id)
        )).scalars().all()
        assert len(rows) == 1, f"rep {rep}: {len(rows)} approval rows"
        assert rows[0].approval_state == "APPROVED", f"rep {rep}"
        assert rows[0].approver_user_id == owners["a_id"], f"rep {rep}"
        assert rows[0].authorization_used_at is None, f"rep {rep}"
        assert rows[0].policy_decision == "REQUIRE_APPROVAL", f"rep {rep}"

    # No two usable tokens: at most one response carries a token.
    tokens = [r.json().get("authorization_token", "") for r in results]
    nonempty = [t for t in tokens if t]
    assert len(nonempty) <= 1, f"rep {rep}: {len(nonempty)} tokens minted"

    # No 5xx leaks (unique-constraint failures must be handled).
    assert all(c in (200, 403, 404, 409) for c in _codes(results)), (
        f"rep {rep}: {_codes(results)}"
    )


# ── Race 2: APPROVE vs REJECT ────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("rep", REP_IDS)
async def test_race_approve_reject(api_client, session_factory, owners, rep):
    p = await seed_proposal(session_factory, owners["repo_id"], owners["a_id"])

    results = await _fire_simultaneous([
        lambda: api_client.post(f"/api/actions/{p.id}/approve", json={}),
        lambda: api_client.post(f"/api/actions/{p.id}/reject",
                                json={"reason": "race reject"}),
    ])
    _assert_no_exceptions(results, rep)

    async with session_factory() as session:
        rows = (await session.execute(
            select(Approval).where(Approval.action_proposal_id == p.id)
        )).scalars().all()
        states = {r.approval_state for r in rows}
        live = [r for r in rows if r.approval_state in ("PENDING", "APPROVED")]
        assert len(live) <= 1, f"rep {rep}: {len(live)} live approvals"
        # No contradictory state: APPROVED and REJECTED never coexist as
        # terminal outcomes of the same proposal.
        assert not ({"APPROVED", "REJECTED"} <= states or
                    ("APPROVED" in states and any(
                        r.approval_state == "REJECTED" for r in rows))), (
            f"rep {rep}: contradictory states {states}"
        )

        prop = await session.get(ActionProposal, p.id)
        approved = any(
            r.approval_state == "APPROVED" for r in rows
        )
        if approved:
            assert prop.status == "APPROVED", f"rep {rep}: proposal {prop.status}"
            assert live, f"rep {rep}"
        else:
            assert prop.status == "REJECTED", f"rep {rep}: proposal {prop.status}"
            assert all(r.approval_state == "REJECTED" for r in rows), f"rep {rep}"

    # Exactly one winner; no 5xx.
    codes = _codes(results)
    assert 200 in codes, f"rep {rep}: no winner {codes}"
    assert all(c in (200, 403, 404, 409) for c in codes), f"rep {rep}: {codes}"

    # Audit reflects the decided outcome.
    async with session_factory() as session:
        kinds = (await session.execute(
            select(AuditEvent.event_type).where(
                AuditEvent.event_type.in_(["APPROVAL_GRANTED", "APPROVAL_REJECTED"])
            )
        )).scalars().all()
        assert kinds, f"rep {rep}: no lifecycle audit event"


# ── Race 3: CONSUME vs CONSUME (token double-spend) ──────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("rep", REP_IDS)
async def test_race_consume_consume(api_client, session_factory, owners, rep):
    p = await seed_proposal(session_factory, owners["repo_id"], owners["a_id"])
    r = await api_client.post(f"/api/actions/{p.id}/approve", json={})
    assert r.status_code == 200, r.text
    token = r.json()["authorization_token"]
    approval_id = (await api_client.get(f"/api/actions/{p.id}/approval")).json()["id"]

    results = await _fire_simultaneous([
        lambda: api_client.post(
            f"/api/actions/{p.id}/approval/{approval_id}/consume-token",
            json={"token": token}),
        lambda: api_client.post(
            f"/api/actions/{p.id}/approval/{approval_id}/consume-token",
            json={"token": token}),
    ])
    _assert_no_exceptions(results, rep)

    # Exactly one success; the loser is denied, never a 5xx.
    assert _codes(results) == [200, 403], f"rep {rep}: {_codes(results)}"

    async with session_factory() as session:
        row = (await session.execute(
            select(Approval).where(Approval.id == uuid_module.UUID(approval_id))
        )).scalars().one()
        assert row.approval_state == "USED", f"rep {rep}: {row.approval_state}"
        assert row.authorization_used_at is not None, f"rep {rep}"


# ── Race 4: REVOKE vs CONSUME ────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("rep", REP_IDS)
async def test_race_revoke_consume(api_client, session_factory, owners, rep):
    p = await seed_proposal(session_factory, owners["repo_id"], owners["a_id"])
    r = await api_client.post(f"/api/actions/{p.id}/approve", json={})
    assert r.status_code == 200, r.text
    token = r.json()["authorization_token"]
    approval_id = (await api_client.get(f"/api/actions/{p.id}/approval")).json()["id"]

    results = await _fire_simultaneous([
        lambda: api_client.post(
            f"/api/actions/{p.id}/approval/{approval_id}/revoke",
            json={"reason": "race revoke"}),
        lambda: api_client.post(
            f"/api/actions/{p.id}/approval/{approval_id}/consume-token",
            json={"token": token}),
    ])
    _assert_no_exceptions(results, rep)

    async with session_factory() as session:
        row = (await session.execute(
            select(Approval).where(Approval.id == uuid_module.UUID(approval_id))
        )).scalars().one()
        # Deterministic terminal state: exactly USED or REVOKED, never both.
        assert row.approval_state in ("USED", "REVOKED"), (
            f"rep {rep}: {row.approval_state}"
        )
        if row.approval_state == "REVOKED":
            assert row.authorization_used_at is None, (
                f"rep {rep}: revoked approval was consumed"
            )

    # No 5xx in either path.
    for r_ in results:
        assert r_.status_code in (200, 403, 409), (
            f"rep {rep}: {r_.method} {r_.url.path} -> {r_.status_code}"
        )

    # Post-race invariant: the token can never be used after the race.
    r2 = await api_client.post(
        f"/api/actions/{p.id}/approval/{approval_id}/consume-token",
        json={"token": token},
    )
    assert r2.status_code == 403, f"rep {rep}: post-race consume {r2.status_code}"
    async with session_factory() as session:
        row = (await session.execute(
            select(Approval).where(Approval.id == uuid_module.UUID(approval_id))
        )).scalars().one()
        assert row.approval_state in ("USED", "REVOKED"), f"rep {rep}"


# ── Race 5: APPROVE vs REVOKE (no resurrection) ──────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("rep", REP_IDS)
async def test_race_approve_revoke(api_client, session_factory, owners, rep):
    p = await seed_proposal(session_factory, owners["repo_id"], owners["a_id"])
    r = await api_client.post(f"/api/actions/{p.id}/approve", json={})
    assert r.status_code == 200, r.text
    approval_id = (await api_client.get(f"/api/actions/{p.id}/approval")).json()["id"]

    results = await _fire_simultaneous([
        lambda: api_client.post(f"/api/actions/{p.id}/approve", json={}),
        lambda: api_client.post(
            f"/api/actions/{p.id}/approval/{approval_id}/revoke",
            json={"reason": "race revoke 2"}),
    ])
    _assert_no_exceptions(results, rep)

    async with session_factory() as session:
        rows = (await session.execute(
            select(Approval).where(Approval.action_proposal_id == p.id)
        )).scalars().all()
        live = [r_ for r_ in rows if r_.approval_state in ("PENDING", "APPROVED")]
        # No resurrection and no duplicates: at most the original row,
        # which is either still APPROVED (approve-side idempotency won
        # before the revoke) or REVOKED — never both, never recreated.
        assert len(rows) == 1, f"rep {rep}: {len(rows)} approval rows"
        assert len(live) <= 1, f"rep {rep}: {len(live)} live approvals"

    assert all(c in (200, 403, 404, 409) for c in _codes(results)), (
        f"rep {rep}: {_codes(results)}"
    )


# ── Race 6: high-contention storm (4-way mixed) ──────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("rep", [0, 1, 2])  # 3 reps × 4 concurrent ops
async def test_race_mixed_storm(api_client, session_factory, owners, rep):
    p = await seed_proposal(session_factory, owners["repo_id"], owners["a_id"])
    r = await api_client.post(f"/api/actions/{p.id}/approve", json={})
    assert r.status_code == 200, r.text
    token = r.json()["authorization_token"]
    approval_id = (await api_client.get(f"/api/actions/{p.id}/approval")).json()["id"]

    results = await _fire_simultaneous([
        lambda: api_client.post(f"/api/actions/{p.id}/approve", json={}),
        lambda: api_client.post(f"/api/actions/{p.id}/reject", json={}),
        lambda: api_client.post(
            f"/api/actions/{p.id}/approval/{approval_id}/revoke", json={}),
        lambda: api_client.post(
            f"/api/actions/{p.id}/approval/{approval_id}/consume-token",
            json={"token": token}),
    ])
    _assert_no_exceptions(results, rep)

    # Determinism check: no 5xx anywhere; every outcome is a handled 2xx/4xx.
    assert all(c in (200, 403, 404, 409) for c in _codes(results)), (
        f"rep {rep}: {_codes(results)}"
    )

    async with session_factory() as session:
        rows = (await session.execute(
            select(Approval).where(Approval.action_proposal_id == p.id)
        )).scalars().all()
        live = [r_ for r_ in rows if r_.approval_state in ("PENDING", "APPROVED")]
        assert len(live) <= 1, f"rep {rep}: {len(live)} live approvals"
        for row in rows:
            # Every row is in a coherent state with coherent token columns.
            if row.approval_state == "USED":
                assert row.authorization_used_at is not None, f"rep {rep}"
            if row.approval_state == "REVOKED":
                assert row.authorization_used_at is None, f"rep {rep}"
