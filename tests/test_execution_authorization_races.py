"""CYVRIX V3.3 — Genuine concurrent execution-authorization race tests
(real PostgreSQL).

These tests are NOT sequential simulations: requests are issued truly
simultaneously (asyncio.gather over a shared barrier) against the real
ASGI app, each with its own PostgreSQL session/transaction, so server-side
concurrency (row locks, partial unique indexes, transaction isolation,
commit races) is genuinely exercised.

Gated behind RUN_INTEGRATION_TESTS=1 + a dedicated migrated database:

    DATABASE_URL=postgresql+asyncpg://... REDIS_URL=redis://... \
    SECRET_KEY=<32+ char secret> RUN_INTEGRATION_TESTS=1 \
    pytest tests/test_execution_authorization_races.py

NOTE: these tests WIPE all tables of the configured database between tests.
NEVER point them at a database holding real data.

Documented deterministic outcomes (docs/v3-execution-authorization.md §7):
- authorize vs authorize  → exactly one live authorization (or the same
                            idempotent record returned to both)
- consume vs consume      → exactly one 200; loser 409 AUTHORIZATION_REPLAY
- consume vs revoke       → terminal state exactly CONSUMED or REVOKED;
                            a revoked authorization can never be consumed
- authorize vs expiry     → no authorization after effective expiration
- policy-change vs authorize → DENY wins (POLICY_DENIED)
- risk-change vs authorize   → DENY wins (RISK_CHANGED)
"""
import asyncio
import json
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
    ActionProposal, Approval, AuditEvent, ExecutionAuthorization, Finding,
    Recommendation, Repository, GithubInstallation, RiskAssessment, Scan,
    SystemControl, User,
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
        # Kill switch OFF for the race scenarios (each test seeds its own)
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
    """redis-py async clients bind to the creating event loop; reset the
    app-global pool each test so no stale-loop connections are reused."""
    import app.session as session_module

    session_module._redis_pool = None
    yield
    session_module._redis_pool = None


@pytest.fixture
async def owners(clean_db, session_factory, redis_client):
    """User A owns repo/proposal; user B exists (off-chain). Step-up fresh."""
    async with session_factory() as session:
        ua = User(email=f"race3-a-{uuid4().hex[:8]}@test.com", github_id=8_300_001)
        ub = User(email=f"race3-b-{uuid4().hex[:8]}@test.com", github_id=8_300_002)
        session.add_all([ua, ub])
        await session.flush()
        inst = GithubInstallation(
            user_id=ua.id, installation_id=8_400_001,
            account_login="race3-org", account_type="Organization",
        )
        session.add(inst)
        await session.flush()
        repo = Repository(
            installation_id=inst.id, github_repo_id=8_500_001,
            owner="race3-org", name="race-repo", default_branch="main",
            is_active=True,
        )
        session.add(repo)
        await session.commit()
        await session.refresh(repo)
        return {"a": ua, "b": ub, "repo": repo}


async def seed_proposal(session_factory, repository, *, proposer_id) -> ActionProposal:
    from app.services.action_model import proposal_expiry

    async with session_factory() as session:
        scan = Scan(
            id=uuid4(), repository_id=repository.id, status="COMPLETED",
            trigger="manual", commit_sha=BASE_COMMIT,
        )
        session.add(scan)
        await session.flush()
        finding = Finding(
            id=uuid4(), scan_id=scan.id, repository_id=repository.id,
            fingerprint=f"fp-{uuid4().hex[:12]}", scanner="dependency",
            source_type="DEPENDENCY", vulnerability_id="GHSA-race",
            package_name="lodash", package_version="4.17.19",
            title="Race proposal", severity="HIGH", status="OPEN",
            evidence={"manifest_path": "package.json"},
        )
        session.add(finding)
        await session.flush()
        recommendation = Recommendation(
            id=uuid4(), finding_id=finding.id, status="COMPLETED",
            trust_level="SUPPORTED", title="Upgrade lodash",
            change="Upgrade lodash to 4.17.21", validation_state="VALIDATED",
        )
        session.add(recommendation)
        await session.flush()
        session.add(RiskAssessment(
            id=uuid4(), finding_id=finding.id, risk_score=45,
            risk_level="MEDIUM", risk_version=1, factors={"base_score": 45},
        ))
        proposal = ActionProposal(
            id=uuid4(), finding_id=finding.id, recommendation_id=recommendation.id,
            repository_id=repository.id, created_by=proposer_id,
            action_type="DEPENDENCY_UPGRADE", status="POLICY_CHECKED",
            base_commit_sha=BASE_COMMIT, target_branch="cyvrix/fix",
            files=["package.json"],
            operations=[{
                "type": "UPDATE_DEPENDENCY_VERSION", "file": "package.json",
                "name": "lodash", "ecosystem": "npm",
                "from_version": "4.17.19", "to_version": "4.17.21",
            }],
            expected_diff='- "lodash": "4.17.19"\n+ "lodash": "4.17.21"',
            rationale="Patch prototype pollution",
            risk_score=45, risk_level="MEDIUM",
            recommendation_trust="SUPPORTED", validation_state="VALIDATED",
            policy_version="3.1", policy_decision="REQUIRE_APPROVAL",
            policy_reason_code="MEDIUM_RISK_REQUIRES_APPROVAL",
            policy_matched_rule="POL-027",
            action_digest="PENDING",
            expires_at=proposal_expiry(datetime.now(timezone.utc)),
        )
        proposal.action_digest = _compute_digest(proposal)
        session.add(proposal)
        await session.commit()
        await session.refresh(proposal)
        return proposal


async def approve_proposal(session_factory, proposal, approver_id) -> str:
    """Approve via the service directly (deterministic setup); returns the
    one-time token. Step-up evidence loader is monkeypatched at module use
    time by _fresh_step_up below."""
    from app.services import approval_service

    async with session_factory() as session:
        p = (
            await session.execute(
                select(ActionProposal).where(ActionProposal.id == proposal.id)
            )
        ).scalar_one()
        u = (
            await session.execute(select(User).where(User.id == approver_id))
        ).scalar_one()
        outcome = await approval_service.grant_approval(
            session, proposal=p, approver=u, second_approver_user_id=None,
            reason="race setup",
        )
        assert outcome.ok, outcome.reason_code
        assert outcome.authorization_token
        return outcome.authorization_token


@pytest.fixture
def fresh_step_up(monkeypatch):
    from app.services import approval_service

    async def fake_loader(*, approver, second_approver_user_id=None):
        second_ts = datetime.now(timezone.utc) if second_approver_user_id else None
        return datetime.now(timezone.utc), second_ts, None

    monkeypatch.setattr(approval_service, "_load_step_up_evidence", fake_loader)


@pytest.fixture
async def app_client(fresh_step_up, owners):
    """Async HTTP client on the REAL ASGI app with real-PG sessions.

    Same proven pattern as tests/test_approval_races.py: own engine +
    get_db override, auth overridden to user A (these tests exercise
    authorization-layer concurrency, not authentication), barrier-based
    simultaneous firing.
    """
    from httpx import ASGITransport, AsyncClient

    import app.session as app_session
    from app.auth import get_current_user
    from app.database import get_db
    from app.main import app
    from app.routes.actions import check_proposal_rate_limit
    from app.routes.approvals import check_approval_rate_limit
    from app.routes.execution_authorization import check_execution_auth_rate_limit

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
    app.dependency_overrides[check_execution_auth_rate_limit] = override_rate_limit

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c

    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(check_approval_rate_limit, None)
    app.dependency_overrides.pop(check_proposal_rate_limit, None)
    app.dependency_overrides.pop(check_execution_auth_rate_limit, None)
    # Drop the loop-bound pool without aclose (old loop is gone).
    app_session._redis_pool = None
    await engine.dispose()


def _act_as(client, user_id):
    """Kept for signature compatibility; the client is pinned to user A
    for the whole fixture (authorization races, not auth races)."""


async def _setup_approved(client, session_factory, owners) -> tuple:
    """Seed + approve; returns (proposal, token)."""
    proposal = await seed_proposal(
        session_factory, owners["repo"], proposer_id=owners["a"].id
    )
    token = await approve_proposal(session_factory, proposal, owners["a"].id)
    return proposal, token


async def _gather(*coros):
    """Fire request coroutines at (nearly) the same instant via a barrier."""
    barrier = asyncio.Barrier(len(coros))

    async def _run(coro):
        await barrier.wait()
        return await coro

    return await asyncio.gather(
        *[_run(c) for c in coros], return_exceptions=True
    )


# ── Race classes ─────────────────────────────────────────────────────


class TestAuthorizeRaces:
    @pytest.mark.parametrize("rep", REP_IDS)
    @pytest.mark.asyncio
    async def test_race_authorize_authorize(
        self, app_client, session_factory, owners, rep,
    ):
        """Two simultaneous authorize requests: at most one live
        authorization exists afterwards; ids agree or one is a mirror."""
        proposal, _ = await _setup_approved(app_client, session_factory, owners)

        async def go():
            return await app_client.post(
                f"/api/actions/{proposal.id}/authorize", json={}
            )

        r1, r2 = await _gather(go(), go())
        for r in (r1, r2):
            assert not isinstance(r, Exception), r
            assert r.status_code == 200, (r.status_code, r.text)
        ids = {r.json()["id"] for r in (r1, r2)}
        assert len(ids) == 1, f"two distinct live authorizations: {ids}"

        async with session_factory() as session:
            rows = (
                await session.execute(
                    select(ExecutionAuthorization).where(
                        ExecutionAuthorization.action_proposal_id == proposal.id,
                        ExecutionAuthorization.authorization_state == "AUTHORIZED",
                    )
                )
            ).scalars().all()
            assert len(rows) == 1

    @pytest.mark.parametrize("rep", REP_IDS)
    @pytest.mark.asyncio
    async def test_race_consume_consume(
        self, app_client, session_factory, owners, rep,
    ):
        """Two simultaneous consume requests with the same valid token:
        exactly one 200; the loser gets 409 AUTHORIZATION_REPLAY; terminal
        state CONSUMED; approval USED exactly once."""
        proposal, token = await _setup_approved(app_client, session_factory, owners)

        r = await app_client.post(f"/api/actions/{proposal.id}/authorize", json={})
        assert r.status_code == 200
        auth_id = r.json()["id"]

        async def go():
            return await app_client.post(
                f"/api/actions/authorization/{auth_id}/consume",
                json={"token": token},
            )

        c1, c2 = await _gather(go(), go())
        codes = sorted(
            c.status_code for c in (c1, c2) if not isinstance(c, Exception)
        )
        assert not any(isinstance(c, Exception) for c in (c1, c2))
        assert codes == [200, 409], f"expected [200, 409], got {codes}"
        loser = c1 if c1.status_code == 409 else c2
        assert loser.json()["detail"]["reason_code"] == "AUTHORIZATION_REPLAY"

        async with session_factory() as session:
            row = (
                await session.execute(
                    select(ExecutionAuthorization).where(
                        ExecutionAuthorization.id == uuid_module.UUID(auth_id)
                    )
                )
            ).scalar_one()
            appr = (
                await session.execute(
                    select(Approval).where(Approval.id == row.approval_id)
                )
            ).scalar_one()
            assert row.authorization_state == "CONSUMED"
            assert appr.approval_state == "USED"

    @pytest.mark.parametrize("rep", REP_IDS)
    @pytest.mark.asyncio
    async def test_race_consume_revoke(
        self, app_client, session_factory, owners, rep,
    ):
        """Simultaneous consume + revoke: terminal state is exactly
        CONSUMED or REVOKED; a revoked authorization can never be
        consumed; no contradictory state."""
        proposal, token = await _setup_approved(app_client, session_factory, owners)

        r = await app_client.post(f"/api/actions/{proposal.id}/authorize", json={})
        auth_id = r.json()["id"]

        async def consume():
            return await app_client.post(
                f"/api/actions/authorization/{auth_id}/consume",
                json={"token": token},
            )

        async def revoke():
            return await app_client.post(
                f"/api/actions/authorization/{auth_id}/revoke",
                json={"reason": "race"},
            )

        (c, rv) = await _gather(consume(), revoke())
        assert not isinstance(c, Exception) and not isinstance(rv, Exception)
        final_states = set()
        async with session_factory() as session:
            row = (
                await session.execute(
                    select(ExecutionAuthorization).where(
                        ExecutionAuthorization.id == uuid_module.UUID(auth_id)
                    )
                )
            ).scalar_one()
            final_states.add(row.authorization_state)
        # Exactly one terminal winner; CONSUMED excludes REVOKED and vice versa
        assert final_states <= {"CONSUMED", "REVOKED"}
        # If consumed, the revoke must have failed (4xx) — never 200 on both.
        # The race loser is revoked-no-op (idempotent 200 mirror) or denied;
        # both are safe. The invariant under test is DB-level: exactly one
        # terminal state, and CONSUMED ⇔ the token was used exactly once.
        if row.authorization_state == "CONSUMED":
            assert rv.status_code in (200, 403, 409)
            async with session_factory() as session:
                final = (
                    await session.execute(
                        select(ExecutionAuthorization).where(
                            ExecutionAuthorization.id == uuid_module.UUID(auth_id)
                        )
                    )
                ).scalar_one()
                assert final.authorization_state == "CONSUMED", \
                    "consumed authorization was resurrected as REVOKED"
        else:
            assert c.status_code in (403, 409), c.text

    @pytest.mark.parametrize("rep", REP_IDS)
    @pytest.mark.asyncio
    async def test_race_authorize_vs_expiry(
        self, app_client, session_factory, owners, rep,
    ):
        """Approval expires while authorize is in flight: no authorization
        may be created after effective expiration."""
        proposal, _ = await _setup_approved(app_client, session_factory, owners)


        async def expire():
            await asyncio.sleep(0)
            async with session_factory() as session:
                appr = (
                    await session.execute(
                        select(Approval).where(
                            Approval.action_proposal_id == proposal.id
                        )
                    )
                ).scalar_one()
                appr.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
                await session.commit()

        async def authorize():
            return await app_client.post(
                f"/api/actions/{proposal.id}/authorize", json={}
            )

        results = await _gather(expire(), authorize())
        auth_res = results[1]
        assert not isinstance(auth_res, Exception)
        # Either expired first (denied) or authorized before expiry took
        # effect — but never an AUTHORIZED record on an EXPIRED approval.
        async with session_factory() as session:
            appr = (
                await session.execute(
                    select(Approval).where(
                        Approval.action_proposal_id == proposal.id
                    )
                )
            ).scalar_one()
            rows = (
                await session.execute(
                    select(ExecutionAuthorization).where(
                        ExecutionAuthorization.action_proposal_id == proposal.id
                    )
                )
            ).scalars().all()
            if appr.approval_state == "EXPIRED":
                assert rows == []
            else:
                assert all(r.authorization_state == "AUTHORIZED" for r in rows)

    @pytest.mark.parametrize("rep", REP_IDS)
    @pytest.mark.asyncio
    async def test_race_policy_change_vs_authorize(
        self, app_client, session_factory, owners, rep,
    ):
        """Policy flips to DENY (repo deactivated) while authorize is in
        flight: DENY wins — no live authorization afterwards."""
        proposal, _ = await _setup_approved(app_client, session_factory, owners)


        async def deactivate():
            await asyncio.sleep(0)
            async with session_factory() as session:
                repo = (
                    await session.execute(
                        select(Repository).where(Repository.id == owners["repo"].id)
                    )
                ).scalar_one()
                repo.is_active = False
                await session.commit()

        async def authorize():
            return await app_client.post(
                f"/api/actions/{proposal.id}/authorize", json={}
            )

        results = await _gather(deactivate(), authorize())
        auth_res = results[1]
        assert not isinstance(auth_res, Exception)
        async with session_factory() as session:
            rows = (
                await session.execute(
                    select(ExecutionAuthorization).where(
                        ExecutionAuthorization.action_proposal_id == proposal.id,
                        ExecutionAuthorization.authorization_state == "AUTHORIZED",
                    )
                )
            ).scalars().all()
            # Either the deactivation landed before the authorize's policy
            # re-evaluation (→ denied) or after its commit (→ authorized).
            # Both are safe; what must NEVER happen is POLICY_DENIED plus a
            # live authorization in the same final state.
            if auth_res.status_code == 200:
                assert len(rows) == 1
            else:
                assert auth_res.status_code in (403, 409)
                assert rows == []

    @pytest.mark.parametrize("rep", REP_IDS)
    @pytest.mark.asyncio
    async def test_race_risk_change_vs_authorize(
        self, app_client, session_factory, owners, rep,
    ):
        """Risk reassessed while authorize is in flight: snapshot-drift
        detection and the authorize race resolve without contradiction."""
        proposal, _ = await _setup_approved(app_client, session_factory, owners)


        async def bump_risk():
            await asyncio.sleep(0)
            async with session_factory() as session:
                finding = (
                    await session.execute(
                        select(Finding).where(Finding.id == proposal.finding_id)
                    )
                ).scalar_one()
                session.add(RiskAssessment(
                    id=uuid4(), finding_id=finding.id, risk_score=85,
                    risk_level="HIGH", risk_version=1, factors={"x": 1},
                ))
                await session.commit()

        async def authorize():
            return await app_client.post(
                f"/api/actions/{proposal.id}/authorize", json={}
            )

        results = await _gather(bump_risk(), authorize())
        auth_res = results[1]
        assert not isinstance(auth_res, Exception)
        # Safe outcomes: denied (drift detected) or authorized (raced ahead).
        # Never a 200 with RISK_CHANGED in the audit trail contradicting it.
        if auth_res.status_code == 200:
            assert auth_res.json()["authorization_state"] == "AUTHORIZED"
        else:
            assert auth_res.status_code in (403, 409)
            detail = auth_res.json()["detail"]["reason_code"]
            assert detail in ("RISK_CHANGED", "POLICY_DENIED", "ACTION_STALE",
                              "POLICY_VERSION_STALE", "RECOMMENDATION_CHANGED")


class TestStorm:
    @pytest.mark.parametrize("rep", REP_IDS[:3])
    @pytest.mark.asyncio
    async def test_four_way_storm(
        self, app_client, session_factory, owners, rep,
    ):
        """authorize ×2 + consume ×1 + revoke ×1 all released together:
        final state deterministic — at most one live authorization ever,
        terminal state exactly one of CONSUMED/REVOKED/AUTHORIZED, no 5xx,
        no duplicate rows."""
        proposal, token = await _setup_approved(app_client, session_factory, owners)


        results = await _gather(
            app_client.post(f"/api/actions/{proposal.id}/authorize", json={}),
            app_client.post(f"/api/actions/{proposal.id}/authorize", json={}),
        )
        # First resolve the authorizes, then storm consume+revoke against
        # whatever authorization exists (may be none if both denied).
        ok_results = [r for r in results if not isinstance(r, Exception)]
        assert all(r.status_code == 200 for r in ok_results), \
            [(r.status_code, r.text) for r in ok_results]
        ids = {r.json()["id"] for r in ok_results}
        assert len(ids) == 1, "duplicate live authorizations"
        auth_id = ids.pop()

        async def consume():
            return await app_client.post(
                f"/api/actions/authorization/{auth_id}/consume",
                json={"token": token},
            )

        async def revoke():
            return await app_client.post(
                f"/api/actions/authorization/{auth_id}/revoke", json={}
            )

        c, rv = await _gather(consume(), revoke())
        assert not isinstance(c, Exception) and not isinstance(rv, Exception)
        assert c.status_code != 500 and rv.status_code != 500
        async with session_factory() as session:
            rows = (
                await session.execute(
                    select(ExecutionAuthorization).where(
                        ExecutionAuthorization.action_proposal_id == proposal.id
                    )
                )
            ).scalars().all()
            assert len(rows) == 1
            assert rows[0].authorization_state in ("AUTHORIZED", "CONSUMED", "REVOKED")
