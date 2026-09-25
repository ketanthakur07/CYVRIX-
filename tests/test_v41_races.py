"""CYVRIX V4.1 — public API races on REAL PostgreSQL.

Gated behind RUN_INTEGRATION_TESTS=1 and the migrated database (see
infra/integration.env). These are the invariants that a single-threaded
test cannot establish:

  - rotate x rotate produces EXACTLY ONE successor (two live keys would
    mean two credentials for one logical key)
  - rotate x revoke never leaves two live keys
  - concurrent revokes are idempotent and revocation is FINAL
  - duplicate idempotent requests produce the side effect exactly once
  - same key + different request under concurrency resolves to exactly one
    winner and one conflict (never two winners, never a false replay)
  - the end-to-end POST /api/v1/scans retry path creates one scan

V4.1 external-boundary races (quotas, webhook replay, audit org chains)
live in test_v41_boundary_races.py.
"""
import asyncio
import os
import uuid as uuid_module

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION_TESTS") != "1",
    reason="V4.1 races require RUN_INTEGRATION_TESTS=1 and real PostgreSQL",
)

from sqlalchemy import select  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.models import (  # noqa: E402
    ApiIdempotencyKey,
    ApiKey,
    GithubInstallation,
    OrganizationMembership,
    Repository,
    Scan,
    SystemControl,
    User,
)
from app.services import api_key_service  # noqa: E402
from app.services import idempotency_service as idem  # noqa: E402
from app.services import organization_service as org_svc  # noqa: E402
from app.services import v4_rbac as rbac  # noqa: E402
from app.services.organization_service import OrgError  # noqa: E402

REPETITIONS = 10
REP_IDS = list(range(REPETITIONS))


@pytest.fixture(scope="module")
async def real_engine():
    settings = get_settings()
    if "sqlite" in settings.database_url:
        pytest.skip("PostgreSQL required for V4.1 races")
    eng = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
    yield eng
    await eng.dispose()


@pytest.fixture
def session_factory(real_engine):
    return async_sessionmaker(real_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture
async def clean_db_real(real_engine):
    from conftest import wipe_all_tables

    async with real_engine.begin() as conn:
        await wipe_all_tables(conn)
        await conn.execute(
            SystemControl.__table__.insert().values(
                key="operational_state", value="NORMAL"
            )
        )
    yield


@pytest.fixture
async def org_ctx(session_factory, clean_db_real):
    """One org, one owner membership, one installation, one repository."""
    async with session_factory() as s:
        owner = User(email=f"v41-owner-{uuid_module.uuid4()}@t.local")
        s.add(owner)
        await s.flush()
        org = await org_svc.create_organization(
            s, name=f"Race-{uuid_module.uuid4().hex[:8]}", creator_user_id=owner.id
        )
        await s.flush()
        inst = GithubInstallation(
            user_id=owner.id,
            installation_id=uuid_module.uuid4().int % 900000 + 1,
            account_login="race",
            account_type="Organization",
            organization_id=org.id,
        )
        s.add(inst)
        await s.flush()
        repo = Repository(
            installation_id=inst.id,
            github_repo_id=uuid_module.uuid4().int % 900000 + 1,
            owner="race",
            name="race-repo",
            default_branch="main",
            is_active=True,
        )
        s.add(repo)
        await s.flush()
        membership = await org_svc.get_membership(
            s, org_id=org.id, user_id=owner.id
        )
        await s.commit()
        return {
            "org_id": org.id,
            "user_id": owner.id,
            "repo_id": repo.id,
            "role": membership.role,
        }


async def _issue_key(session_factory, ctx, *, scopes=None, name="race-key"):
    async with session_factory() as s:
        membership = await org_svc.get_membership(
            s, org_id=ctx["org_id"], user_id=ctx["user_id"]
        )
        row, secret = await api_key_service.create_api_key(
            s,
            org_id=ctx["org_id"],
            actor_membership=membership,
            actor_user_id=ctx["user_id"],
            name=name,
            scopes=scopes or ["repositories:read"],
        )
        await s.commit()
        return row.id, secret


async def _live_key_count(session_factory, key_name="race-key"):
    async with session_factory() as s:
        rows = (
            await s.execute(
                select(ApiKey).where(
                    ApiKey.name == key_name, ApiKey.revoked_at.is_(None)
                )
            )
        ).scalars().all()
        return len(rows)


# ── Rotation ─────────────────────────────────────────────────────────


class TestRotationRaces:
    async def test_rotate_versus_rotate_has_exactly_one_winner(
        self, session_factory, org_ctx
    ):
        """Two concurrent rotations must not mint two live successors.

        The loser must be told it lost, deterministically, rather than
        silently issuing a second credential for the same logical key.
        """
        for rep in REP_IDS:
            # A distinct name per repetition gives an exact lineage to
            # count, so repetitions cannot pollute each other's assertion.
            lineage = f"race-key-{rep}"
            key_id, _ = await _issue_key(session_factory, org_ctx, name=lineage)

            async def _rotate():
                async with session_factory() as s:
                    try:
                        membership = await org_svc.get_membership(
                            s, org_id=org_ctx["org_id"], user_id=org_ctx["user_id"]
                        )
                        row, secret = await api_key_service.rotate_api_key(
                            s,
                            org_id=org_ctx["org_id"],
                            actor_membership=membership,
                            actor_user_id=org_ctx["user_id"],
                            key_id=key_id,
                        )
                        await s.commit()
                        return ("ok", secret)
                    except OrgError as exc:
                        await s.rollback()
                        return ("refused", exc.reason_code)
                    except Exception as exc:  # noqa: BLE001
                        await s.rollback()
                        return ("error", type(exc).__name__)

            results = await asyncio.gather(_rotate(), _rotate())
            wins = [r for r in results if r[0] == "ok"]
            refusals = [r for r in results if r[0] == "refused"]

            assert len(wins) == 1, f"rep {rep}: expected one successor, got {results}"
            assert len(refusals) == 1, f"rep {rep}: expected one refusal, got {results}"
            # The loser's refusal is specific, not a generic failure.
            assert refusals[0][1] == "API_KEY_ALREADY_REVOKED", results
            # Exactly one live key survives the pair for this lineage.
            assert await _live_key_count(session_factory, lineage) == 1

    async def test_rotate_versus_revoke_never_leaves_two_live_keys(
        self, session_factory, org_ctx
    ):
        for rep in REP_IDS:
            lineage = f"rv-key-{rep}"
            key_id, _ = await _issue_key(session_factory, org_ctx, name=lineage)

            async def _rotate():
                async with session_factory() as s:
                    try:
                        membership = await org_svc.get_membership(
                            s, org_id=org_ctx["org_id"], user_id=org_ctx["user_id"]
                        )
                        await api_key_service.rotate_api_key(
                            s,
                            org_id=org_ctx["org_id"],
                            actor_membership=membership,
                            actor_user_id=org_ctx["user_id"],
                            key_id=key_id,
                        )
                        await s.commit()
                    except Exception:  # noqa: BLE001
                        await s.rollback()

            async def _revoke():
                async with session_factory() as s:
                    try:
                        membership = await org_svc.get_membership(
                            s, org_id=org_ctx["org_id"], user_id=org_ctx["user_id"]
                        )
                        await api_key_service.revoke_api_key(
                            s,
                            org_id=org_ctx["org_id"],
                            actor_membership=membership,
                            key_id=key_id,
                        )
                        await s.commit()
                    except Exception:  # noqa: BLE001
                        await s.rollback()

            await asyncio.gather(_rotate(), _revoke())
            live = await _live_key_count(session_factory, lineage)
            assert live <= 1, f"rep {rep}: {live} live keys after rotate+revoke"

    async def test_concurrent_revokes_are_idempotent_and_final(
        self, session_factory, org_ctx
    ):
        key_id, secret = await _issue_key(session_factory, org_ctx)

        async def _revoke():
            async with session_factory() as s:
                try:
                    membership = await org_svc.get_membership(
                        s, org_id=org_ctx["org_id"], user_id=org_ctx["user_id"]
                    )
                    await api_key_service.revoke_api_key(
                        s,
                        org_id=org_ctx["org_id"],
                        actor_membership=membership,
                        key_id=key_id,
                    )
                    await s.commit()
                    return "ok"
                except Exception as exc:  # noqa: BLE001
                    await s.rollback()
                    return type(exc).__name__

        await asyncio.gather(*[_revoke() for _ in range(REPETITIONS)])

        async with session_factory() as s:
            assert await api_key_service.authenticate_api_key(s, secret) is None
            row = (
                await s.execute(select(ApiKey).where(ApiKey.id == key_id))
            ).scalar_one()
            assert row.revoked_at is not None


# ── Idempotency ──────────────────────────────────────────────────────


class TestIdempotencyRaces:
    async def test_duplicate_idempotent_requests_have_one_winner(
        self, session_factory, org_ctx
    ):
        """N concurrent identical requests: exactly one performs the work."""
        scope = "POST /api/v1/scans"
        digest = idem.canonical_request_digest({"repository_id": str(org_ctx["repo_id"])})

        for rep in REP_IDS:
            key_value = f"race-key-{rep:04d}-aaaa"

            async def _attempt():
                async with session_factory() as s:
                    try:
                        res = await idem.reserve(
                            s,
                            organization_id=org_ctx["org_id"],
                            scope=scope,
                            key_value=key_value,
                            request_digest=digest,
                        )
                        if res.owned:
                            # Simulate the side effect + outcome recording.
                            await asyncio.sleep(0.01)
                            await idem.complete(
                                s, res, status_code=202, body={"scan_id": "one"}
                            )
                        await s.commit()
                        return res.outcome
                    except Exception as exc:  # noqa: BLE001
                        await s.rollback()
                        return f"ERROR:{type(exc).__name__}"

            outcomes = await asyncio.gather(*[_attempt() for _ in range(5)])
            acquired = [o for o in outcomes if o == idem.OUTCOME_ACQUIRED]
            assert len(acquired) == 1, f"rep {rep}: outcomes={outcomes}"
            for outcome in outcomes:
                assert not outcome.startswith("ERROR:"), outcomes
                assert outcome in (
                    idem.OUTCOME_ACQUIRED,
                    idem.OUTCOME_REPLAY,
                    idem.OUTCOME_IN_PROGRESS,
                ), outcomes

            async with session_factory() as s:
                rows = (
                    await s.execute(
                        select(ApiIdempotencyKey).where(
                            ApiIdempotencyKey.key_value == key_value
                        )
                    )
                ).scalars().all()
            assert len(rows) == 1, "exactly one record per key"

    async def test_same_key_different_request_never_replays(
        self, session_factory, org_ctx
    ):
        scope = "POST /api/v1/scans"
        for rep in REP_IDS:
            key_value = f"race-conflict-{rep:04d}"
            digest_a = idem.canonical_request_digest({"repository_id": str(uuid_module.uuid4())})
            digest_b = idem.canonical_request_digest({"repository_id": str(uuid_module.uuid4())})

            async def _attempt(digest):
                async with session_factory() as s:
                    try:
                        res = await idem.reserve(
                            s,
                            organization_id=org_ctx["org_id"],
                            scope=scope,
                            key_value=key_value,
                            request_digest=digest,
                        )
                        if res.owned:
                            await asyncio.sleep(0.01)
                            await idem.complete(
                                s, res, status_code=202, body={"scan_id": "x"}
                            )
                        await s.commit()
                        return res.outcome
                    except Exception as exc:  # noqa: BLE001
                        await s.rollback()
                        return f"ERROR:{type(exc).__name__}"

            outcomes = await asyncio.gather(_attempt(digest_a), _attempt(digest_b))
            assert idem.OUTCOME_ACQUIRED in outcomes, outcomes
            # Never two winners, and the loser is a conflict or in-progress —
            # never a replay of the other request's result.
            assert outcomes.count(idem.OUTCOME_ACQUIRED) == 1, outcomes
            other = [o for o in outcomes if o != idem.OUTCOME_ACQUIRED][0]
            assert other in (idem.OUTCOME_CONFLICT, idem.OUTCOME_IN_PROGRESS), outcomes


# ── End-to-end: concurrent POST /api/v1/scans ────────────────────────


class TestScanEndpointOnRealPostgres:
    async def test_retry_creates_one_scan_and_one_enqueue(self, real_engine, org_ctx):
        """The real HTTP path against real PostgreSQL.

        Concurrency is established at the primitive level (see
        TestIdempotencyRaces, 10 repetitions); this test establishes that
        the ENDPOINT is actually wired to it — so the guarantee is not just
        a property of an unused service. Kept sequential deliberately: a
        threaded TestClient deadlocks on the portal, and adding a second
        async engine would prove the primitive again rather than the wiring.
        """
        from fastapi.testclient import TestClient

        from app.database import get_db
        from app.main import app
        import app.worker as worker

        TestSession = async_sessionmaker(
            real_engine, class_=AsyncSession, expire_on_commit=False
        )

        async def _override():
            db = TestSession()
            try:
                yield db
            finally:
                await db.close()

        enqueued: list[str] = []
        original = worker.enqueue_scan
        worker.enqueue_scan = lambda scan_id: enqueued.append(scan_id)
        app.dependency_overrides[get_db] = _override

        # Issue a write-scoped key for this org.
        async with TestSession() as s:
            membership = await org_svc.get_membership(
                s, org_id=org_ctx["org_id"], user_id=org_ctx["user_id"]
            )
            _, secret = await api_key_service.create_api_key(
                s,
                org_id=org_ctx["org_id"],
                actor_membership=membership,
                actor_user_id=org_ctx["user_id"],
                name="race-key",
                scopes=["scans:create", "scans:read"],
            )
            await s.commit()

        headers = {
            "Authorization": f"Bearer {secret}",
            "Idempotency-Key": "e2e-race-key-0001",
        }
        body = {"repository_id": str(org_ctx["repo_id"])}

        try:
            with TestClient(app) as c:
                first = c.post("/api/v1/scans", json=body, headers=headers)
                second = c.post("/api/v1/scans", json=body, headers=headers)
        finally:
            worker.enqueue_scan = original
            app.dependency_overrides.pop(get_db, None)

        assert first.status_code == 202, first.text
        assert second.status_code == 202, second.text
        # Identical replayed outcome.
        assert second.json() == first.json()

        async with TestSession() as s:
            scans = (
                await s.execute(
                    select(Scan).where(Scan.repository_id == org_ctx["repo_id"])
                )
            ).scalars().all()
        # The side effect happened exactly once.
        assert len(scans) == 1, f"expected one scan, got {len(scans)}"
        assert len(enqueued) == 1, f"expected one enqueue, got {len(enqueued)}"
