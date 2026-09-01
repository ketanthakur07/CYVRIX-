"""CYVRIX Real Integration Tests.

These tests require real PostgreSQL and Redis services.
They test the actual application stack, not mocked versions.

Run with: pytest test_real_integration.py -v --tb=short

Requires:
- PostgreSQL on localhost:5433 (or configured DATABASE_URL)
- Redis on localhost:6380 (or configured REDIS_URL)
"""
import os
import sys
import asyncio
import pytest
from uuid import uuid4
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

# Skip all tests if integration services are not available
pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION_TESTS") != "1",
    reason="Integration tests require RUN_INTEGRATION_TESTS=1 and running PostgreSQL/Redis"
)


@pytest.fixture
async def real_engine():
    """Create a real PostgreSQL engine for integration tests."""
    from sqlalchemy.ext.asyncio import create_async_engine
    from app.config import get_settings

    settings = get_settings()
    if "sqlite" in settings.database_url:
        pytest.skip("PostgreSQL required for integration tests")

    eng = create_async_engine(settings.database_url, echo=False)
    yield eng
    await eng.dispose()


@pytest.fixture
async def real_redis():
    """Create a real Redis connection for integration tests."""
    import redis.asyncio as aioredis
    from app.config import get_settings

    settings = get_settings()
    try:
        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        await r.ping()
        yield r
        await r.aclose()
    except Exception:
        pytest.skip("Redis required for integration tests")


@pytest.fixture
async def real_session_factory(real_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
    return async_sessionmaker(real_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture
async def clean_real_db(real_engine):
    """Clean all tables between tests."""
    from app.database import Base
    async with real_engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(table.delete())
    yield


class TestRealPostgreSQL:
    """Test real PostgreSQL integration."""

    @pytest.mark.asyncio
    async def test_create_user(self, real_session_factory, clean_real_db):
        from app.models import User

        async with real_session_factory() as session:
            user = User(
                id=uuid4(),
                email="integration@test.com",
                github_id=12345,
                github_login="integration-user",
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)

            assert user.id is not None
            assert user.email == "integration@test.com"
            assert user.github_id == 12345

    @pytest.mark.asyncio
    async def test_full_relationship_chain(self, real_session_factory, clean_real_db):
        """Test the complete relationship chain:
        User → Installation → Repository → Scan → Finding → Investigation → Risk
        """
        from app.models import (
            User, GithubInstallation, Repository, Scan,
            Finding, Investigation, RiskAssessment,
        )

        async with real_session_factory() as session:
            # User
            user = User(id=uuid4(), email="chain@test.com", github_id=99999)
            session.add(user)
            await session.flush()

            # Installation
            installation = GithubInstallation(
                id=uuid4(),
                user_id=user.id,
                installation_id=11111,
                account_login="test-org",
                account_type="Organization",
            )
            session.add(installation)
            await session.flush()

            # Repository
            repo = Repository(
                id=uuid4(),
                installation_id=installation.id,
                github_repo_id=22222,
                owner="test-org",
                name="test-repo",
                default_branch="main",
                is_active=True,
            )
            session.add(repo)
            await session.flush()

            # Scan
            scan = Scan(
                id=uuid4(),
                repository_id=repo.id,
                status="COMPLETED",
                trigger="manual",
            )
            session.add(scan)
            await session.flush()

            # Finding
            finding = Finding(
                id=uuid4(),
                scan_id=scan.id,
                repository_id=repo.id,
                fingerprint="test-fingerprint",
                scanner="dependency",
                vulnerability_id="CVE-2024-9999",
                package_name="test-package",
                package_version="1.0.0",
                title="Test vulnerability",
                severity="HIGH",
                status="OPEN",
            )
            session.add(finding)
            await session.flush()

            # Investigation
            investigation = Investigation(
                id=uuid4(),
                finding_id=finding.id,
                status="COMPLETED",
                verdict="CONFIRMED",
                exploitability="HIGH",
                exposure="EXTERNAL",
                confidence=0.90,
                summary="Test summary",
                recommendation="Test recommendation",
            )
            session.add(investigation)
            await session.flush()

            # Risk Assessment
            risk = RiskAssessment(
                id=uuid4(),
                finding_id=finding.id,
                risk_score=85,
                risk_level="HIGH",
                risk_version=1,
                factors={"base_score": 60, "exposure_mod": 15, "exploit_mod": 10},
            )
            session.add(risk)
            await session.commit()

            # Verify all records
            assert user.id is not None
            assert installation.user_id == user.id
            assert repo.installation_id == installation.id
            assert scan.repository_id == repo.id
            assert finding.scan_id == scan.id
            assert investigation.finding_id == finding.id
            assert risk.finding_id == finding.id

    @pytest.mark.asyncio
    async def test_unique_constraints(self, real_session_factory, clean_real_db):
        """Test that unique constraints are enforced."""
        from app.models import User
        from sqlalchemy.exc import IntegrityError

        async with real_session_factory() as session:
            user1 = User(id=uuid4(), email="unique@test.com", github_id=11111)
            session.add(user1)
            await session.commit()

        # Try to create duplicate email
        async with real_session_factory() as session:
            user2 = User(id=uuid4(), email="unique@test.com", github_id=22222)
            session.add(user2)
            with pytest.raises(IntegrityError):
                await session.commit()
            await session.rollback()

        # Try to create duplicate github_id
        async with real_session_factory() as session:
            user3 = User(id=uuid4(), email="different@test.com", github_id=11111)
            session.add(user3)
            with pytest.raises(IntegrityError):
                await session.commit()
            await session.rollback()

    @pytest.mark.asyncio
    async def test_cascade_delete(self, real_session_factory, clean_real_db):
        """Test delete behavior for user → installation relationship.

        The current schema uses RESTRICT (not CASCADE) on the FK,
        so deleting a user with installations raises IntegrityError.
        This test documents the actual behavior.
        """
        from app.models import User, GithubInstallation, Repository
        from sqlalchemy import select
        from sqlalchemy.exc import IntegrityError

        async with real_session_factory() as session:
            user = User(id=uuid4(), email="cascade@test.com", github_id=33333)
            session.add(user)
            await session.flush()

            inst = GithubInstallation(
                id=uuid4(),
                user_id=user.id,
                installation_id=44444,
                account_login="cascade-org",
                account_type="Organization",
            )
            session.add(inst)
            await session.flush()

            repo = Repository(
                id=uuid4(),
                installation_id=inst.id,
                github_repo_id=55555,
                owner="cascade-org",
                name="cascade-repo",
                default_branch="main",
                is_active=True,
            )
            session.add(repo)
            await session.commit()

            user_id = user.id

        # Delete user — should fail due to FK constraint (RESTRICT)
        async with real_session_factory() as session:
            user = await session.get(User, user_id)
            if user:
                with pytest.raises(IntegrityError):
                    await session.delete(user)
                    await session.commit()
                await session.rollback()

        # Verify user and installation still exist
        async with real_session_factory() as session:
            user = await session.get(User, user_id)
            assert user is not None
            result = await session.execute(
                select(GithubInstallation).where(GithubInstallation.user_id == user_id)
            )
            installations = result.scalars().all()
            assert len(installations) == 1


class TestRealRedis:
    """Test real Redis integration."""

    @pytest.mark.asyncio
    async def test_session_lifecycle(self, real_redis):
        """Test session creation, validation, and deletion in real Redis."""
        from app.session import create_session, get_session_user_id, destroy_session

        user_id = uuid4()

        # Create session
        session_id, signature, cookie = await create_session(
            user_id,
            metadata={"test": "true"},
            r=real_redis,
        )

        # Verify session exists
        user_id_result = await get_session_user_id(session_id, signature, r=real_redis)
        assert user_id_result == user_id

        # Destroy session
        await destroy_session(session_id, r=real_redis)

        # Verify session is gone
        user_id_result = await get_session_user_id(session_id, signature, r=real_redis)
        assert user_id_result is None

    @pytest.mark.asyncio
    async def test_session_expiration(self, real_redis):
        """Test that sessions expire correctly."""
        from app.session import create_session, get_session_user_id

        user_id = uuid4()

        # Create session
        session_id, signature, _ = await create_session(user_id, r=real_redis)

        # Verify it exists
        result = await get_session_user_id(session_id, signature, r=real_redis)
        assert result == user_id

        # Manually expire the session
        await real_redis.delete(f"session:{session_id}")

        # Verify it's gone
        result = await get_session_user_id(session_id, signature, r=real_redis)
        assert result is None

    @pytest.mark.asyncio
    async def test_rate_limiting_real_redis(self, real_redis):
        """Test rate limiting with real Redis."""
        from app.rate_limit import check_rate_limit

        # Clear any leftover rate limit keys from previous runs
        import time as _time
        current_time = int(_time.time())
        window_start = current_time - (current_time % 60)
        for offset in range(-3, 4):
            stale_key = f"ratelimit:test:rate:1:{window_start + offset * 60}"
            await real_redis.delete(stale_key)

        # Test within limit
        allowed, remaining = await check_rate_limit(
            key="test:rate:1",
            max_requests=5,
            window_seconds=60,
            r=real_redis,
        )
        assert allowed is True
        assert remaining >= 0

        # Test at limit
        for i in range(4):
            await check_rate_limit(
                key="test:rate:1",
                max_requests=5,
                window_seconds=60,
                r=real_redis,
            )

        # Now should be blocked
        allowed, remaining = await check_rate_limit(
            key="test:rate:1",
            max_requests=5,
            window_seconds=60,
            r=real_redis,
        )
        assert allowed is False

    @pytest.mark.asyncio
    async def test_rq_job_queue(self):
        """Test that RQ jobs can be queued and retrieved with real Redis."""
        import redis
        from rq import Queue
        from app.config import get_settings

        settings = get_settings()
        # Use synchronous redis client for RQ (RQ is sync)
        sync_redis = redis.from_url(settings.redis_url)

        queue = Queue("test-queue", connection=sync_redis)

        # Enqueue a test job
        job = queue.enqueue("os.path.join", "/a", "/b")
        assert job is not None
        assert job.id is not None

        # Verify job is in queue
        assert len(queue) >= 1

        # Clean up
        queue.empty()
        sync_redis.close()


class TestRealFastAPI:
    """Test real FastAPI application with real PostgreSQL/Redis."""

    @pytest.fixture
    def real_client(self, real_engine, real_redis):
        """Create a test client with real database and Redis."""
        from fastapi.testclient import TestClient
        from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
        from app.database import get_db
        from app.main import app

        TestSession = async_sessionmaker(real_engine, class_=AsyncSession, expire_on_commit=False)

        async def override_get_db():
            db = TestSession()
            try:
                yield db
            finally:
                await db.close()

        app.dependency_overrides[get_db] = override_get_db
        with TestClient(app) as c:
            yield c
        app.dependency_overrides.clear()

    def test_health_endpoint(self, real_client):
        resp = real_client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_unauthenticated_access(self, real_client):
        resp = real_client.get("/api/repositories")
        assert resp.status_code == 401

    def test_auth_me_unauthenticated(self, real_client):
        resp = real_client.get("/api/auth/me")
        assert resp.status_code == 401
