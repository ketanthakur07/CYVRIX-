"""CYVRIX Integration Tests.

Tests the full API + Database integration including:
- Authentication flow
- Repository CRUD
- Scan lifecycle
- Finding persistence
- Authorization (IDOR)
- Error handling
"""
import os
import sys
import pytest
from uuid import uuid4
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from fastapi.testclient import TestClient
from app.database import Base, get_db
from app.auth import get_current_user
from app.models import (
    User, GithubInstallation, Repository, Scan,
    Finding, Investigation, RiskAssessment,
)

TEST_DB_URL = "sqlite+aiosqlite:///test_integration.db"


@pytest.fixture(scope="module")
def event_loop():
    import asyncio
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="module")
async def engine():
    eng = create_async_engine(TEST_DB_URL)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await eng.dispose()
    try:
        os.remove("test_integration.db")
    except OSError:
        pass


@pytest.fixture(autouse=True)
async def clean_db(engine):
    async with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(table.delete())
    yield


@pytest.fixture
def client(engine):
    TestSession = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            await db.close()

    from app.main import app
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def authenticated_client(client, sf):
    import asyncio
    from app.main import app
    from app.auth import get_current_user

    async def _create_user():
        async with sf() as s:
            user = User(
                id=uuid4(), email="integration@test.local",
                github_id=88888, github_login="integration-user",
            )
            s.add(user)
            await s.commit()
            await s.refresh(user)
            return user

    loop = asyncio.new_event_loop()
    user = loop.run_until_complete(_create_user())
    loop.close()

    async def override_get_current_user():
        return user

    app.dependency_overrides[get_current_user] = override_get_current_user
    yield client
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
def sf(engine):
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class TestHealthCheck:
    def test_health_endpoint(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestAuthenticationFlow:
    def test_unauthenticated_access_rejected(self, client):
        resp = client.get("/api/repositories")
        assert resp.status_code == 401

    def test_authenticated_access_allowed(self, authenticated_client):
        resp = authenticated_client.get("/api/repositories")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_auth_me_returns_user(self, authenticated_client):
        resp = authenticated_client.get("/api/auth/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == "integration@test.local"
        assert data["github_login"] == "integration-user"

    def test_logout_destroys_session(self, authenticated_client):
        resp = authenticated_client.post("/api/auth/logout")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True


class TestRepositoryLifecycle:
    def test_create_and_list_repository(self, authenticated_client, sf):
        import asyncio
        from app.main import app
        from app.auth import get_current_user

        # Setup: create user, installation, repo
        async def _setup():
            async with sf() as s:
                user = User(id=uuid4(), email="repo-test@test.local", github_id=77777)
                s.add(user)
                await s.flush()
                inst = GithubInstallation(
                    id=uuid4(), user_id=user.id, installation_id=44444,
                    account_login="test-org", account_type="Organization",
                )
                s.add(inst)
                await s.flush()
                repo = Repository(
                    id=uuid4(), installation_id=inst.id, github_repo_id=55555,
                    owner="test-org", name="test-repo", default_branch="main",
                    is_active=True,
                )
                s.add(repo)
                await s.commit()
                return str(repo.id), user

        loop = asyncio.new_event_loop()
        repo_id, user = loop.run_until_complete(_setup())
        loop.close()

        # Override auth for this user
        async def override():
            return user
        app.dependency_overrides[get_current_user] = override

        try:
            # List repositories
            resp = authenticated_client.get("/api/repositories")
            assert resp.status_code == 200
            repos = resp.json()
            assert len(repos) == 1
            assert repos[0]["repository"]["owner"] == "test-org"

            # Get single repository
            resp = authenticated_client.get(f"/api/repositories/{repo_id}")
            assert resp.status_code == 200
            assert resp.json()["repository"]["name"] == "test-repo"
        finally:
            app.dependency_overrides.pop(get_current_user, None)


class TestScanLifecycle:
    def test_scan_flow(self, authenticated_client, sf):
        import asyncio
        from app.main import app
        from app.auth import get_current_user

        async def _setup():
            async with sf() as s:
                user = User(id=uuid4(), email="scan-test@test.local", github_id=66666)
                s.add(user)
                await s.flush()
                inst = GithubInstallation(
                    id=uuid4(), user_id=user.id, installation_id=33333,
                    account_login="scan-org", account_type="Organization",
                )
                s.add(inst)
                await s.flush()
                repo = Repository(
                    id=uuid4(), installation_id=inst.id, github_repo_id=44444,
                    owner="scan-org", name="scan-repo", default_branch="main",
                    is_active=True,
                )
                s.add(repo)
                await s.commit()
                return str(repo.id), user

        loop = asyncio.new_event_loop()
        repo_id, user = loop.run_until_complete(_setup())
        loop.close()

        async def override():
            return user
        app.dependency_overrides[get_current_user] = override

        try:
            mock_worker = MagicMock()
            with patch.dict("sys.modules", {"app.worker": mock_worker}):
                # Start scan
                resp = authenticated_client.post(
                    "/api/scans", json={"repository_id": repo_id}
                )
                assert resp.status_code == 200
                scan_data = resp.json()
                assert scan_data["status"] == "QUEUED"
                scan_id = scan_data["id"]

                # Get scan status
                resp = authenticated_client.get(f"/api/scans/{scan_id}")
                assert resp.status_code == 200

                # Get scan findings (empty initially)
                resp = authenticated_client.get(f"/api/scans/{scan_id}/findings")
                assert resp.status_code == 200
                assert resp.json() == []
        finally:
            app.dependency_overrides.pop(get_current_user, None)


class TestAuthorizationIDOR:
    def test_user_cannot_access_other_users_repo(self, client, sf):
        import asyncio
        from app.main import app
        from app.auth import get_current_user

        async def _setup():
            async with sf() as s:
                # User A
                user_a = User(id=uuid4(), email="idor-a@test.local", github_id=11111)
                s.add(user_a)
                await s.flush()
                inst_a = GithubInstallation(
                    id=uuid4(), user_id=user_a.id, installation_id=11112,
                    account_login="org-a", account_type="Organization",
                )
                s.add(inst_a)
                await s.flush()
                repo_a = Repository(
                    id=uuid4(), installation_id=inst_a.id, github_repo_id=11113,
                    owner="org-a", name="repo-a", default_branch="main", is_active=True,
                )
                s.add(repo_a)

                # User B
                user_b = User(id=uuid4(), email="idor-b@test.local", github_id=22222)
                s.add(user_b)
                await s.flush()
                inst_b = GithubInstallation(
                    id=uuid4(), user_id=user_b.id, installation_id=22223,
                    account_login="org-b", account_type="Organization",
                )
                s.add(inst_b)
                await s.flush()
                repo_b = Repository(
                    id=uuid4(), installation_id=inst_b.id, github_repo_id=22224,
                    owner="org-b", name="repo-b", default_branch="main", is_active=True,
                )
                s.add(repo_b)
                await s.commit()

                return str(repo_a.id), str(repo_b.id), user_a, user_b

        loop = asyncio.new_event_loop()
        repo_a_id, repo_b_id, user_a, user_b = loop.run_until_complete(_setup())
        loop.close()

        # User A accessing their own repo
        async def override_a():
            return user_a
        app.dependency_overrides[get_current_user] = override_a
        try:
            resp = client.get(f"/api/repositories/{repo_a_id}")
            assert resp.status_code == 200

            # User A trying to access User B's repo (IDOR)
            resp = client.get(f"/api/repositories/{repo_b_id}")
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.pop(get_current_user, None)

        # User B accessing their own repo
        async def override_b():
            return user_b
        app.dependency_overrides[get_current_user] = override_b
        try:
            resp = client.get(f"/api/repositories/{repo_b_id}")
            assert resp.status_code == 200

            # User B trying to access User A's repo (IDOR)
            resp = client.get(f"/api/repositories/{repo_a_id}")
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.pop(get_current_user, None)


class TestErrorHandling:
    def test_invalid_uuid_returns_422(self, authenticated_client):
        resp = authenticated_client.get("/api/repositories/not-a-uuid")
        assert resp.status_code == 422

    def test_nonexistent_resource_returns_404(self, authenticated_client):
        resp = authenticated_client.get(f"/api/repositories/{uuid4()}")
        assert resp.status_code == 404

    def test_inactive_repo_cannot_be_scanned(self, authenticated_client, sf):
        import asyncio
        from app.main import app
        from app.auth import get_current_user

        async def _setup():
            async with sf() as s:
                user = User(id=uuid4(), email="inactive@test.local", github_id=99999)
                s.add(user)
                await s.flush()
                inst = GithubInstallation(
                    id=uuid4(), user_id=user.id, installation_id=88888,
                    account_login="inactive-org", account_type="Organization",
                )
                s.add(inst)
                await s.flush()
                repo = Repository(
                    id=uuid4(), installation_id=inst.id, github_repo_id=77777,
                    owner="inactive-org", name="inactive-repo", default_branch="main",
                    is_active=False,
                )
                s.add(repo)
                await s.commit()
                return str(repo.id), user

        loop = asyncio.new_event_loop()
        repo_id, user = loop.run_until_complete(_setup())
        loop.close()

        async def override():
            return user
        app.dependency_overrides[get_current_user] = override

        try:
            resp = authenticated_client.post(
                "/api/scans", json={"repository_id": repo_id}
            )
            assert resp.status_code == 400
            assert "inactive" in resp.json()["detail"].lower()
        finally:
            app.dependency_overrides.pop(get_current_user, None)


class TestDashboardAggregation:
    def test_dashboard_returns_correct_structure(self, authenticated_client):
        resp = authenticated_client.get("/api/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_repositories" in data
        assert "total_scans" in data
        assert "total_findings" in data
        assert "findings_by_severity" in data
        assert "recent_scans" in data
        assert isinstance(data["findings_by_severity"], list)
        assert isinstance(data["recent_scans"], list)
