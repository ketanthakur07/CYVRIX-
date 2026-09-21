"""Comprehensive GitHub App integration tests using async SQLite."""
import os
import sys
import pytest
from uuid import uuid4
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from fastapi.testclient import TestClient

from app.database import Base, get_db
from app.models import User, GithubInstallation, Repository, Scan

TEST_DB_URL = "sqlite+aiosqlite:///test_github_integration.db"


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
        os.remove("test_github_integration.db")
    except OSError:
        pass


@pytest.fixture(autouse=True)
async def clean_db(engine):
    async with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(table.delete())
    yield


@pytest.fixture
def sf(engine):
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


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
    """Create an authenticated client for testing."""
    import asyncio

    async def _create_user():
        async with sf() as s:
            user = User(id=uuid4(), email="authenticated@test.local", github_id=99999, github_login="auth-user")
            s.add(user)
            await s.commit()
            await s.refresh(user)
            return user

    loop = asyncio.new_event_loop()
    user = loop.run_until_complete(_create_user())
    loop.close()

    from app.main import app
    from app.auth import get_current_user

    async def override_get_current_user():
        return user

    app.dependency_overrides[get_current_user] = override_get_current_user
    yield client
    app.dependency_overrides.pop(get_current_user, None)


async def _create_user(session, email="authenticated@test.local"):
    # Check if user already exists
    from sqlalchemy import select
    result = await session.execute(select(User).where(User.email == email))
    existing = result.scalar_one_or_none()
    if existing:
        return existing
    github_id = abs(hash(email)) % 900000 + 100000  # Unique github_id per email
    user = User(id=uuid4(), email=email, github_id=github_id, github_login=email.split("@")[0])
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def _create_installation(session, user_id, installation_id=12345, login="test-org"):
    inst = GithubInstallation(
        id=uuid4(), user_id=user_id, installation_id=installation_id,
        account_login=login, account_type="Organization",
    )
    session.add(inst)
    await session.commit()
    await session.refresh(inst)
    return inst


async def _create_repository(session, installation_id, github_repo_id=99999, name="test-repo", active=True):
    repo = Repository(
        id=uuid4(), installation_id=installation_id, github_repo_id=github_repo_id,
        owner="test-org", name=name, default_branch="main", is_active=active,
    )
    session.add(repo)
    await session.commit()
    await session.refresh(repo)
    return repo


MOCK_REPOS = [
    {"id": 11111, "name": "my-app", "owner": {"login": "test-user", "type": "User"}, "default_branch": "main"},
    {"id": 22222, "name": "my-lib", "owner": {"login": "test-user", "type": "User"}, "default_branch": "develop"},
]


class TestGitHubCallback:
    def test_callback_missing_installation_id(self, client):
        resp = client.get("/api/github/callback")
        assert resp.status_code == 422

    @patch("app.services.github.get_installation_repositories")
    def test_callback_valid_installation(self, mock_get_repos, client, sf):
        mock_get_repos.return_value = MOCK_REPOS
        resp = client.get("/api/github/callback?installation_id=12345", follow_redirects=False)
        assert resp.status_code == 307
        assert "error=not_authenticated" in resp.headers["location"]

    @patch("app.services.github.get_installation_repositories")
    def test_callback_github_auth_failure(self, mock_get_repos, client):
        from app.services.github import GitHubAuthError
        mock_get_repos.side_effect = GitHubAuthError("Auth failed")
        resp = client.get("/api/github/callback?installation_id=12345", follow_redirects=False)
        assert resp.status_code == 307
        assert "error=auth_failed" in resp.headers["location"]

    @patch("app.services.github.get_installation_repositories")
    def test_callback_github_unavailable(self, mock_get_repos, client):
        from app.services.github import GitHubUnavailableError
        mock_get_repos.side_effect = GitHubUnavailableError("GitHub down")
        resp = client.get("/api/github/callback?installation_id=12345", follow_redirects=False)
        assert resp.status_code == 307
        assert "error=github_unavailable" in resp.headers["location"]


class TestConnectURL:
    def test_connect_no_config_returns_500(self, client):
        resp = client.get("/api/github/connect", follow_redirects=False)
        assert resp.status_code == 500


class TestRepositoryActivation:
    def test_activate_repository(self, authenticated_client, sf):
        import asyncio
        loop = asyncio.new_event_loop()
        async def _setup():
            async with sf() as s:
                user = await _create_user(s)
                inst = await _create_installation(s, user.id)
                repo = await _create_repository(s, inst.id, active=False)
                return str(repo.id)
        repo_id = loop.run_until_complete(_setup())
        loop.close()

        resp = authenticated_client.post(f"/api/repositories/{repo_id}/activate")
        assert resp.status_code == 200
        assert resp.json()["is_active"] is True

    def test_deactivate_repository(self, authenticated_client, sf):
        import asyncio
        loop = asyncio.new_event_loop()
        async def _setup():
            async with sf() as s:
                user = await _create_user(s)
                inst = await _create_installation(s, user.id)
                repo = await _create_repository(s, inst.id, active=True)
                return str(repo.id)
        repo_id = loop.run_until_complete(_setup())
        loop.close()

        resp = authenticated_client.post(f"/api/repositories/{repo_id}/deactivate")
        assert resp.status_code == 200
        assert resp.json()["is_active"] is False

    def test_activate_nonexistent_repo(self, authenticated_client):
        resp = authenticated_client.post(f"/api/repositories/{uuid4()}/activate")
        assert resp.status_code == 404

    def test_activate_requires_auth(self, client):
        resp = client.post(f"/api/repositories/{uuid4()}/activate")
        assert resp.status_code == 401


class TestAuthorization:
    def test_no_user_returns_401(self, client):
        resp = client.get("/api/repositories")
        assert resp.status_code == 401

    def test_user_cannot_access_other_repo(self, client, sf):
        """Test IDOR: User A cannot access User B's repository."""
        import asyncio
        from app.main import app
        from app.auth import get_current_user

        # Create two users and their resources
        async def _setup():
            async with sf() as s:
                user_a = await _create_user(s, "user-a@test.com")
                user_b = await _create_user(s, "user-b@test.com")
                inst_a = await _create_installation(s, user_a.id, installation_id=30001, login="user-a")
                inst_b = await _create_installation(s, user_b.id, installation_id=30002, login="user-b")
                repo_a = await _create_repository(s, inst_a.id, github_repo_id=70001, name="repo-a")
                repo_b = await _create_repository(s, inst_b.id, github_repo_id=70002, name="repo-b")
                return str(repo_a.id), str(repo_b.id), user_a, user_b
        loop = asyncio.new_event_loop()
        repo_a_id, repo_b_id, user_a, user_b = loop.run_until_complete(_setup())
        loop.close()

        # User A should access their own repo
        async def override_a():
            return user_a
        app.dependency_overrides[get_current_user] = override_a
        try:
            resp = client.get(f"/api/repositories/{repo_a_id}")
            assert resp.status_code == 200
            # User A should NOT access User B's repo (IDOR)
            resp = client.get(f"/api/repositories/{repo_b_id}")
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.pop(get_current_user, None)

        # User B should access their own repo
        async def override_b():
            return user_b
        app.dependency_overrides[get_current_user] = override_b
        try:
            resp = client.get(f"/api/repositories/{repo_b_id}")
            assert resp.status_code == 200
            # User B should NOT access User A's repo (IDOR)
            resp = client.get(f"/api/repositories/{repo_a_id}")
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.pop(get_current_user, None)


class TestScanIntegration:
    def test_scan_active_repo_creates_record(self, authenticated_client, sf):
        import asyncio
        loop = asyncio.new_event_loop()
        async def _setup():
            async with sf() as s:
                user = await _create_user(s)
                inst = await _create_installation(s, user.id)
                repo = await _create_repository(s, inst.id, active=True)
                return str(repo.id)
        repo_id = loop.run_until_complete(_setup())
        loop.close()

        mock_worker = MagicMock()
        with patch.dict("sys.modules", {"app.worker": mock_worker}):
            resp = authenticated_client.post("/api/scans", json={"repository_id": repo_id})
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "QUEUED"
            assert data["trigger"] == "manual"
            mock_worker.enqueue_scan.assert_called_once_with(data["id"])

    def test_scan_inactive_repo_rejected(self, authenticated_client, sf):
        import asyncio
        loop = asyncio.new_event_loop()
        async def _setup():
            async with sf() as s:
                user = await _create_user(s)
                inst = await _create_installation(s, user.id)
                repo = await _create_repository(s, inst.id, active=False)
                return str(repo.id)
        repo_id = loop.run_until_complete(_setup())
        loop.close()

        resp = authenticated_client.post("/api/scans", json={"repository_id": repo_id})
        assert resp.status_code == 400
        assert "inactive" in resp.json()["detail"].lower()

    def test_concurrent_scan_rejected(self, authenticated_client, sf):
        import asyncio
        loop = asyncio.new_event_loop()
        async def _setup():
            async with sf() as s:
                user = await _create_user(s)
                inst = await _create_installation(s, user.id)
                repo = await _create_repository(s, inst.id, active=True)
                return str(repo.id)
        repo_id = loop.run_until_complete(_setup())
        loop.close()

        mock_worker = MagicMock()
        with patch.dict("sys.modules", {"app.worker": mock_worker}):
            resp1 = authenticated_client.post("/api/scans", json={"repository_id": repo_id})
            assert resp1.status_code == 200

            resp2 = authenticated_client.post("/api/scans", json={"repository_id": repo_id})
            assert resp2.status_code == 409
            assert "already in progress" in resp2.json()["detail"]

    def test_scan_requires_auth(self, client):
        resp = client.post("/api/scans", json={"repository_id": str(uuid4())})
        assert resp.status_code == 401


class TestTokenSecurity:
    def test_installation_tokens_never_in_response(self, authenticated_client, sf):
        import asyncio
        loop = asyncio.new_event_loop()
        async def _setup():
            async with sf() as s:
                user = await _create_user(s)
                await _create_installation(s, user.id)
        loop.run_until_complete(_setup())
        loop.close()

        resp = authenticated_client.get("/api/github/installations")
        data = resp.json()
        assert len(data) == 1
        assert "token" not in str(data).lower()
        assert "access_token" not in str(data).lower()

    def test_github_credentials_not_in_callback_response(self, client):
        resp = client.get("/api/github/callback?installation_id=12345", follow_redirects=False)
        assert resp.status_code in (307, 400, 500)
        if resp.status_code == 307:
            assert "token" not in resp.headers.get("location", "").lower()


class TestGitHubService:
    def test_jwt_creation_without_config(self):
        from app.services.github import _create_jwt, GitHubAuthError
        # NOTE: deliberately NO get_settings.cache_clear() here. Clearing
        # the lru_cache swaps the settings singleton for a fresh object,
        # while modules that captured `settings = get_settings()` at import
        # time (e.g. routes/execution_runs.py) keep the original — later
        # suites patching executor_service_token on the new object would
        # then hit EXECUTOR_DISABLED at request time. The patch() below
        # fully controls the config this test needs.
        with patch("app.services.github.settings") as mock_settings:
            mock_settings.github_app_id = ""
            mock_settings.github_app_private_key = ""
            with pytest.raises(GitHubAuthError):
                _create_jwt()

    def test_github_service_error_classes(self):
        from app.services.github import GitHubAuthError, GitHubRateLimitError, GitHubUnavailableError
        assert issubclass(GitHubAuthError, Exception)
        assert issubclass(GitHubRateLimitError, Exception)
        assert issubclass(GitHubUnavailableError, Exception)


class TestRepositoryList:
    def test_list_repositories_empty(self, authenticated_client):
        resp = authenticated_client.get("/api/repositories")
        assert resp.status_code == 200
        assert resp.json() == []
