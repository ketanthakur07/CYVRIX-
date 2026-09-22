import sys
import os
import json
import pytest
from uuid import uuid4
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.database import Base, get_db
from app.models import User, GithubInstallation, Repository, Scan, Finding
from app.auth import get_current_user

TEST_DB_URL = "sqlite+aiosqlite:///test_cyvrix.db"


@pytest.fixture(scope="session")
async def engine():
    """Create a session-scoped async SQLite engine."""
    eng = create_async_engine(TEST_DB_URL)

    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield eng

    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await eng.dispose()
    try:
        os.remove("test_cyvrix.db")
    except OSError:
        pass


@pytest.fixture(autouse=True)
async def clean_db(engine):
    """Clean all tables between tests, then provision the V3.7
    operational_state control row exactly as migration 010 does in
    production. (execution_disabled continues to be seeded by the tests
    that exercise kill-switch-gated paths, as in V3.3–V3.6.)

    Services still fail closed when rows are missing/unreadable —
    tests that exercise those paths delete the rows explicitly."""
    from app.models import SystemControl
    async with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(table.delete())
        await conn.execute(
            __import__("sqlalchemy").insert(SystemControl).values(
                {"key": "operational_state", "value": "NORMAL"},
            )
        )
    yield


@pytest.fixture
def session_factory(engine):
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture
async def client(engine):
    """Create test client with async test database override."""
    TestSession = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            await db.close()

    from fastapi.testclient import TestClient
    from app.main import app
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
async def test_user(session_factory):
    """Create a test user."""
    async with session_factory() as session:
        user = User(
            id=uuid4(),
            email="admin@cyvrix.local",
            github_id=12345,
            github_login="test-user",
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


@pytest.fixture
async def test_user_b(session_factory):
    """Create a second test user for IDOR testing."""
    async with session_factory() as session:
        user = User(
            id=uuid4(),
            email="user-b@cyvrix.local",
            github_id=67890,
            github_login="test-user-b",
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


@pytest.fixture
async def test_installation(session_factory, test_user):
    """Create a test GitHub installation."""
    async with session_factory() as session:
        installation = GithubInstallation(
            id=uuid4(),
            user_id=test_user.id,
            installation_id=12345,
            account_login="test-org",
            account_type="Organization",
        )
        session.add(installation)
        await session.commit()
        await session.refresh(installation)
        return installation


@pytest.fixture
async def test_installation_b(session_factory, test_user_b):
    """Create a test GitHub installation for user B."""
    async with session_factory() as session:
        installation = GithubInstallation(
            id=uuid4(),
            user_id=test_user_b.id,
            installation_id=67890,
            account_login="user-b-org",
            account_type="Organization",
        )
        session.add(installation)
        await session.commit()
        await session.refresh(installation)
        return installation


@pytest.fixture
async def test_repository(session_factory, test_installation):
    """Create a test repository."""
    async with session_factory() as session:
        repo = Repository(
            id=uuid4(),
            installation_id=test_installation.id,
            github_repo_id=99999,
            owner="test-org",
            name="test-repo",
            default_branch="main",
            is_active=True,
        )
        session.add(repo)
        await session.commit()
        await session.refresh(repo)
        return repo


@pytest.fixture
async def test_repository_b(session_factory, test_installation_b):
    """Create a test repository for user B."""
    async with session_factory() as session:
        repo = Repository(
            id=uuid4(),
            installation_id=test_installation_b.id,
            github_repo_id=99998,
            owner="user-b-org",
            name="test-repo-b",
            default_branch="main",
            is_active=True,
        )
        session.add(repo)
        await session.commit()
        await session.refresh(repo)
        return repo


@pytest.fixture
async def test_inactive_repository(session_factory, test_installation):
    """Create a test repository that is inactive."""
    async with session_factory() as session:
        repo = Repository(
            id=uuid4(),
            installation_id=test_installation.id,
            github_repo_id=99997,
            owner="test-org",
            name="inactive-repo",
            default_branch="main",
            is_active=False,
        )
        session.add(repo)
        await session.commit()
        await session.refresh(repo)
        return repo


@pytest.fixture
def authenticated_client(client, test_user):
    """Create an authenticated test client by overriding get_current_user.

    This is the proper way to test authenticated endpoints:
    - Tests explicitly specify which user is authenticated
    - No hidden default user
    - Clean separation of auth and authorization testing
    """
    from fastapi.testclient import TestClient
    from app.main import app

    async def override_get_current_user():
        return test_user

    app.dependency_overrides[get_current_user] = override_get_current_user
    yield client
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
def authenticated_client_b(client, test_user_b):
    """Create an authenticated test client for user B."""
    from fastapi.testclient import TestClient
    from app.main import app

    async def override_get_current_user():
        return test_user_b

    app.dependency_overrides[get_current_user] = override_get_current_user
    yield client
    app.dependency_overrides.pop(get_current_user, None)
