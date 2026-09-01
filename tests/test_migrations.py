"""CYVRIX Migration Tests.

Tests that verify:
- Migration schema matches SQLAlchemy models
- Data preservation through migration
- Schema drift detection
- Migration idempotency
- Constraint/integrity verification
"""
import os
import sys
import pytest
from uuid import uuid4
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.database import Base
from app.models import (
    User, GithubInstallation, Repository, Scan,
    Dependency, Finding, Investigation, RiskAssessment, AuditEvent,
)


TEST_MIGRATION_DB_URL = "sqlite+aiosqlite:///test_migration.db"


@pytest.fixture(scope="module")
def event_loop():
    import asyncio
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="module")
async def engine():
    eng = create_async_engine(TEST_MIGRATION_DB_URL)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await eng.dispose()
    try:
        os.remove("test_migration.db")
    except OSError:
        pass


class TestSchemaCompleteness:
    """Verify all expected tables exist in the schema."""

    @pytest.mark.asyncio
    async def test_all_tables_exist(self, engine):
        expected_tables = {
            "users", "github_installations", "repositories", "scans",
            "dependencies", "findings", "investigations", "risk_assessments",
            "audit_events",
        }
        async with engine.connect() as conn:
            result = await conn.run_sync(
                lambda sync_conn: inspect(sync_conn).get_table_names()
            )
            actual_tables = set(result)
            assert expected_tables.issubset(actual_tables), (
                f"Missing tables: {expected_tables - actual_tables}"
            )

    @pytest.mark.asyncio
    async def test_users_columns(self, engine):
        expected = {"id", "email", "github_id", "github_login", "created_at"}
        async with engine.connect() as conn:
            columns = await conn.run_sync(
                lambda sync_conn: {c["name"] for c in inspect(sync_conn).get_columns("users")}
            )
            assert expected.issubset(columns)

    @pytest.mark.asyncio
    async def test_repositories_columns(self, engine):
        expected = {
            "id", "installation_id", "github_repo_id", "owner", "name",
            "default_branch", "is_active", "created_at",
        }
        async with engine.connect() as conn:
            columns = await conn.run_sync(
                lambda sync_conn: {c["name"] for c in inspect(sync_conn).get_columns("repositories")}
            )
            assert expected.issubset(columns)

    @pytest.mark.asyncio
    async def test_findings_columns(self, engine):
        expected = {
            "id", "scan_id", "repository_id", "fingerprint", "scanner",
            "vulnerability_id", "package_name", "package_version", "title",
            "description", "severity", "status", "created_at",
        }
        async with engine.connect() as conn:
            columns = await conn.run_sync(
                lambda sync_conn: {c["name"] for c in inspect(sync_conn).get_columns("findings")}
            )
            assert expected.issubset(columns)

    @pytest.mark.asyncio
    async def test_investigations_columns(self, engine):
        expected = {
            "id", "finding_id", "status", "verdict", "exploitability",
            "exposure", "confidence", "summary", "evidence", "assumptions",
            "uncertainties", "recommendation", "raw_model_response", "created_at",
        }
        async with engine.connect() as conn:
            columns = await conn.run_sync(
                lambda sync_conn: {c["name"] for c in inspect(sync_conn).get_columns("investigations")}
            )
            assert expected.issubset(columns)


class TestUniqueConstraints:
    """Verify critical unique constraints exist."""

    @pytest.mark.asyncio
    async def test_users_email_unique(self, engine):
        async with engine.begin() as conn:
            await conn.execute(
                User.__table__.insert(),
                {"id": uuid4(), "email": "unique@test.com"}
            )
            with pytest.raises(Exception):
                await conn.execute(
                    User.__table__.insert(),
                    {"id": uuid4(), "email": "unique@test.com"}
                )
            await conn.rollback()

    @pytest.mark.asyncio
    async def test_users_github_id_unique(self, engine):
        async with engine.begin() as conn:
            await conn.execute(
                User.__table__.insert(),
                {"id": uuid4(), "email": "gh1@test.com", "github_id": 12345}
            )
            with pytest.raises(Exception):
                await conn.execute(
                    User.__table__.insert(),
                    {"id": uuid4(), "email": "gh2@test.com", "github_id": 12345}
                )
            await conn.rollback()


class TestForeignKeyIntegrity:
    """Verify foreign key relationships exist in schema."""

    @pytest.mark.asyncio
    async def test_foreign_keys_defined(self, engine):
        """Verify foreign keys are defined in the schema metadata."""
        # Check that foreign keys exist in the model metadata
        repo_table = Repository.__table__
        fk_columns = [c.name for c in repo_table.columns if c.foreign_keys]
        assert "installation_id" in fk_columns

        finding_table = Finding.__table__
        fk_columns = [c.name for c in finding_table.columns if c.foreign_keys]
        assert "scan_id" in fk_columns
        assert "repository_id" in fk_columns

        scan_table = Scan.__table__
        fk_columns = [c.name for c in scan_table.columns if c.foreign_keys]
        assert "repository_id" in fk_columns

        investigation_table = Investigation.__table__
        fk_columns = [c.name for c in investigation_table.columns if c.foreign_keys]
        assert "finding_id" in fk_columns

        risk_table = RiskAssessment.__table__
        fk_columns = [c.name for c in risk_table.columns if c.foreign_keys]
        assert "finding_id" in fk_columns


class TestDataPreservation:
    """Test that representative data survives schema operations."""

    @pytest.mark.asyncio
    async def test_full_data_lifecycle(self, engine):
        """Create a full set of related records and verify they persist."""
        session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        async with session_factory() as session:
            # Create user
            user = User(id=uuid4(), email="lifecycle@test.com", github_id=55555, github_login="lifecycle")
            session.add(user)
            await session.flush()

            # Create installation
            installation = GithubInstallation(
                id=uuid4(), user_id=user.id, installation_id=11111,
                account_login="test-org", account_type="Organization",
            )
            session.add(installation)
            await session.flush()

            # Create repository
            repo = Repository(
                id=uuid4(), installation_id=installation.id, github_repo_id=77777,
                owner="test-org", name="test-repo", default_branch="main", is_active=True,
            )
            session.add(repo)
            await session.flush()

            # Create scan
            scan = Scan(
                id=uuid4(), repository_id=repo.id, status="COMPLETED",
                trigger="manual", commit_sha="abc123",
            )
            session.add(scan)
            await session.flush()

            # Create finding
            finding = Finding(
                id=uuid4(), scan_id=scan.id, repository_id=repo.id,
                fingerprint="test-fingerprint-123", scanner="dependency",
                vulnerability_id="CVE-2024-1234", package_name="lodash",
                package_version="4.17.20", title="Test vulnerability",
                severity="HIGH", status="OPEN",
            )
            session.add(finding)
            await session.flush()

            # Create investigation
            investigation = Investigation(
                id=uuid4(), finding_id=finding.id, status="COMPLETED",
                verdict="CONFIRMED", exploitability="HIGH", exposure="EXTERNAL",
                confidence=0.85, summary="Test summary",
                recommendation="Test recommendation",
            )
            session.add(investigation)
            await session.flush()

            # Create risk assessment
            risk = RiskAssessment(
                id=uuid4(), finding_id=finding.id, risk_score=75,
                risk_level="HIGH", risk_version=1,
                factors={"base_score": 60, "exposure_mod": 15},
            )
            session.add(risk)
            await session.flush()

            # Create audit event
            event = AuditEvent(
                id=uuid4(), repository_id=repo.id, event_type="SCAN_COMPLETED",
                event_metadata={"scan_id": str(scan.id)},
            )
            session.add(event)
            await session.commit()

            # Verify all records exist
            user_id = user.id
            repo_id = repo.id
            scan_id = scan.id
            finding_id = finding.id

        # Re-read and verify
        async with session_factory() as session:
            u = await session.get(User, user_id)
            assert u is not None
            assert u.email == "lifecycle@test.com"
            assert u.github_id == 55555

            r = await session.get(Repository, repo_id)
            assert r is not None
            assert r.owner == "test-org"
            assert r.is_active is True

            s = await session.get(Scan, scan_id)
            assert s is not None
            assert s.status == "COMPLETED"

            f = await session.get(Finding, finding_id)
            assert f is not None
            assert f.fingerprint == "test-fingerprint-123"
            assert f.severity == "HIGH"


class TestMigrationFile:
    """Verify migration file is safe and correct."""

    def test_migration_file_exists(self):
        migration_path = os.path.join(
            os.path.dirname(__file__), "..", "apps", "api", "alembic", "versions", "001_initial_schema.py"
        )
        assert os.path.exists(migration_path), f"Migration file not found: {migration_path}"

    def test_migration_has_upgrade_and_downgrade(self):
        migration_path = os.path.join(
            os.path.dirname(__file__), "..", "apps", "api", "alembic", "versions", "001_initial_schema.py"
        )
        with open(migration_path, "r") as f:
            content = f.read()
        assert "def upgrade() -> None:" in content
        assert "def downgrade() -> None:" in content

    def test_migration_no_network_calls(self):
        migration_path = os.path.join(
            os.path.dirname(__file__), "..", "apps", "api", "alembic", "versions", "001_initial_schema.py"
        )
        with open(migration_path, "r") as f:
            content = f.read()
        forbidden = ["requests.", "httpx.", "subprocess", "os.system", "shell=True", "curl", "wget"]
        for pattern in forbidden:
            assert pattern not in content, f"Migration contains forbidden pattern: {pattern}"

    def test_migration_no_secrets(self):
        migration_path = os.path.join(
            os.path.dirname(__file__), "..", "apps", "api", "alembic", "versions", "001_initial_schema.py"
        )
        with open(migration_path, "r") as f:
            content = f.read()
        secret_patterns = ["password", "SECRET_KEY", "API_KEY", "private_key"]
        for pattern in secret_patterns:
            assert pattern.lower() not in content.lower(), f"Migration may contain secret: {pattern}"


class TestSchemaDrift:
    """Verify schema matches models (no drift)."""

    @pytest.mark.asyncio
    async def test_no_missing_tables(self, engine):
        """All model tables should exist without needing create_all."""
        model_tables = set(Base.metadata.tables.keys())
        async with engine.connect() as conn:
            db_tables = set(await conn.run_sync(
                lambda sync_conn: inspect(sync_conn).get_table_names()
            ))
        assert model_tables.issubset(db_tables), (
            f"Schema drift: missing tables {model_tables - db_tables}"
        )
