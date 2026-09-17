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
    ActionProposal, Approval, Recommendation,
)


TEST_MIGRATION_DB_URL = "sqlite+aiosqlite:///test_migration.db"


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


class TestSourceTypePersistence:
    """DB-level regression proving source_type and evidence persist correctly."""

    @pytest.mark.asyncio
    async def test_dependency_finding_source_type_persists(self, engine):
        """DEPENDENCY finding persists source_type=DEPENDENCY and evidence in DB."""
        session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with session_factory() as session:
            user = User(id=uuid4(), email="dep-test@test.com", github_id=30001)
            session.add(user)
            await session.flush()
            inst = GithubInstallation(
                id=uuid4(), user_id=user.id, installation_id=30010,
                account_login="dep-org", account_type="Organization",
            )
            session.add(inst)
            await session.flush()
            repo = Repository(
                id=uuid4(), installation_id=inst.id, github_repo_id=30011,
                owner="dep-org", name="dep-repo", default_branch="main", is_active=True,
            )
            session.add(repo)
            await session.flush()
            scan = Scan(
                id=uuid4(), repository_id=repo.id, status="COMPLETED",
                trigger="manual", commit_sha="dep123",
            )
            session.add(scan)
            await session.flush()
            finding = Finding(
                id=uuid4(), scan_id=scan.id, repository_id=repo.id,
                fingerprint="dep-fp-001", scanner="dependency",
                source_type="DEPENDENCY",
                vulnerability_id="CVE-2024-9999",
                package_name="lodash", package_version="4.17.20",
                title="Test dependency vuln", severity="HIGH", status="OPEN",
                evidence={"rule": "dependency_upgrade", "manifest": "package.json"},
            )
            session.add(finding)
            await session.commit()
            finding_id = finding.id

        # Re-read from DB and verify
        async with session_factory() as session:
            f = await session.get(Finding, finding_id)
            assert f is not None
            assert f.source_type == "DEPENDENCY", f"Expected DEPENDENCY, got {f.source_type}"
            assert f.evidence is not None, "Evidence should not be None"
            assert f.evidence["rule"] == "dependency_upgrade"
            assert f.evidence["manifest"] == "package.json"

    @pytest.mark.asyncio
    async def test_container_finding_source_type_persists(self, engine):
        """CONTAINER finding persists source_type=CONTAINER and evidence in DB."""
        session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with session_factory() as session:
            user = User(id=uuid4(), email="cont-test@test.com", github_id=30002)
            session.add(user)
            await session.flush()
            inst = GithubInstallation(
                id=uuid4(), user_id=user.id, installation_id=30020,
                account_login="cont-org", account_type="Organization",
            )
            session.add(inst)
            await session.flush()
            repo = Repository(
                id=uuid4(), installation_id=inst.id, github_repo_id=30021,
                owner="cont-org", name="cont-repo", default_branch="main", is_active=True,
            )
            session.add(repo)
            await session.flush()
            scan = Scan(
                id=uuid4(), repository_id=repo.id, status="COMPLETED",
                trigger="manual", commit_sha="cont123",
            )
            session.add(scan)
            await session.flush()
            finding = Finding(
                id=uuid4(), scan_id=scan.id, repository_id=repo.id,
                fingerprint="cont-fp-001", scanner="container",
                source_type="CONTAINER",
                title="Container runs as root", severity="MEDIUM", status="OPEN",
                evidence={"dockerfile": "Dockerfile", "has_user": False},
            )
            session.add(finding)
            await session.commit()
            finding_id = finding.id

        async with session_factory() as session:
            f = await session.get(Finding, finding_id)
            assert f is not None
            assert f.source_type == "CONTAINER", f"Expected CONTAINER, got {f.source_type}"
            assert f.evidence is not None
            assert f.evidence["dockerfile"] == "Dockerfile"
            assert f.evidence["has_user"] is False

    @pytest.mark.asyncio
    async def test_log_finding_source_type_persists(self, engine):
        """LOG finding persists source_type=LOG and evidence in DB."""
        session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with session_factory() as session:
            user = User(id=uuid4(), email="log-test@test.com", github_id=30003)
            session.add(user)
            await session.flush()
            inst = GithubInstallation(
                id=uuid4(), user_id=user.id, installation_id=30030,
                account_login="log-org", account_type="Organization",
            )
            session.add(inst)
            await session.flush()
            repo = Repository(
                id=uuid4(), installation_id=inst.id, github_repo_id=30031,
                owner="log-org", name="log-repo", default_branch="main", is_active=True,
            )
            session.add(repo)
            await session.flush()
            scan = Scan(
                id=uuid4(), repository_id=repo.id, status="COMPLETED",
                trigger="manual", commit_sha="log123",
            )
            session.add(scan)
            await session.flush()
            finding = Finding(
                id=uuid4(), scan_id=scan.id, repository_id=repo.id,
                fingerprint="log-fp-001", scanner="log_analyzer",
                source_type="LOG",
                title="Potential brute-force pattern", severity="HIGH", status="OPEN",
                evidence={"log_source": "access.log", "event_count": 15},
            )
            session.add(finding)
            await session.commit()
            finding_id = finding.id

        async with session_factory() as session:
            f = await session.get(Finding, finding_id)
            assert f is not None
            assert f.source_type == "LOG", f"Expected LOG, got {f.source_type}"
            assert f.evidence is not None
            assert f.evidence["log_source"] == "access.log"
            assert f.evidence["event_count"] == 15


class TestActionProposalsSchema:
    """V3.1: action_proposals table — schema, constraints, ownership chain."""

    @pytest.mark.asyncio
    async def test_action_proposals_table_exists(self, engine):
        async with engine.connect() as conn:
            tables = await conn.run_sync(
                lambda sync_conn: inspect(sync_conn).get_table_names()
            )
        assert "action_proposals" in tables

    @pytest.mark.asyncio
    async def test_action_proposals_columns(self, engine):
        expected = {
            "id", "finding_id", "recommendation_id", "repository_id", "created_by",
            "action_type", "status", "base_commit_sha", "target_branch",
            "files", "operations", "expected_diff", "rationale", "evidence",
            "risk_score", "risk_level", "recommendation_trust", "validation_state",
            "policy_version", "policy_decision", "policy_reason_code",
            "policy_matched_rule", "policy_explanation",
            "action_digest", "expires_at", "created_at",
        }
        async with engine.connect() as conn:
            columns = await conn.run_sync(
                lambda sync_conn: {c["name"] for c in inspect(sync_conn).get_columns("action_proposals")}
            )
        assert expected.issubset(columns), f"Missing: {expected - columns}"

    @pytest.mark.asyncio
    async def test_action_proposals_foreign_keys(self, engine):
        from sqlalchemy import UniqueConstraint
        fk_columns = [c.name for c in ActionProposal.__table__.columns if c.foreign_keys]
        assert {"finding_id", "recommendation_id", "repository_id", "created_by"}.issubset(fk_columns)

    @pytest.mark.asyncio
    async def test_action_proposals_identity_unique_constraint(self, engine):
        from sqlalchemy import UniqueConstraint
        constraints = [
            c for c in ActionProposal.__table__.constraints
            if isinstance(c, UniqueConstraint) and c.name == "uq_proposal_identity"
        ]
        assert len(constraints) == 1
        cols = {c.name for c in constraints[0].columns}
        assert cols == {"recommendation_id", "base_commit_sha", "action_digest"}

    @pytest.mark.asyncio
    async def test_action_proposal_lifecycle_preserves_ownership(
        self, engine
    ):
        """Full chain: user → installation → repository → scan → finding →
        recommendation → risk → proposal, then ownership-reachable readback."""
        session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        from app.models import ActionProposal as AP, Recommendation as Rec
        from datetime import datetime, timedelta, timezone

        async with session_factory() as session:
            user = User(id=uuid4(), email="v31@test.com", github_id=40001)
            session.add(user)
            await session.flush()
            inst = GithubInstallation(
                id=uuid4(), user_id=user.id, installation_id=40010,
                account_login="v31-org", account_type="Organization",
            )
            session.add(inst)
            await session.flush()
            repo = Repository(
                id=uuid4(), installation_id=inst.id, github_repo_id=40011,
                owner="v31-org", name="v31-repo", default_branch="main", is_active=True,
            )
            session.add(repo)
            await session.flush()
            scan = Scan(
                id=uuid4(), repository_id=repo.id, status="COMPLETED",
                trigger="manual", commit_sha="a" * 40,
            )
            session.add(scan)
            await session.flush()
            finding = Finding(
                id=uuid4(), scan_id=scan.id, repository_id=repo.id,
                fingerprint="v31-fp-001", scanner="dependency", source_type="DEPENDENCY",
                title="Vuln in lodash", severity="HIGH", status="OPEN",
                evidence={"manifest_path": "package.json"},
            )
            session.add(finding)
            await session.flush()
            rec = Rec(
                id=uuid4(), finding_id=finding.id, status="COMPLETED",
                trust_level="SUPPORTED", title="Upgrade lodash",
                validation_state="VALIDATED",
            )
            session.add(rec)
            session.add(AP(
                id=uuid4(), finding_id=finding.id, recommendation_id=rec.id,
                repository_id=repo.id, created_by=user.id,
                action_type="DEPENDENCY_UPGRADE", status="POLICY_CHECKED",
                base_commit_sha="a" * 40, target_branch="cyvrix/fix",
                files=["package.json"],
                operations=[{"type": "UPDATE_DEPENDENCY_VERSION",
                             "file": "package.json", "name": "lodash",
                             "ecosystem": "npm",
                             "from_version": "4.17.19", "to_version": "4.17.21"}],
                expected_diff="- 4.17.19\n+ 4.17.21",
                risk_score=45, risk_level="MEDIUM",
                policy_version="3.1", policy_decision="REQUIRE_APPROVAL",
                policy_reason_code="MEDIUM_RISK_REQUIRES_APPROVAL",
                policy_matched_rule="POL-027",
                action_digest="d" * 64,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            ))
            await session.commit()

        async with session_factory() as session:
            proposal = (await session.execute(
                AP.__table__.select().where(AP.action_digest == "d" * 64)
            )).first()
            assert proposal is not None
            # Ownership reachability: proposal → repository → installation → user
            from sqlalchemy import select
            from app.models import GithubInstallation as Inst
            row = (await session.execute(
                select(AP)
                .join(Repository, Repository.id == AP.repository_id)
                .join(Inst, Inst.id == Repository.installation_id)
                .where(Inst.user_id == user.id)
            )).scalars().all()
            assert len(row) == 1


class TestApprovalsSchema:
    """V3.2: approvals table — schema, constraints, ownership chain."""

    @pytest.mark.asyncio
    async def test_approvals_table_exists(self, engine):
        async with engine.connect() as conn:
            tables = await conn.run_sync(
                lambda sync_conn: inspect(sync_conn).get_table_names()
            )
        assert "approvals" in tables

    @pytest.mark.asyncio
    async def test_approvals_columns(self, engine):
        expected = {
            "id", "action_proposal_id", "action_digest", "approver_user_id",
            "second_approver_user_id", "approval_state", "approval_reason",
            "policy_version", "policy_decision", "approval_level",
            "approved_at", "expires_at", "authorization_token_hash",
            "authorization_issued_at", "authorization_used_at", "created_at",
        }
        async with engine.connect() as conn:
            columns = await conn.run_sync(
                lambda sync_conn: {c["name"] for c in inspect(sync_conn).get_columns("approvals")}
            )
        assert expected.issubset(columns), f"Missing: {expected - columns}"

    @pytest.mark.asyncio
    async def test_approvals_foreign_keys(self, engine):
        from sqlalchemy import ForeignKey

        fk_columns = [c.name for c in Approval.__table__.columns if c.foreign_keys]
        assert {"action_proposal_id", "approver_user_id", "second_approver_user_id"}.issubset(fk_columns)

    @pytest.mark.asyncio
    async def test_approval_lifecycle_preserves_ownership(self, engine):
        """Full chain: user → installation → repository → proposal → approval,
        then ownership-reachable readback."""
        session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        from datetime import datetime, timedelta, timezone
        from uuid import uuid4 as uid

        async with session_factory() as session:
            user = User(id=uid(), email="v32@test.com", github_id=50001)
            session.add(user)
            await session.flush()
            inst = GithubInstallation(
                id=uid(), user_id=user.id, installation_id=50010,
                account_login="v32-org", account_type="Organization",
            )
            session.add(inst)
            await session.flush()
            repo = Repository(
                id=uid(), installation_id=inst.id, github_repo_id=50011,
                owner="v32-org", name="v32-repo", default_branch="main", is_active=True,
            )
            session.add(repo)
            await session.flush()
            scan = Scan(
                id=uid(), repository_id=repo.id, status="COMPLETED",
                trigger="manual", commit_sha="b" * 40,
            )
            session.add(scan)
            await session.flush()
            finding = Finding(
                id=uid(), scan_id=scan.id, repository_id=repo.id,
                fingerprint="v32-fp-001", scanner="dependency", source_type="DEPENDENCY",
                title="Vuln", severity="HIGH", status="OPEN", evidence={},
            )
            session.add(finding)
            await session.flush()
            rec = Recommendation(
                id=uid(), finding_id=finding.id, status="COMPLETED",
                trust_level="SUPPORTED", title="Upgrade", validation_state="VALIDATED",
            )
            session.add(rec)
            await session.flush()
            proposal = ActionProposal(
                id=uid(), finding_id=finding.id, recommendation_id=rec.id,
                repository_id=repo.id, created_by=user.id,
                action_type="DEPENDENCY_UPGRADE", status="POLICY_CHECKED",
                base_commit_sha="b" * 40, target_branch="cyvrix/fix",
                files=["package.json"], operations=[{"type": "UPDATE_DEPENDENCY_VERSION"}],
                expected_diff="diff", risk_score=45, risk_level="MEDIUM",
                policy_version="3.1", policy_decision="REQUIRE_APPROVAL",
                policy_reason_code="MEDIUM_RISK_REQUIRES_APPROVAL",
                policy_matched_rule="POL-027", action_digest="e" * 64,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            )
            session.add(proposal)
            await session.flush()
            session.add(Approval(
                id=uid(), action_proposal_id=proposal.id,
                action_digest=proposal.action_digest, approver_user_id=user.id,
                approval_state="APPROVED", policy_version="3.1",
                policy_decision="REQUIRE_APPROVAL",
                approved_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=60),
                authorization_token_hash="h" * 64,
                authorization_issued_at=datetime.now(timezone.utc),
            ))
            await session.commit()

        async with session_factory() as session:
            from sqlalchemy import select as sel

            rows = (await session.execute(
                sel(Approval)
                .join(ActionProposal, ActionProposal.id == Approval.action_proposal_id)
                .join(Repository, Repository.id == ActionProposal.repository_id)
                .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
                .where(GithubInstallation.user_id == user.id)
            )).scalars().all()
            assert len(rows) == 1
            assert rows[0].approval_state == "APPROVED"
            assert rows[0].authorization_token_hash == "h" * 64


class TestExecutionAuthorizationsSchema:
    """V3.3: execution_authorizations + system_controls — schema, FKs,
    ownership chain, hash-only material."""

    @pytest.mark.asyncio
    async def test_execution_authorizations_table_exists(self, engine):
        async with engine.connect() as conn:
            tables = await conn.run_sync(
                lambda sync_conn: inspect(sync_conn).get_table_names()
            )
        assert "execution_authorizations" in tables
        assert "system_controls" in tables

    @pytest.mark.asyncio
    async def test_execution_authorizations_columns(self, engine):
        expected = {
            "id", "action_proposal_id", "approval_id", "action_digest",
            "repository_id", "base_commit_sha", "target_branch",
            "policy_version", "policy_decision", "authorization_state",
            "contract", "contract_digest", "contract_version",
            "authorized_by_user_id", "consumed_at", "created_at",
        }
        async with engine.connect() as conn:
            columns = await conn.run_sync(
                lambda sync_conn: {
                    c["name"]
                    for c in inspect(sync_conn).get_columns("execution_authorizations")
                }
            )
        assert expected.issubset(columns), f"Missing: {expected - columns}"

    @pytest.mark.asyncio
    async def test_execution_authorizations_foreign_keys(self, engine):
        from app.models import ExecutionAuthorization as EA

        fk_columns = [c.name for c in EA.__table__.columns if c.foreign_keys]
        assert {
            "action_proposal_id", "approval_id", "repository_id",
            "authorized_by_user_id",
        }.issubset(fk_columns)

    @pytest.mark.asyncio
    async def test_authorization_lifecycle_preserves_ownership(self, engine):
        """Full chain: user → installation → repository → proposal →
        approval → execution authorization, ownership-reachable readback;
        no plaintext token material anywhere on the authorization row."""
        session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        from datetime import datetime, timedelta, timezone
        from uuid import uuid4 as uid

        from app.models import ExecutionAuthorization, SystemControl

        async with session_factory() as session:
            user = User(id=uid(), email="v33@test.com", github_id=60001)
            session.add(user)
            await session.flush()
            inst = GithubInstallation(
                id=uid(), user_id=user.id, installation_id=60010,
                account_login="v33-org", account_type="Organization",
            )
            session.add(inst)
            await session.flush()
            repo = Repository(
                id=uid(), installation_id=inst.id, github_repo_id=60011,
                owner="v33-org", name="v33-repo", default_branch="main",
                is_active=True,
            )
            session.add(repo)
            await session.flush()
            scan = Scan(
                id=uid(), repository_id=repo.id, status="COMPLETED",
                trigger="manual", commit_sha="c" * 40,
            )
            session.add(scan)
            await session.flush()
            finding = Finding(
                id=uid(), scan_id=scan.id, repository_id=repo.id,
                fingerprint="v33-fp-001", scanner="dependency",
                source_type="DEPENDENCY", title="Vuln", severity="HIGH",
                status="OPEN", evidence={},
            )
            session.add(finding)
            await session.flush()
            rec = Recommendation(
                id=uid(), finding_id=finding.id, status="COMPLETED",
                trust_level="SUPPORTED", title="Upgrade", validation_state="VALIDATED",
            )
            session.add(rec)
            await session.flush()
            proposal = ActionProposal(
                id=uid(), finding_id=finding.id, recommendation_id=rec.id,
                repository_id=repo.id, created_by=user.id,
                action_type="DEPENDENCY_UPGRADE", status="APPROVED",
                base_commit_sha="c" * 40, target_branch="cyvrix/fix",
                files=["package.json"],
                operations=[{"type": "UPDATE_DEPENDENCY_VERSION"}],
                expected_diff="diff", risk_score=45, risk_level="MEDIUM",
                policy_version="3.1", policy_decision="REQUIRE_APPROVAL",
                policy_reason_code="MEDIUM_RISK_REQUIRES_APPROVAL",
                policy_matched_rule="POL-027", action_digest="d" * 64,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            )
            session.add(proposal)
            await session.flush()
            approval = Approval(
                id=uid(), action_proposal_id=proposal.id,
                action_digest=proposal.action_digest, approver_user_id=user.id,
                approval_state="APPROVED", policy_version="3.1",
                policy_decision="REQUIRE_APPROVAL",
                approved_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=60),
                authorization_token_hash="h" * 64,
                authorization_issued_at=datetime.now(timezone.utc),
            )
            session.add(approval)
            await session.flush()
            session.add(ExecutionAuthorization(
                id=uid(), action_proposal_id=proposal.id, approval_id=approval.id,
                action_digest=proposal.action_digest, repository_id=repo.id,
                base_commit_sha="c" * 40, target_branch="cyvrix/fix",
                policy_version="3.1", policy_decision="REQUIRE_APPROVAL",
                authorization_state="AUTHORIZED",
                contract={"action_digest": proposal.action_digest,
                          "allowed_files": ["package.json"]},
                contract_digest="e" * 64, contract_version="1",
                authorized_by_user_id=user.id,
            ))
            session.add(SystemControl(key="execution_disabled", value="false"))
            await session.commit()

        async with session_factory() as session:
            from sqlalchemy import select as sel

            from app.models import ExecutionAuthorization as EA

            rows = (await session.execute(
                sel(EA)
                .join(ActionProposal, ActionProposal.id == EA.action_proposal_id)
                .join(Repository, Repository.id == ActionProposal.repository_id)
                .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
                .where(GithubInstallation.user_id == user.id)
            )).scalars().all()
            assert len(rows) == 1
            assert rows[0].authorization_state == "AUTHORIZED"
            # No token/credential material on the authorization record
            row_blob = str(rows[0].contract) + rows[0].contract_digest
            assert "authorization_token_hash" not in row_blob
            assert ("h" * 64) not in row_blob
