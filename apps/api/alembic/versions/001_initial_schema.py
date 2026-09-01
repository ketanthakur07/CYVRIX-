"""initial schema - CYVRIX V1 baseline

Revision ID: 001
Revises: None
Create Date: 2026-08-28

This is the initial baseline migration representing the complete CYVRIX V1 schema.
It was hand-written to accurately represent the current SQLAlchemy models.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── users ────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.Text(), nullable=False, unique=True),
        sa.Column("github_id", sa.Integer(), nullable=True, unique=True),
        sa.Column("github_login", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ── github_installations ─────────────────────────────────────────
    op.create_table(
        "github_installations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("installation_id", sa.BigInteger(), nullable=False, unique=True),
        sa.Column("account_login", sa.Text(), nullable=False),
        sa.Column("account_type", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_github_installations_user_id", "github_installations", ["user_id"])

    # ── repositories ─────────────────────────────────────────────────
    op.create_table(
        "repositories",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("installation_id", UUID(as_uuid=True), sa.ForeignKey("github_installations.id"), nullable=False),
        sa.Column("github_repo_id", sa.BigInteger(), nullable=False, unique=True),
        sa.Column("owner", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("default_branch", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=True, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("owner", "name", name="uq_owner_name"),
    )
    op.create_index("ix_repositories_installation_id", "repositories", ["installation_id"])

    # ── scans ────────────────────────────────────────────────────────
    op.create_table(
        "scans",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("repository_id", UUID(as_uuid=True), sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="QUEUED"),
        sa.Column("trigger", sa.Text(), nullable=False, server_default="manual"),
        sa.Column("error_reason", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("commit_sha", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_scans_repository_id", "scans", ["repository_id"])

    # ── dependencies ─────────────────────────────────────────────────
    op.create_table(
        "dependencies",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("version", sa.Text(), nullable=False),
        sa.Column("ecosystem", sa.Text(), nullable=False),
        sa.Column("manifest_path", sa.Text(), nullable=False),
    )
    op.create_index("ix_dependencies_scan_id", "dependencies", ["scan_id"])

    # ── findings ─────────────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("repository_id", UUID(as_uuid=True), sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("fingerprint", sa.Text(), nullable=False),
        sa.Column("scanner", sa.Text(), nullable=False, server_default="dependency"),
        sa.Column("vulnerability_id", sa.Text(), nullable=True),
        sa.Column("package_name", sa.Text(), nullable=True),
        sa.Column("package_version", sa.Text(), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="OPEN"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("repository_id", "fingerprint", name="uq_repo_fingerprint"),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_repository_id", "findings", ["repository_id"])

    # ── investigations ───────────────────────────────────────────────
    op.create_table(
        "investigations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("finding_id", UUID(as_uuid=True), sa.ForeignKey("findings.id"), nullable=False, unique=True),
        sa.Column("status", sa.Text(), nullable=False, server_default="PENDING"),
        sa.Column("verdict", sa.Text(), nullable=True),
        sa.Column("exploitability", sa.Text(), nullable=True),
        sa.Column("exposure", sa.Text(), nullable=True),
        sa.Column("confidence", sa.Numeric(3, 2), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("evidence", JSONB(), nullable=True),
        sa.Column("assumptions", JSONB(), nullable=True),
        sa.Column("uncertainties", JSONB(), nullable=True),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("raw_model_response", JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ── risk_assessments ─────────────────────────────────────────────
    op.create_table(
        "risk_assessments",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("finding_id", UUID(as_uuid=True), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("risk_level", sa.Text(), nullable=False),
        sa.Column("risk_version", sa.Integer(), nullable=False),
        sa.Column("factors", JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_risk_assessments_finding_id", "risk_assessments", ["finding_id"])

    # ── audit_events ─────────────────────────────────────────────────
    op.create_table(
        "audit_events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("repository_id", UUID(as_uuid=True), nullable=True),
        sa.Column("finding_id", UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("metadata", JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"])


def downgrade() -> None:
    """Downgrade drops all tables created by upgrade.

    NOTE: This is destructive and will remove all data.
    Only use for development/testing rollback.
    """
    op.drop_table("audit_events")
    op.drop_table("risk_assessments")
    op.drop_table("investigations")
    op.drop_table("findings")
    op.drop_table("dependencies")
    op.drop_table("scans")
    op.drop_table("repositories")
    op.drop_table("github_installations")
    op.drop_table("users")
