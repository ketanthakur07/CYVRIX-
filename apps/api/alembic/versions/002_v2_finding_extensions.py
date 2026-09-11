"""V2 finding extensions and new tables

Revision ID: 002
Revises: 001
Create Date: 2026-09-02

Adds:
- source_type column to findings
- evidence column to findings
- recommendations table
- reports table
- indexes for new columns
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── findings extensions ────────────────────────────────────────
    op.add_column("findings", sa.Column("source_type", sa.Text(), nullable=False, server_default="DEPENDENCY"))
    op.add_column("findings", sa.Column("evidence", JSONB(), nullable=True))
    op.create_index("ix_findings_source_type", "findings", ["source_type"])

    # ── recommendations ───────────────────────────────────────────
    op.create_table(
        "recommendations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("finding_id", UUID(as_uuid=True), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="PENDING"),
        sa.Column("trust_level", sa.Text(), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("what", sa.Text(), nullable=True),
        sa.Column("why", sa.Text(), nullable=True),
        sa.Column("change", sa.Text(), nullable=True),
        sa.Column("uncertainty", sa.Text(), nullable=True),
        sa.Column("risk", sa.Text(), nullable=True),
        sa.Column("validation", sa.Text(), nullable=True),
        sa.Column("evidence", JSONB(), nullable=True),
        sa.Column("raw_model_response", JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_recommendations_finding_id", "recommendations", ["finding_id"])
    op.create_index("ix_recommendations_status", "recommendations", ["status"])

    # ── reports ───────────────────────────────────────────────────
    op.create_table(
        "reports",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("repository_id", UUID(as_uuid=True), sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("report_type", sa.Text(), nullable=False),
        sa.Column("format", sa.Text(), nullable=False, server_default="markdown"),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_reports_scan_id", "reports", ["scan_id"])
    op.create_index("ix_reports_repository_id", "reports", ["repository_id"])


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_table("recommendations")
    op.drop_index("ix_findings_source_type", "findings")
    op.drop_column("findings", "evidence")
    op.drop_column("findings", "source_type")
