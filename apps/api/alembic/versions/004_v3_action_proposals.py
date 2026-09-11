"""V3.1 action proposals

Revision ID: 004
Revises: 003
Create Date: 2026-09-07

Adds (additive only — no V1/V2 changes):
- action_proposals table (proposed remediation actions; never executed in V3.1)
- identity constraint: (recommendation_id, base_commit_sha, action_digest)
- indexes for ownership/status queries, expiry sweeps, digest lookup
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "action_proposals",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("finding_id", UUID(as_uuid=True),
                  sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("recommendation_id", UUID(as_uuid=True),
                  sa.ForeignKey("recommendations.id"), nullable=False),
        sa.Column("repository_id", UUID(as_uuid=True),
                  sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("created_by", UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("action_type", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="PROPOSED"),
        sa.Column("base_commit_sha", sa.Text(), nullable=False),
        sa.Column("target_branch", sa.Text(), nullable=False),
        sa.Column("files", JSONB(), nullable=False),
        sa.Column("operations", JSONB(), nullable=False),
        sa.Column("expected_diff", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("evidence", JSONB(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("risk_level", sa.Text(), nullable=False),
        sa.Column("recommendation_trust", sa.Text(), nullable=True),
        sa.Column("validation_state", sa.Text(), nullable=True),
        sa.Column("policy_version", sa.Text(), nullable=False),
        sa.Column("policy_decision", sa.Text(), nullable=False),
        sa.Column("policy_reason_code", sa.Text(), nullable=False),
        sa.Column("policy_matched_rule", sa.Text(), nullable=False),
        sa.Column("policy_explanation", sa.Text(), nullable=True),
        sa.Column("action_digest", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("recommendation_id", "base_commit_sha", "action_digest",
                            name="uq_proposal_identity"),
    )
    op.create_index("ix_action_proposals_repo_status", "action_proposals",
                    ["repository_id", "status"])
    op.create_index("ix_action_proposals_status_expiry", "action_proposals",
                    ["status", "expires_at"])
    op.create_index("ix_action_proposals_digest", "action_proposals", ["action_digest"])


def downgrade() -> None:
    op.drop_index("ix_action_proposals_digest", table_name="action_proposals")
    op.drop_index("ix_action_proposals_status_expiry", table_name="action_proposals")
    op.drop_index("ix_action_proposals_repo_status", table_name="action_proposals")
    op.drop_table("action_proposals")
