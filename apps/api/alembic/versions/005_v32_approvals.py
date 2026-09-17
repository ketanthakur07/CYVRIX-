"""V3.2 approvals (human approval of action proposals — authorization data only)

Revision ID: 005
Revises: 004
Create Date: 2026-09-12

Adds (additive only — no V1/V2/V3.1 changes):
- approvals table: binds an authorized human to the exact action proposal
  via action_digest, with a one-time authorization token (hash only),
  bounded expiry, and explicit state semantics
- uq_approvals_live: partial unique index — at most one live (PENDING or
  APPROVED) approval per proposal
- uq_approvals_principal: distinct principals per proposal (second-principal
  rule for HIGH/CRITICAL risk)
- indexes for proposal/state queries and digest lookups

No execution capability is introduced by this migration.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "approvals",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("action_proposal_id", UUID(as_uuid=True),
                  sa.ForeignKey("action_proposals.id"), nullable=False),
        sa.Column("action_digest", sa.Text(), nullable=False),
        sa.Column("approver_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("second_approver_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=True),
        sa.Column("approval_state", sa.Text(), nullable=False,
                  server_default="PENDING"),
        sa.Column("approval_reason", sa.Text(), nullable=True),
        sa.Column("policy_version", sa.Text(), nullable=False),
        sa.Column("policy_decision", sa.Text(), nullable=False),
        sa.Column("approval_level", sa.Text(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authorization_token_hash", sa.Text(), nullable=True),
        sa.Column("authorization_issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("authorization_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    # At most one live (PENDING/APPROVED) approval per proposal
    op.create_index(
        "uq_approvals_live",
        "approvals",
        ["action_proposal_id"],
        unique=True,
        postgresql_where=sa.text("approval_state IN ('PENDING', 'APPROVED')"),
    )
    # Distinct principals per proposal (second-principal rule).
    # Partial: only constrains live (PENDING/APPROVED) rounds so a rejected
    # or expired round never blocks a legitimate later approval round.
    op.create_index(
        "uq_approvals_principal",
        "approvals",
        ["action_proposal_id", "approver_user_id", "second_approver_user_id"],
        unique=True,
        postgresql_where=sa.text("approval_state IN ('PENDING', 'APPROVED')"),
    )
    op.create_index("ix_approvals_proposal_state", "approvals",
                    ["action_proposal_id", "approval_state"])
    op.create_index("ix_approvals_digest", "approvals", ["action_digest"])


def downgrade() -> None:
    op.drop_index("ix_approvals_digest", table_name="approvals")
    op.drop_index("ix_approvals_proposal_state", table_name="approvals")
    op.drop_index("uq_approvals_principal", table_name="approvals")
    op.drop_index("uq_approvals_live", table_name="approvals")
    op.drop_table("approvals")
