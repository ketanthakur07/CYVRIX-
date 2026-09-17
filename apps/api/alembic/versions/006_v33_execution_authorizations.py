"""V3.3 execution authorizations (the final deterministic authorization gate)

Revision ID: 006
Revises: 005
Create Date: 2026-09-14

Adds (additive only — no V1/V2/V3.1/V3.2 changes):
- execution_authorizations: the immutable record binding an APPROVED
  approval to a future execution, via a digest-bound, non-executable
  contract. One-time consumption enforced by state + approval lock.
- uq_execution_authorizations_live: partial unique index — at most one
  AUTHORIZED (live) authorization per proposal
- system_controls: server-owned operational control flags. Seeded with
  execution_disabled='false' (kill switch OFF — no execution exists in
  V3.3 anyway); flipping it to 'true' denies all authorization. A failed
  read of this control fails closed in the authorization service.

No execution capability is introduced by this migration: these tables
record authorization decisions only.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "execution_authorizations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("action_proposal_id", UUID(as_uuid=True),
                  sa.ForeignKey("action_proposals.id"), nullable=False),
        sa.Column("approval_id", UUID(as_uuid=True),
                  sa.ForeignKey("approvals.id"), nullable=False),
        sa.Column("action_digest", sa.Text(), nullable=False),
        sa.Column("repository_id", UUID(as_uuid=True),
                  sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("base_commit_sha", sa.Text(), nullable=False),
        sa.Column("target_branch", sa.Text(), nullable=False),
        sa.Column("policy_version", sa.Text(), nullable=False),
        sa.Column("policy_decision", sa.Text(), nullable=False),
        sa.Column("authorization_state", sa.Text(), nullable=False,
                  server_default="AUTHORIZED"),
        sa.Column("contract", JSONB, nullable=False),
        sa.Column("contract_digest", sa.Text(), nullable=False),
        sa.Column("contract_version", sa.Text(), nullable=False),
        sa.Column("authorized_by_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    # At most one live (AUTHORIZED) authorization per proposal.
    # Terminal states (CONSUMED/EXPIRED/REVOKED) never block a legitimate
    # later authorization round (fresh approval → fresh authorization).
    op.create_index(
        "uq_execution_authorizations_live",
        "execution_authorizations",
        ["action_proposal_id"],
        unique=True,
        postgresql_where=sa.text("authorization_state = 'AUTHORIZED'"),
    )
    op.create_index("ix_execution_authorizations_digest",
                    "execution_authorizations", ["action_digest"])
    op.create_index("ix_execution_authorizations_state",
                    "execution_authorizations", ["authorization_state"])
    op.create_index("ix_execution_authorizations_approval",
                    "execution_authorizations", ["approval_id"])

    op.create_table(
        "system_controls",
        sa.Column("key", sa.Text(), primary_key=True, nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Seed the kill switch OFF (no execution exists yet; flipping to
    # 'true' denies all execution authorization). Toggling is an audited
    # privileged operation per security-model §12.
    op.execute(
        "INSERT INTO system_controls (key, value, updated_at) "
        "VALUES ('execution_disabled', 'false', now()) "
        "ON CONFLICT (key) DO NOTHING"
    )


def downgrade() -> None:
    op.drop_table("system_controls")
    op.drop_index("ix_execution_authorizations_approval", table_name="execution_authorizations")
    op.drop_index("ix_execution_authorizations_state", table_name="execution_authorizations")
    op.drop_index("ix_execution_authorizations_digest", table_name="execution_authorizations")
    op.drop_index("uq_execution_authorizations_live", table_name="execution_authorizations")
    op.drop_table("execution_authorizations")
