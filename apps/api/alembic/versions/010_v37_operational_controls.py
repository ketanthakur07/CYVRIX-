"""V3.7 operational controls (repo controls, circuit breakers, leases,
reconciliation runs, operational events, user roles, ops state seed)

Revision ID: 010
Revises: 009
Create Date: 2026-09-21

Adds (additive only — no earlier-phase changes):
- users.role: USER | OPERATOR | ADMIN (least-privilege operator model;
  existing users default to USER; bootstrap via CYVRIX_OPERATOR_EMAILS
  grants OPERATOR capabilities only when the role is not provisioned)
- repository_controls: per-repository ENABLED | PAUSED | BLOCKED
  (tenant-owned containment; missing row fails closed in services)
- circuit_breakers: per (repository, scope, action_type) bounded
  consecutive-failure breaker; OPEN requires operator reset
- execution_leases: explicit job ownership (owner, attempt, heartbeat,
  expiry); one ACTIVE lease per subject (partial unique index)
- reconciliation_runs: deterministic, idempotent reconciliation passes
- operational_events: structured, secret-free operational audit feed
- system_controls seed: operational_state='NORMAL' — the V3.7 control
  plane state (existing execution_disabled kill switch is unchanged;
  missing/unparseable operational_state fails closed in services)

No migration introduces execution capability by itself: DDL only.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision: str = "010"
down_revision: Union[str, None] = "009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # users.role (least-privilege operator model)
    op.add_column(
        "users",
        sa.Column("role", sa.Text(), nullable=False, server_default="USER"),
    )

    op.create_table(
        "repository_controls",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("repository_id", UUID(as_uuid=True),
                  sa.ForeignKey("repositories.id"), nullable=False, unique=True),
        sa.Column("control_state", sa.Text(), nullable=False, server_default="ENABLED"),
        sa.Column("reason", sa.Text()),
        sa.Column("updated_by_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_repository_controls_state", "repository_controls", ["control_state"])

    op.create_table(
        "circuit_breakers",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("repository_id", UUID(as_uuid=True),
                  sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("action_type", sa.Text(), nullable=False, server_default="ANY"),
        sa.Column("breaker_state", sa.Text(), nullable=False, server_default="CLOSED"),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_consecutive_failures", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("opened_at", sa.DateTime(timezone=True)),
        sa.Column("opened_reason_code", sa.Text()),
        sa.Column("reset_by_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("repository_id", "scope", "action_type",
                            name="uq_circuit_breakers_scope"),
    )
    op.create_index("ix_circuit_breakers_state", "circuit_breakers", ["breaker_state"])

    op.create_table(
        "execution_leases",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("subject_type", sa.Text(), nullable=False),
        sa.Column("subject_id", UUID(as_uuid=True), nullable=False),
        sa.Column("repository_id", UUID(as_uuid=True),
                  sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("lease_owner_id", sa.Text(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("lease_state", sa.Text(), nullable=False, server_default="ACTIVE"),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "uq_execution_leases_active", "execution_leases", ["subject_id"],
        unique=True,
        postgresql_where=sa.text("lease_state = 'ACTIVE'"),
    )
    op.create_index("ix_execution_leases_state", "execution_leases", ["lease_state"])
    op.create_index("ix_execution_leases_subject", "execution_leases",
                    ["subject_type", "subject_id"])

    op.create_table(
        "reconciliation_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("trigger", sa.Text(), nullable=False, server_default="OPERATOR"),
        sa.Column("status", sa.Text(), nullable=False, server_default="RUNNING"),
        sa.Column("findings", JSONB),
        sa.Column("stats", JSONB),
        sa.Column("detail", sa.Text()),
        sa.Column("started_by_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_reconciliation_runs_status", "reconciliation_runs", ["status"])

    op.create_table(
        "operational_events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("repository_id", UUID(as_uuid=True)),
        sa.Column("subject_type", sa.Text()),
        sa.Column("subject_id", UUID(as_uuid=True)),
        sa.Column("reason_code", sa.Text()),
        sa.Column("detail", sa.Text()),
        sa.Column("created_by_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_operational_events_type", "operational_events", ["event_type"])
    op.create_index("ix_operational_events_created", "operational_events", ["created_at"])

    # Seed the operational state (NORMAL) — idempotent insert.
    op.execute(
        "INSERT INTO system_controls (key, value, updated_at) "
        "VALUES ('operational_state', 'NORMAL', NOW()) "
        "ON CONFLICT (key) DO NOTHING"
    )


def downgrade() -> None:
    op.drop_index("ix_operational_events_created", table_name="operational_events")
    op.drop_index("ix_operational_events_type", table_name="operational_events")
    op.drop_table("operational_events")
    op.drop_index("ix_reconciliation_runs_status", table_name="reconciliation_runs")
    op.drop_table("reconciliation_runs")
    op.drop_index("ix_execution_leases_subject", table_name="execution_leases")
    op.drop_index("ix_execution_leases_state", table_name="execution_leases")
    op.drop_index("uq_execution_leases_active", table_name="execution_leases")
    op.drop_table("execution_leases")
    op.drop_index("ix_circuit_breakers_state", table_name="circuit_breakers")
    op.drop_table("circuit_breakers")
    op.drop_index("ix_repository_controls_state", table_name="repository_controls")
    op.drop_table("repository_controls")
    op.drop_column("users", "role")
