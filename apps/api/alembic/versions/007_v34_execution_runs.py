"""V3.4 sandboxed execution engine (execution runs + workspace snapshots)

Revision ID: 007
Revises: 006
Create Date: 2026-09-14

Adds (additive only — no earlier-phase changes):
- execution_runs: one admission-to-cleanup lifecycle per execution,
  bound to exactly one V3.3 execution authorization. A UNIQUE live
  index (ADMISSION_PENDING/EXECUTING per authorization) prevents two
  concurrent admissions; a UNIQUE completed index makes a consumed
  authorization exactly-once. No credentials, no tokens, no secrets.
- workspace_snapshots: per-file content-addressed hashes of the
  materialized BEFORE and AFTER states of the sandbox workspace. This
  is the base/result evidence for later verification (V3.6) and
  rollback (V3.7). Hashes only — never file content.
- resource_profile: the frozen limit set each run executed under
  (auditability of the sandbox contract).

No execution capability is introduced by DDL itself; these tables
record executions that only the V3.4 engine may create.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "execution_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("execution_authorization_id", UUID(as_uuid=True),
                  sa.ForeignKey("execution_authorizations.id"), nullable=False),
        sa.Column("action_proposal_id", UUID(as_uuid=True),
                  sa.ForeignKey("action_proposals.id"), nullable=False),
        sa.Column("repository_id", UUID(as_uuid=True),
                  sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("action_digest", sa.Text(), nullable=False),
        sa.Column("contract_digest", sa.Text(), nullable=False),
        sa.Column("run_state", sa.Text(), nullable=False,
                  server_default="ADMISSION_PENDING"),
        sa.Column("fail_reason_code", sa.Text(), nullable=True),
        sa.Column("fail_detail", sa.Text(), nullable=True),
        sa.Column("execution_profile", sa.Text(), nullable=False),
        sa.Column("resource_profile", JSONB, nullable=False),
        sa.Column("cleanup_status", sa.Text(), nullable=False,
                  server_default="NOT_STARTED"),
        sa.Column("cleanup_detail", sa.Text(), nullable=True),
        sa.Column("result", JSONB, nullable=True),
        sa.Column("diff_digest", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    # At most one live (ADMISSION_PENDING/EXECUTING) run per authorization:
    # two executors can never both reserve the same authorization.
    op.create_index(
        "uq_execution_runs_live",
        "execution_runs",
        ["execution_authorization_id"],
        unique=True,
        postgresql_where=sa.text(
            "run_state IN ('ADMISSION_PENDING', 'EXECUTING')"
        ),
    )
    # Exactly-once: at most one COMPLETED/RESULT_READY/CLEANUP_FAILED run
    # per authorization — a replayed admission is refused by this backstop.
    op.create_index(
        "uq_execution_runs_done",
        "execution_runs",
        ["execution_authorization_id"],
        unique=True,
        postgresql_where=sa.text(
            "run_state IN ('RESULT_READY', 'COMPLETED', 'CLEANUP_FAILED')"
        ),
    )
    op.create_index("ix_execution_runs_state", "execution_runs", ["run_state"])
    op.create_index("ix_execution_runs_digest", "execution_runs", ["action_digest"])
    op.create_index("ix_execution_runs_repository", "execution_runs", ["repository_id"])

    op.create_table(
        "workspace_snapshots",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("execution_run_id", UUID(as_uuid=True),
                  sa.ForeignKey("execution_runs.id"), nullable=False),
        sa.Column("phase", sa.Text(), nullable=False),  # BEFORE | AFTER
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("content_sha256", sa.Text(), nullable=False),
        sa.Column("size_bytes", sa.Integer, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "uq_workspace_snapshots_file",
        "workspace_snapshots",
        ["execution_run_id", "phase", "file_path"],
        unique=True,
    )
    op.create_index(
        "ix_workspace_snapshots_run", "workspace_snapshots", ["execution_run_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_workspace_snapshots_run", table_name="workspace_snapshots")
    op.drop_index("uq_workspace_snapshots_file", table_name="workspace_snapshots")
    op.drop_table("workspace_snapshots")
    op.drop_index("ix_execution_runs_repository", table_name="execution_runs")
    op.drop_index("ix_execution_runs_digest", table_name="execution_runs")
    op.drop_index("ix_execution_runs_state", table_name="execution_runs")
    op.drop_index("uq_execution_runs_done", table_name="execution_runs")
    op.drop_index("uq_execution_runs_live", table_name="execution_runs")
    op.drop_table("execution_runs")
