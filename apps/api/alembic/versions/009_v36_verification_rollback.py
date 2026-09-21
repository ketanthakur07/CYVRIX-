"""V3.6 verification + rollback (verification runs/checks + rollback runs)

Revision ID: 009
Revises: 008
Create Date: 2026-09-19

Adds (additive only — no earlier-phase changes):
- verification_runs: ONE verification lifecycle per committed Git
  remediation. Created only from server-side remediation state, never
  client claims. UNIQUE git_remediation_id makes the verdict exactly-once:
  a re-verification request is refused at the DB level (a changed verdict
  requires a NEW remediation decision, never a state rewrite).
  The frozen VerificationPlan + canonical digest are persisted — later
  plan mismatch is a tamper event, never repaired.
- verification_checks: one row per planned deterministic check with
  bounded, scrubbed evidence (expected/observed conditions). Repository
  output is untrusted data and is never stored raw.
- rollback_runs: ONE controlled rollback per remediation. The rollback
  target is SERVER-DERIVED (the frozen contract's base_commit_sha); the
  client can never name a SHA. UNIQUE git_remediation_id is the
  idempotency key. Mechanism is a new revert branch + revert commit + PR:
  NO force push, NO history rewrite, NO default-branch mutation.

No migration capability is introduced by DDL itself; rollback Git
effects are produced only by the V3.6 rollback engine after server-side
state verification (fail closed on branch movement / stale targets).
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision: str = "009"
down_revision: Union[str, None] = "008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "verification_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("git_remediation_id", UUID(as_uuid=True),
                  sa.ForeignKey("git_remediations.id"), nullable=False),
        sa.Column("execution_run_id", UUID(as_uuid=True),
                  sa.ForeignKey("execution_runs.id"), nullable=False),
        sa.Column("repository_id", UUID(as_uuid=True),
                  sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("action_digest", sa.Text(), nullable=False),
        sa.Column("verification_state", sa.Text(), nullable=False,
                  server_default="PENDING"),
        # PASS|FAIL|INCONCLUSIVE|SKIPPED|BLOCKED — set only on COMPLETED
        sa.Column("result", sa.Text()),
        sa.Column("reason_code", sa.Text()),
        sa.Column("detail", sa.Text()),
        # Frozen plan + canonical digest (tamper evidence)
        sa.Column("verification_plan", JSONB, nullable=False),
        sa.Column("plan_digest", sa.Text(), nullable=False),
        sa.Column("plan_version", sa.Text(), nullable=False),
        sa.Column("checks_total", sa.Integer(), nullable=False,
                  server_default="0"),
        sa.Column("checks_passed", sa.Integer(), nullable=False,
                  server_default="0"),
        sa.Column("checks_failed", sa.Integer(), nullable=False,
                  server_default="0"),
        sa.Column("checks_other", sa.Integer(), nullable=False,
                  server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "uq_verification_runs_remediation",
        "verification_runs",
        ["git_remediation_id"],
        unique=True,
    )
    op.create_index("ix_verification_runs_state", "verification_runs",
                    ["verification_state"])
    op.create_index("ix_verification_runs_repo", "verification_runs",
                    ["repository_id"])

    op.create_table(
        "verification_checks",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("verification_run_id", UUID(as_uuid=True),
                  sa.ForeignKey("verification_runs.id"), nullable=False),
        sa.Column("check_type", sa.Text(), nullable=False),
        sa.Column("check_version", sa.Text(), nullable=False),
        sa.Column("result", sa.Text(), nullable=False),
        sa.Column("reason_code", sa.Text(), nullable=False),
        sa.Column("evidence", JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "uq_verification_checks_type",
        "verification_checks",
        ["verification_run_id", "check_type"],
        unique=True,
    )
    op.create_index("ix_verification_checks_run", "verification_checks",
                    ["verification_run_id"])

    op.create_table(
        "rollback_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("git_remediation_id", UUID(as_uuid=True),
                  sa.ForeignKey("git_remediations.id"), nullable=False),
        sa.Column("repository_id", UUID(as_uuid=True),
                  sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("action_digest", sa.Text(), nullable=False),
        sa.Column("rollback_state", sa.Text(), nullable=False,
                  server_default="PENDING"),
        sa.Column("fail_reason_code", sa.Text()),
        sa.Column("fail_detail", sa.Text()),
        # Server-derived target (contract base) + expected branch state —
        # no client-supplied SHA exists anywhere in this table.
        sa.Column("rollback_target_sha", sa.Text(), nullable=False),
        sa.Column("expected_branch_sha", sa.Text(), nullable=False),
        sa.Column("revert_branch", sa.Text(), nullable=False),
        sa.Column("revert_sha", sa.Text()),
        sa.Column("revert_pr_number", sa.Integer()),
        sa.Column("revert_pr_url", sa.Text()),
        sa.Column("cleanup_status", sa.Text(), nullable=False,
                  server_default="NOT_STARTED"),
        sa.Column("cleanup_detail", sa.Text()),
        sa.Column("requested_by_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "uq_rollback_runs_remediation",
        "rollback_runs",
        ["git_remediation_id"],
        unique=True,
    )
    op.create_index(
        "uq_rollback_runs_branch_live",
        "rollback_runs",
        ["repository_id", "revert_branch"],
        unique=True,
        postgresql_where=sa.text(
            "rollback_state IN ('PENDING', 'PRECHECK', 'ROLLING_BACK', 'VERIFYING')"
        ),
    )
    op.create_index("ix_rollback_runs_state", "rollback_runs",
                    ["rollback_state"])
    op.create_index("ix_rollback_runs_repo", "rollback_runs",
                    ["repository_id"])

    # V3.6: credential issuances gain a purpose dimension (REMEDIATION_PUSH
    # vs ROLLBACK_PUSH) — a rollback is a distinct audited authorization,
    # not a replay of the original push credential. The one-ISSUED-per-
    # remediation unique index becomes per (remediation, purpose).
    op.add_column(
        "github_credential_issuances",
        sa.Column("purpose", sa.Text(), nullable=False,
                  server_default="REMEDIATION_PUSH"),
    )
    op.drop_index("uq_github_credential_issuances_key",
                  table_name="github_credential_issuances")
    op.create_index(
        "uq_github_credential_issuances_key",
        "github_credential_issuances",
        ["git_remediation_id", "purpose", "result"],
        unique=True,
        postgresql_where=sa.text("result = 'ISSUED'"),
    )


def downgrade() -> None:
    op.drop_index("uq_github_credential_issuances_key",
                  table_name="github_credential_issuances")
    op.drop_column("github_credential_issuances", "purpose")
    op.create_index(
        "uq_github_credential_issuances_key",
        "github_credential_issuances",
        ["git_remediation_id", "result"],
        unique=True,
        postgresql_where=sa.text("result = 'ISSUED'"),
    )
    op.drop_index("ix_rollback_runs_repo", table_name="rollback_runs")
    op.drop_index("ix_rollback_runs_state", table_name="rollback_runs")
    op.drop_index("uq_rollback_runs_branch_live", table_name="rollback_runs")
    op.drop_index("uq_rollback_runs_remediation", table_name="rollback_runs")
    op.drop_table("rollback_runs")
    op.drop_index("ix_verification_checks_run", table_name="verification_checks")
    op.drop_index("uq_verification_checks_type", table_name="verification_checks")
    op.drop_table("verification_checks")
    op.drop_index("ix_verification_runs_repo", table_name="verification_runs")
    op.drop_index("ix_verification_runs_state", table_name="verification_runs")
    op.drop_index("uq_verification_runs_remediation", table_name="verification_runs")
    op.drop_table("verification_runs")
