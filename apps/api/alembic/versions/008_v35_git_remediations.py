"""V3.5 controlled Git/GitHub remediation (git remediations + credential issuances)

Revision ID: 008
Revises: 007
Create Date: 2026-09-18

Adds (additive only — no earlier-phase changes):
- git_remediations: ONE Git/GitHub remediation lifecycle per consumed
  V3.4 execution run. Created only from server-side verified run state,
  never from client claims. UNIQUE execution_run_id makes the pipeline
  exactly-once: a replayed remediation request is refused at the DB level.
  The full Git/GitHub contract (repo identity, base SHA, source/target
  branch, authorized file set, stage ceiling) is frozen at creation into
  a digestable remediation contract — later mismatches are tamper events,
  never repaired.
- github_credential_issuances: AUDIT-ONLY records of short-lived,
  repo-scoped GitHub token issuances bound to one remediation. Token
  material is NEVER stored here (no plaintext, no hash of the token) —
  the record exists so issuance is observable and revocation semantics
  are auditable. issuance_key is UNIQUE per remediation (one-time).

No migration capability is introduced by DDL itself; push/PR effects are
produced only by the V3.5 remediation engine after server-side
verification (V3.5 remains: NO force push, NO default-branch push,
NO direct push to protected branches).
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision: str = "008"
down_revision: Union[str, None] = "007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "git_remediations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        # Exactly-once anchor: one remediation per V3.4 execution run.
        sa.Column("execution_run_id", UUID(as_uuid=True),
                  sa.ForeignKey("execution_runs.id"), nullable=False),
        sa.Column("execution_authorization_id", UUID(as_uuid=True),
                  sa.ForeignKey("execution_authorizations.id"), nullable=False),
        sa.Column("action_proposal_id", UUID(as_uuid=True),
                  sa.ForeignKey("action_proposals.id"), nullable=False),
        sa.Column("repository_id", UUID(as_uuid=True),
                  sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("action_digest", sa.Text(), nullable=False),
        # Frozen, digestable contract (repo identity, base sha, branches,
        # authorized files, stage ceiling) + its canonical digest.
        sa.Column("remediation_contract", JSONB, nullable=False),
        sa.Column("remediation_contract_digest", sa.Text(), nullable=False),
        sa.Column("contract_version", sa.Text(), nullable=False),
        # Server-derived repository identity (canonical, verified against
        # the ownership chain AND the GitHub remote before any push).
        sa.Column("repo_owner", sa.Text(), nullable=False),
        sa.Column("repo_name", sa.Text(), nullable=False),
        sa.Column("installation_id", sa.BigInteger(), nullable=False),
        sa.Column("base_commit_sha", sa.Text(), nullable=False),
        sa.Column("source_branch", sa.Text(), nullable=False),
        sa.Column("target_branch", sa.Text(), nullable=False),
        # State machine (execution_run_model.GitRemediationState values).
        sa.Column("remediation_state", sa.Text(), nullable=False,
                  server_default="PENDING"),
        sa.Column("fail_reason_code", sa.Text()),
        sa.Column("fail_detail", sa.Text()),
        # Server-generated remediation branch in the controlled namespace.
        sa.Column("remediation_branch", sa.Text(), nullable=False),
        sa.Column("committed_sha", sa.Text()),
        sa.Column("pushed_sha", sa.Text()),
        sa.Column("pr_number", sa.Integer()),
        sa.Column("pr_url", sa.Text()),
        sa.Column("pr_state", sa.Text()),
        # Stage ceiling snapshot (LOCAL_ONLY < COMMIT_ALLOWED < PUSH_ALLOWED
        # < PR_ALLOWED) — never client-controlled.
        sa.Column("stage_ceiling", sa.Text(), nullable=False),
        sa.Column("cleanup_status", sa.Text(), nullable=False,
                  server_default="NOT_STARTED"),
        sa.Column("cleanup_detail", sa.Text()),
        sa.Column("created_by_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Exactly-once: at most one remediation per execution run, ever.
    op.create_index(
        "uq_git_remediations_run",
        "git_remediations",
        ["execution_run_id"],
        unique=True,
    )
    # At most one live (non-terminal) remediation per execution
    # authorization: retries of the SAME authorization reuse the existing
    # row; a second live pipeline can never exist in parallel.
    op.create_index(
        "uq_git_remediations_live",
        "git_remediations",
        ["execution_authorization_id"],
        unique=True,
        postgresql_where=sa.text(
            "remediation_state IN ('PENDING', 'VERIFYING', 'COMMITTING', "
            "'COMMITTED', 'PUSHING', 'PUSHED', 'PR_CREATING')"
        ),
    )
    # Deterministic branch-name collision guard inside the controlled
    # namespace (repo + branch must be globally unique among LIVE rows).
    op.create_index(
        "uq_git_remediations_branch_live",
        "git_remediations",
        ["repository_id", "remediation_branch"],
        unique=True,
        postgresql_where=sa.text(
            "remediation_state IN ('PENDING', 'VERIFYING', 'COMMITTING', "
            "'COMMITTED', 'PUSHING', 'PUSHED', 'PR_CREATING', 'PR_CREATED')"
        ),
    )
    op.create_index("ix_git_remediations_state", "git_remediations",
                    ["remediation_state"])
    op.create_index("ix_git_remediations_repo", "git_remediations",
                    ["repository_id"])
    op.create_index("ix_git_remediations_digest", "git_remediations",
                    ["action_digest"])

    op.create_table(
        "github_credential_issuances",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("git_remediation_id", UUID(as_uuid=True),
                  sa.ForeignKey("git_remediations.id"), nullable=False),
        sa.Column("execution_authorization_id", UUID(as_uuid=True),
                  sa.ForeignKey("execution_authorizations.id"), nullable=False),
        sa.Column("repository_id", UUID(as_uuid=True),
                  sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("installation_id", sa.BigInteger(), nullable=False),
        sa.Column("repo_owner", sa.Text(), nullable=False),
        sa.Column("repo_name", sa.Text(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("result", sa.Text(), nullable=False, default="ISSUED"),
        sa.Column("fail_reason_code", sa.Text()),
        # NOTE: no token column of any kind — plaintext or hashed. The
        # credential lives only in process memory for the duration of the
        # push/PR step and is never persisted, logged, or returned.
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    # One successful issuance per remediation (credential request is
    # one-time; failures are re-issuable only through a fresh remediation).
    op.create_index(
        "uq_github_credential_issuances_key",
        "github_credential_issuances",
        ["git_remediation_id", "result"],
        unique=True,
        postgresql_where=sa.text("result = 'ISSUED'"),
    )
    op.create_index("ix_github_credential_issuances_remediation",
                    "github_credential_issuances", ["git_remediation_id"])


def downgrade() -> None:
    op.drop_index("ix_github_credential_issuances_remediation",
                  table_name="github_credential_issuances")
    op.drop_index("uq_github_credential_issuances_key",
                  table_name="github_credential_issuances")
    op.drop_table("github_credential_issuances")
    op.drop_index("ix_git_remediations_digest", table_name="git_remediations")
    op.drop_index("ix_git_remediations_repo", table_name="git_remediations")
    op.drop_index("ix_git_remediations_state", table_name="git_remediations")
    op.drop_index("uq_git_remediations_branch_live", table_name="git_remediations")
    op.drop_index("uq_git_remediations_live", table_name="git_remediations")
    op.drop_index("uq_git_remediations_run", table_name="git_remediations")
    op.drop_table("git_remediations")
