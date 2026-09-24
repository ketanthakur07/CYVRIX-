"""V3.8 audit integrity (hash-linked events, signed checkpoints, chains)

Revision ID: 011
Revises: 010
Create Date: 2026-09-25

Adds (additive only — no earlier-phase changes):
- audit_chains: one append-only hash chain per tenant installation
  (chain identity + advisory head bookkeeping)
- audit_chain_events: hash-linked events, (chain_id, seq) unique,
  (chain_id, prev_digest) unique, event_digest globally unique —
  no two events can claim the same position or predecessor
- audit_checkpoints: HMAC-signed chain heads (truncation-detection
  anchor); the MAC key lives outside the database (settings), so a DB
  writer cannot forge a checkpoint
- DB-level append-only guard trigger: rejects UPDATE/DELETE on
  audit_chain_events and audit_checkpoints regardless of application
  role (role separation documented in docs/v3-audit-integrity.md)

No migration introduces execution capability by itself: DDL only.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision: str = "011"
down_revision: Union[str, None] = "010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_APPEND_ONLY_DDL = """
CREATE OR REPLACE FUNCTION cyvrix_audit_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'CYVRIX audit records are append-only: % on % denied',
        TG_OP, TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;
"""


def upgrade() -> None:
    op.create_table(
        "audit_chains",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("installation_id", UUID(as_uuid=True),
                  sa.ForeignKey("github_installations.id"), nullable=False, unique=True),
        sa.Column("last_sequence", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("last_event_digest", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "audit_chain_events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("chain_id", UUID(as_uuid=True),
                  sa.ForeignKey("audit_chains.id"), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("event_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("actor_type", sa.Text(), nullable=False),
        sa.Column("actor_id", sa.Text()),
        sa.Column("actor_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("repository_id", UUID(as_uuid=True), sa.ForeignKey("repositories.id")),
        sa.Column("action_id", UUID(as_uuid=True)),
        sa.Column("authorization_id", UUID(as_uuid=True)),
        sa.Column("execution_run_id", UUID(as_uuid=True)),
        sa.Column("verification_id", UUID(as_uuid=True)),
        sa.Column("rollback_id", UUID(as_uuid=True)),
        sa.Column("reason_code", sa.Text()),
        sa.Column("result", sa.Text()),
        sa.Column("payload", JSONB),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("prev_digest", sa.Text(), nullable=False),
        sa.Column("event_digest", sa.Text(), nullable=False),
    )
    op.create_index("uq_audit_chain_events_seq", "audit_chain_events",
                    ["chain_id", "seq"], unique=True)
    op.create_index("uq_audit_chain_events_prev", "audit_chain_events",
                    ["chain_id", "prev_digest"], unique=True)
    op.create_index("uq_audit_chain_events_digest", "audit_chain_events",
                    ["event_digest"], unique=True)
    op.create_index("ix_audit_chain_events_type", "audit_chain_events", ["event_type"])
    op.create_index("ix_audit_chain_events_repo", "audit_chain_events", ["repository_id"])
    op.create_index("ix_audit_chain_events_recorded", "audit_chain_events", ["recorded_at"])

    op.create_table(
        "audit_checkpoints",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("chain_id", UUID(as_uuid=True),
                  sa.ForeignKey("audit_chains.id"), nullable=False),
        sa.Column("through_sequence", sa.BigInteger(), nullable=False),
        sa.Column("head_digest", sa.Text(), nullable=False),
        # NOTE: intentionally NOT named "sequence": Postgres reserves
        # sequence as a keyword in some positions; keep explicit naming.
        sa.Column("event_count", sa.BigInteger(), nullable=False),
        sa.Column("payload_digest", sa.Text(), nullable=False),
        sa.Column("mac", sa.Text(), nullable=False),
        sa.Column("mac_key_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("uq_audit_checkpoints_seq", "audit_checkpoints",
                    ["chain_id", "through_sequence"], unique=True)

    # DB-level append-only guard (defense in depth; works for any role,
    # including table owners, unless the trigger is explicitly dropped —
    # which is itself observable via pg_trigger / export verification).
    op.execute(_APPEND_ONLY_DDL)
    op.execute(
        "CREATE TRIGGER audit_chain_events_append_only "
        "BEFORE UPDATE OR DELETE ON audit_chain_events "
        "FOR EACH STATEMENT EXECUTE FUNCTION cyvrix_audit_append_only()"
    )
    op.execute(
        "CREATE TRIGGER audit_checkpoints_append_only "
        "BEFORE UPDATE OR DELETE ON audit_checkpoints "
        "FOR EACH STATEMENT EXECUTE FUNCTION cyvrix_audit_append_only()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_checkpoints_append_only ON audit_checkpoints")
    op.execute("DROP TRIGGER IF EXISTS audit_chain_events_append_only ON audit_chain_events")
    op.execute("DROP FUNCTION IF EXISTS cyvrix_audit_append_only()")
    op.drop_index("uq_audit_checkpoints_seq", table_name="audit_checkpoints")
    op.drop_table("audit_checkpoints")
    op.drop_index("ix_audit_chain_events_recorded", table_name="audit_chain_events")
    op.drop_index("ix_audit_chain_events_repo", table_name="audit_chain_events")
    op.drop_index("ix_audit_chain_events_type", table_name="audit_chain_events")
    op.drop_index("uq_audit_chain_events_digest", table_name="audit_chain_events")
    op.drop_index("uq_audit_chain_events_prev", table_name="audit_chain_events")
    op.drop_index("uq_audit_chain_events_seq", table_name="audit_chain_events")
    op.drop_table("audit_chain_events")
    op.drop_table("audit_chains")
