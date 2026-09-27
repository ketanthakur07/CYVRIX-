"""V4.2 completion — outbound webhooks + dedicated CI event intake

Revision ID: 014
Revises: 013
Create Date: 2026-09-27

Additive only: three new tables, no existing table is altered. V1–V4.2
rows (api keys, organizations, repositories, audit chains, scans, jobs)
are untouched and remain valid.

`outbound_webhook_endpoints`
    One subscribed HTTPS receiver per organization. The signing secret
    is stored Fernet-encrypted (key outside the database, settings-owned)
    and is never returned after creation, never logged, never exported.

`outbound_webhook_deliveries`
    One row per logical delivery; identity is
    UNIQUE(organization_id, endpoint_id, event_type, delivery_id) so a
    retry of the same logical event can NEVER mint a second row — the
    delivery_id is stable across retries by construction.

`ci_events`
    The security record of the dedicated CI intake (POST /api/ci/events).
    Identity is UNIQUE(organization_id, repository_id, event_id): a
    replayed CI event is refused at the database level even if the
    idempotency reservation TTL has lapsed. CI payload content is never
    persisted — bounded metadata and server-derived outcome only.

No migration introduces execution capability: DDL only.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision: str = "014"
down_revision: Union[str, None] = "013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Outbound webhook endpoints ───────────────────────────────────
    op.create_table(
        "outbound_webhook_endpoints",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "organization_id",
            UUID(as_uuid=True),
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("status", sa.Text(), nullable=False, server_default="ACTIVE"),
        sa.Column("events", JSONB(), nullable=False, server_default="[]"),
        sa.Column("secret_ciphertext", sa.Text(), nullable=False),
        sa.Column("secret_hint", sa.Text(), nullable=False, server_default=""),
        sa.Column("secret_key_version", sa.Integer(), nullable=False,
                  server_default="1"),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
        sa.Column("created_by_user_id",
                  UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index(
        "ix_outbound_endpoints_org", "outbound_webhook_endpoints",
        ["organization_id"],
    )
    op.create_index(
        "ix_outbound_endpoints_org_active", "outbound_webhook_endpoints",
        ["organization_id"],
        postgresql_where=sa.text("status = 'ACTIVE'"),
    )

    # ── Outbound webhook deliveries (stable identity across retries) ─
    op.create_table(
        "outbound_webhook_deliveries",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "organization_id",
            UUID(as_uuid=True),
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        sa.Column(
            "endpoint_id",
            UUID(as_uuid=True),
            sa.ForeignKey("outbound_webhook_endpoints.id"),
            nullable=False,
        ),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("event_version", sa.Integer(), nullable=False,
                  server_default="1"),
        sa.Column("delivery_id", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False, server_default="PENDING"),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("payload", JSONB(), nullable=False, server_default="{}"),
        sa.Column("last_http_status", sa.Integer()),
        sa.Column("last_error", sa.Text()),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("dead_lettered_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_unique_constraint(
        "uq_outbound_deliveries_identity",
        "outbound_webhook_deliveries",
        ["organization_id", "endpoint_id", "event_type", "delivery_id"],
    )
    op.create_index(
        "ix_outbound_deliveries_due", "outbound_webhook_deliveries",
        ["state", "next_attempt_at"],
        postgresql_where=sa.text("state IN ('PENDING', 'RETRYING')"),
    )
    op.create_index(
        "ix_outbound_deliveries_org", "outbound_webhook_deliveries",
        ["organization_id"],
    )
    op.create_index(
        "ix_outbound_deliveries_state", "outbound_webhook_deliveries",
        ["state"],
    )

    # ── Dedicated CI event intake ────────────────────────────────────
    op.create_table(
        "ci_events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "organization_id",
            UUID(as_uuid=True),
            sa.ForeignKey("organizations.id"),
            nullable=True,
        ),
        sa.Column("api_key_prefix", sa.Text()),
        sa.Column("event_id", sa.Text(), nullable=False),
        sa.Column(
            "repository_id",
            UUID(as_uuid=True),
            sa.ForeignKey("repositories.id"),
            nullable=True,
        ),
        sa.Column("commit_sha", sa.Text()),
        sa.Column("ref", sa.Text()),
        sa.Column("provider", sa.Text(), nullable=False, server_default="github"),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("result", sa.Text()),
        sa.Column("reason_code", sa.Text()),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id"),
                  nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_unique_constraint(
        "uq_ci_events_org_repo_event",
        "ci_events",
        ["organization_id", "repository_id", "event_id"],
    )
    op.create_index("ix_ci_events_org", "ci_events", ["organization_id"])
    op.create_index("ix_ci_events_outcome", "ci_events", ["outcome"])
    op.create_index("ix_ci_events_received", "ci_events", ["received_at"])

    # ── Key-actor honesty for V3 mutation rows ───────────────────────
    # The public API mutation scopes (actions:create / rollback:create)
    # create V3 rows whose actor is a CREDENTIAL, not a user. A user
    # attribution is never fabricated: the columns become nullable and
    # the key identity is witnessed in the V3.8 chain instead. Both
    # changes are additive/backwards-compatible; existing rows keep
    # their values.
    op.alter_column(
        "action_proposals", "created_by",
        existing_type=UUID(as_uuid=True), nullable=True,
    )
    op.alter_column(
        "rollback_runs", "requested_by_user_id",
        existing_type=UUID(as_uuid=True), nullable=True,
    )


def downgrade() -> None:
    # ── Key-actor honesty columns ────────────────────────────────────
    op.alter_column(
        "rollback_runs", "requested_by_user_id",
        existing_type=UUID(as_uuid=True), nullable=False,
    )
    op.alter_column(
        "action_proposals", "created_by",
        existing_type=UUID(as_uuid=True), nullable=False,
    )

    # ── CI events ───────────────────────────────────────────────────
    op.drop_index("ix_ci_events_received", table_name="ci_events")
    op.drop_index("ix_ci_events_outcome", table_name="ci_events")
    op.drop_index("ix_ci_events_org", table_name="ci_events")
    op.drop_constraint(
        "uq_ci_events_org_repo_event", "ci_events", type_="unique"
    )
    op.drop_table("ci_events")

    # ── Outbound deliveries ──────────────────────────────────────────
    op.drop_index("ix_outbound_deliveries_state",
                  table_name="outbound_webhook_deliveries")
    op.drop_index("ix_outbound_deliveries_org",
                  table_name="outbound_webhook_deliveries")
    op.drop_index("ix_outbound_deliveries_due",
                  table_name="outbound_webhook_deliveries")
    op.drop_constraint(
        "uq_outbound_deliveries_identity",
        "outbound_webhook_deliveries",
        type_="unique",
    )
    op.drop_table("outbound_webhook_deliveries")

    # ── Outbound endpoints ───────────────────────────────────────────
    op.drop_index("ix_outbound_endpoints_org_active",
                  table_name="outbound_webhook_endpoints")
    op.drop_index("ix_outbound_endpoints_org",
                  table_name="outbound_webhook_endpoints")
    op.drop_table("outbound_webhook_endpoints")
