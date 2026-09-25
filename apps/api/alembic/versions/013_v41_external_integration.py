"""V4.1 external integration — idempotency, webhooks, commit binding, audit org chains

Revision ID: 013
Revises: 012
Create Date: 2026-09-25

Additive only — no V1–V4.0 table is altered except `audit_chains`, which
gains a nullable `organization_id` (see below) and `scans`, which gains a
nullable `requested_commit_sha`. Both are NULL-able additions: existing
rows are untouched and remain valid.

Tables and changes:

`api_idempotency_keys`
    ONE primitive serving two structurally identical problems:

      - public-API idempotency (`Idempotency-Key` on a mutation), and
      - webhook replay protection (a provider delivery id).

    Both are "a server-side record of (tenant, namespace, key) -> the
    outcome produced, bound to a digest of the request".

    UNIQUE(organization_id, scope, key_value)
        One record per tenant, per operation namespace, per client key.
        This is what makes a concurrent duplicate deterministic: the
        loser cannot insert a second record, so it must replay or
        conflict rather than re-execute the side effect.

    request_digest
        Binds the record to the exact request, so a replay with a
        DIFFERENT body is a conflict instead of a false replay.

    expires_at is NOT NULL: replay protection has bounded retention and
    the cleanup path is a plain indexed delete. No unbounded growth.

`webhook_deliveries`
    The structured security record of every inbound delivery (no payload
    content, ever). UNIQUE(organization_id, github_delivery_id) is the
    DB-level replay backstop alongside the idempotency primitive;
    refused deliveries are stored tenant-less (organization_id NULL).

`scans.requested_commit_sha`
    The REQUESTED commit binding for API/CI/webhook-initiated scans.
    Server-set only. The worker verifies it against the actual clone and
    refuses (COMMIT_MISMATCH) rather than silently analyzing a different
    commit.

`audit_chains.organization_id`
    V4.1 tenancy extension: an organization may hold ZERO installations
    (a key-only tenant), yet its API-key lifecycle and public-API events
    must still be hash-chained. Exactly one of installation_id /
    organization_id is set per chain; the partial unique indexes below
    enforce that at the database level. installation_id drops NOT NULL
    implicitly by becoming a NULL-able column with a partial unique
    index (previously a straight UNIQUE — the one place this migration
    touches V3.8 structure, done additively and backwards-compatibly:
    every pre-existing row keeps its installation_id and satisfies the
    new partial index exactly as it satisfied the old one).

No migration introduces execution capability: DDL only.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision: str = "013"
down_revision: Union[str, None] = "012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Idempotency / replay protection ──────────────────────────────
    op.create_table(
        "api_idempotency_keys",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "organization_id",
            UUID(as_uuid=True),
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("key_value", sa.Text(), nullable=False),
        sa.Column("request_digest", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False, server_default="IN_PROGRESS"),
        sa.Column("response_status", sa.Integer()),
        sa.Column("response_body", JSONB()),
        sa.Column("actor_api_key_prefix", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_unique_constraint(
        "uq_idempotency_org_scope_key",
        "api_idempotency_keys",
        ["organization_id", "scope", "key_value"],
    )
    op.create_index(
        "ix_idempotency_expiry", "api_idempotency_keys", ["expires_at"]
    )
    op.create_index(
        "ix_idempotency_org_created",
        "api_idempotency_keys",
        ["organization_id", "created_at"],
    )

    # ── Inbound webhook delivery record ──────────────────────────────
    op.create_table(
        "webhook_deliveries",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "organization_id",
            UUID(as_uuid=True),
            sa.ForeignKey("organizations.id"),
            nullable=True,
        ),
        sa.Column("github_delivery_id", sa.Text(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("signature_state", sa.Text(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("reason_code", sa.Text()),
        sa.Column(
            "installation_pk",
            UUID(as_uuid=True),
            sa.ForeignKey("github_installations.id"),
            nullable=True,
        ),
        sa.Column(
            "repository_pk",
            UUID(as_uuid=True),
            sa.ForeignKey("repositories.id"),
            nullable=True,
        ),
        sa.Column("commit_sha", sa.Text()),
        sa.Column("ref", sa.Text()),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id"),
                  nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_unique_constraint(
        "uq_webhook_deliveries_org_delivery",
        "webhook_deliveries",
        ["organization_id", "github_delivery_id"],
    )
    op.create_index(
        "ix_webhook_deliveries_org", "webhook_deliveries", ["organization_id"]
    )
    op.create_index(
        "ix_webhook_deliveries_outcome", "webhook_deliveries", ["outcome"]
    )
    op.create_index(
        "ix_webhook_deliveries_received", "webhook_deliveries", ["received_at"]
    )

    # ── Scan commit binding (nullable, server-set only) ──────────────
    op.add_column(
        "scans",
        sa.Column("requested_commit_sha", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_scans_requested_commit", "scans", ["requested_commit_sha"]
    )

    # ── Audit chains: organization-owned chains for key-only tenants ─
    # 1. Drop the implicit UNIQUE index backed by the old column
    #    definition and recreate as a PARTIAL unique index.
    op.drop_constraint(
        "audit_chains_installation_id_key", "audit_chains", type_="unique"
    )
    op.alter_column(
        "audit_chains",
        "installation_id",
        existing_type=UUID(as_uuid=True),
        nullable=True,
    )
    op.create_index(
        "uq_audit_chains_installation",
        "audit_chains",
        ["installation_id"],
        unique=True,
        postgresql_where=sa.text("installation_id IS NOT NULL"),
    )
    # 2. Organization-owned chain (key-only tenants).
    op.add_column(
        "audit_chains",
        sa.Column(
            "organization_id",
            UUID(as_uuid=True),
            sa.ForeignKey("organizations.id"),
            nullable=True,
        ),
    )
    op.create_index(
        "uq_audit_chains_organization",
        "audit_chains",
        ["organization_id"],
        unique=True,
        postgresql_where=sa.text("organization_id IS NOT NULL"),
    )
    op.create_index(
        "ix_audit_chains_org", "audit_chains", ["organization_id"]
    )


def downgrade() -> None:
    # ── Audit chains ──────────────────────────────────────────────────
    op.drop_index("ix_audit_chains_org", table_name="audit_chains")
    op.drop_index("uq_audit_chains_organization", table_name="audit_chains")
    op.drop_column("audit_chains", "organization_id")
    op.drop_index("uq_audit_chains_installation", table_name="audit_chains")
    op.alter_column(
        "audit_chains",
        "installation_id",
        existing_type=UUID(as_uuid=True),
        nullable=False,
    )
    op.create_unique_constraint(
        "audit_chains_installation_id_key",
        "audit_chains",
        ["installation_id"],
    )

    # ── Scans ─────────────────────────────────────────────────────────
    op.drop_index("ix_scans_requested_commit", table_name="scans")
    op.drop_column("scans", "requested_commit_sha")

    # ── Webhook deliveries ────────────────────────────────────────────
    op.drop_index("ix_webhook_deliveries_received", table_name="webhook_deliveries")
    op.drop_index("ix_webhook_deliveries_outcome", table_name="webhook_deliveries")
    op.drop_index("ix_webhook_deliveries_org", table_name="webhook_deliveries")
    op.drop_constraint(
        "uq_webhook_deliveries_org_delivery",
        "webhook_deliveries",
        type_="unique",
    )
    op.drop_table("webhook_deliveries")

    # ── Idempotency ───────────────────────────────────────────────────
    op.drop_index("ix_idempotency_org_created", table_name="api_idempotency_keys")
    op.drop_index("ix_idempotency_expiry", table_name="api_idempotency_keys")
    op.drop_constraint(
        "uq_idempotency_org_scope_key", "api_idempotency_keys", type_="unique"
    )
    op.drop_table("api_idempotency_keys")
