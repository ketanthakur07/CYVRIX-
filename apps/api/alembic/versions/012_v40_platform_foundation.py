"""V4.0 platform foundation (organizations, memberships, invitations, API keys)

Revision ID: 012
Revises: 011
Create Date: 2026-09-25

Additive only — no V1–V3 table is altered destructively:

- organizations: tenant namespace (name/slug/state, versioned policy)
- organization_memberships: server-side membership (role + state);
  UNIQUE(organization_id, user_id)
- organization_invitations: one-time, expiring, HASHED invitations bound to
  the organization (and optionally an email)
- organization_policy_revisions: immutable policy history — a later policy
  change never rewrites the version an action was evaluated against
- api_keys: hashed, prefixed, scoped, expiring, revocable org keys
- github_installations.organization_id: nullable FK (backfilled below)

BACKFILL (V3 compatibility, Phase 37/38): every existing user receives a
personal organization and an ACTIVE ORG_OWNER membership, and every existing
installation is bound to its owner's personal organization. Legacy rows keep
working unchanged because the V3 ownership predicate (`installation.user_id`)
is still honored when organization_id is NULL, and the backfill sets it for
existing rows so no history is lost.

No migration introduces execution capability: DDL + namespace backfill only.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision: str = "012"
down_revision: Union[str, None] = "011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("slug", sa.Text(), nullable=False, unique=True),
        sa.Column("state", sa.Text(), nullable=False, server_default="ACTIVE"),
        sa.Column("is_personal", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_by", UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("policy", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("policy_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "organization_memberships",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("role", sa.Text(), nullable=False, server_default="VIEWER"),
        sa.Column("state", sa.Text(), nullable=False, server_default="ACTIVE"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("uq_org_membership", "organization_memberships",
                    ["organization_id", "user_id"], unique=True)
    op.create_index("ix_org_memberships_user", "organization_memberships",
                    ["user_id", "state"])
    op.create_index("ix_org_memberships_org", "organization_memberships",
                    ["organization_id", "state"])

    op.create_table(
        "organization_invitations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("email", sa.Text()),
        sa.Column("role", sa.Text(), nullable=False, server_default="VIEWER"),
        sa.Column("token_hash", sa.Text(), nullable=False, unique=True),
        sa.Column("created_by", UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True)),
        sa.Column("accepted_by_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_org_invitations_org", "organization_invitations", ["organization_id"])
    op.create_index("ix_org_invitations_email", "organization_invitations", ["email"])

    op.create_table(
        "organization_policy_revisions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("policy", JSONB(), nullable=False),
        sa.Column("changed_by", UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("uq_org_policy_version", "organization_policy_revisions",
                    ["organization_id", "version"], unique=True)

    op.create_table(
        "api_keys",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("prefix", sa.Text(), nullable=False, unique=True),
        sa.Column("key_hash", sa.Text(), nullable=False, unique=True),
        sa.Column("scopes", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("created_by", UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_api_keys_org", "api_keys", ["organization_id"])

    # Additive FK on the existing integration table.
    op.add_column("github_installations",
                  sa.Column("organization_id", UUID(as_uuid=True), nullable=True))
    op.create_foreign_key(
        "fk_github_installations_organization", "github_installations",
        "organizations", ["organization_id"], ["id"],
    )
    op.create_index("ix_github_installations_organization", "github_installations",
                    ["organization_id"])

    # ── Backfill: personal org + owner membership per existing user ──
    op.execute(
        """
        INSERT INTO organizations
            (id, name, slug, state, is_personal, created_by, policy,
             policy_version, created_at, updated_at)
        SELECT gen_random_uuid(), 'Personal', 'personal-' || replace(u.id::text, '-', ''),
               'ACTIVE', true, u.id, '{}'::jsonb, 1, now(), now()
        FROM users u
        """
    )
    op.execute(
        """
        INSERT INTO organization_memberships
            (id, organization_id, user_id, role, state, created_at, updated_at)
        SELECT gen_random_uuid(), o.id, o.created_by, 'ORG_OWNER', 'ACTIVE', now(), now()
        FROM organizations o
        WHERE o.is_personal = true
        """
    )
    op.execute(
        """
        UPDATE github_installations gi
        SET organization_id = o.id
        FROM organizations o
        WHERE o.is_personal = true
          AND o.created_by = gi.user_id
          AND gi.organization_id IS NULL
        """
    )
    op.execute(
        """
        INSERT INTO organization_policy_revisions
            (id, organization_id, version, policy, changed_by, created_at)
        SELECT gen_random_uuid(), o.id, 1, '{}'::jsonb, o.created_by, now()
        FROM organizations o
        """
    )


def downgrade() -> None:
    op.execute(
        "UPDATE github_installations SET organization_id = NULL "
        "WHERE organization_id IS NOT NULL"
    )
    op.drop_index("ix_github_installations_organization",
                  table_name="github_installations")
    op.drop_constraint("fk_github_installations_organization",
                       "github_installations", type_="foreignkey")
    op.drop_column("github_installations", "organization_id")

    op.drop_index("ix_api_keys_org", table_name="api_keys")
    op.drop_table("api_keys")

    op.drop_index("uq_org_policy_version", table_name="organization_policy_revisions")
    op.drop_table("organization_policy_revisions")

    op.drop_index("ix_org_invitations_email", table_name="organization_invitations")
    op.drop_index("ix_org_invitations_org", table_name="organization_invitations")
    op.drop_table("organization_invitations")

    op.drop_index("ix_org_memberships_org", table_name="organization_memberships")
    op.drop_index("ix_org_memberships_user", table_name="organization_memberships")
    op.drop_index("uq_org_membership", table_name="organization_memberships")
    op.drop_table("organization_memberships")

    op.drop_table("organizations")
