"""V2.6 recommendation re-validation columns

Revision ID: 003
Revises: 002
Create Date: 2026-09-03

Adds:
- validation_state column to recommendations
- validation_details column to recommendations
- validated_at column to recommendations
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("recommendations", sa.Column("validation_state", sa.Text(), nullable=True))
    op.add_column("recommendations", sa.Column("validation_details", JSONB(), nullable=True))
    op.add_column("recommendations", sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_recommendations_validation_state", "recommendations", ["validation_state"])


def downgrade() -> None:
    op.drop_index("ix_recommendations_validation_state", "recommendations")
    op.drop_column("recommendations", "validated_at")
    op.drop_column("recommendations", "validation_details")
    op.drop_column("recommendations", "validation_state")
