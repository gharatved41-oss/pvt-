"""initial_schema

Revision ID: 535f960cbf27
Revises: 
Create Date: 2026-10-27 19:17:57.907417

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from app.core.database import Base

# revision identifiers, used by Alembic.
revision: str = '535f960cbf27'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: ensure all Phase 1 and platform tables are properly created."""
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    """Downgrade schema."""
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
