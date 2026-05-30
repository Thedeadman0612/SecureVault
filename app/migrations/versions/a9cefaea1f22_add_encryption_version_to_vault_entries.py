"""add encryption_version to vault_entries

Revision ID: a9cefaea1f22
Revises: 61c78f942f62
Create Date: 2026-05-30 11:26:45.156342

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic
revision: str = 'a9cefaea1f22'
down_revision: Union[str, None] = '61c78f942f62'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add encryption_version to vault_entries.
    # server_default="fernet" stamps every existing row with the Phase 1
    # algorithm so the service layer knows how to decrypt them.
    # No data is touched — re-encryption happens lazily in vault_service at
    # first read after login (the key is required and only lives in session).
    op.add_column(
        'vault_entries',
        sa.Column(
            'encryption_version',
            sa.String(),
            server_default='fernet',
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column('vault_entries', 'encryption_version')
