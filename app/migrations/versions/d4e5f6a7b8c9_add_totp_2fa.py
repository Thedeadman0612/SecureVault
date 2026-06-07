"""add TOTP 2FA: totp columns on users, recovery_codes table

Revision ID: d4e5f6a7b8c9
Revises: a9cefaea1f22
Create Date: 2026-06-07 00:00:00.000000

Changes (Phase 3):
  - users.totp_secret     VARCHAR NULL  — AES-GCM encrypted TOTP secret;
                                          NULL means 2FA is not enabled.
  - users.totp_enabled    BOOLEAN NOT NULL DEFAULT 0  — flag set to 1 after
                                          the user confirms their first TOTP code.
  - recovery_codes table  — stores Argon2id hashes of one-time recovery codes;
                            FK to users with ON DELETE CASCADE.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic
revision: str = "d4e5f6a7b8c9"
down_revision: Union[str, None] = "a9cefaea1f22"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # SQLite supports ALTER TABLE ADD COLUMN for nullable columns and columns
    # with a non-expression default, so op.add_column() is safe here.
    op.add_column(
        "users",
        sa.Column("totp_secret", sa.String(), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column(
            "totp_enabled",
            sa.Boolean(),
            nullable=False,
            server_default="0",
        ),
    )

    op.create_table(
        "recovery_codes",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("code_hash", sa.String(), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_recovery_codes_user_id", "recovery_codes", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_recovery_codes_user_id", table_name="recovery_codes")
    op.drop_table("recovery_codes")
    op.drop_column("users", "totp_enabled")
    op.drop_column("users", "totp_secret")
