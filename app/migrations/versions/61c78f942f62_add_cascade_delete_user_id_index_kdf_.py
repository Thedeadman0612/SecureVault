"""add cascade delete, user_id index, kdf_salt unique

Revision ID: 61c78f942f62
Revises: 9680c40ab116
Create Date: 2026-05-28 23:11:27.389874

Changes:
  F3 — Add ON DELETE CASCADE to vault_entries.user_id FK so that deleting a
        User automatically removes all their vault rows at the DB level.

  F4 — Add an index on vault_entries.user_id. Every vault query filters by
        user_id — without an index this is a full table scan on every request.

  W9 — Add a UNIQUE constraint on users.kdf_salt so two users can never
        accidentally share a salt and derive the same vault key.

Implementation note:
  SQLite does not support ALTER TABLE ADD/DROP CONSTRAINT. The standard
  pattern is: create a new table with the desired schema, copy data, drop the
  old table, rename the new one. This migration follows that pattern directly
  via raw DDL rather than Alembic's batch_alter_table, which has difficulty
  with unnamed FK constraints (name=None) reflected from SQLite.

  FK enforcement is temporarily disabled during the copy with
  PRAGMA foreign_keys=off to avoid spurious constraint errors on the temp
  table that references the still-present old table.
"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic
revision: str = '61c78f942f62'
down_revision: Union[str, None] = '9680c40ab116'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("PRAGMA foreign_keys=off")

    # ------------------------------------------------------------------
    # W9: Recreate users table with UNIQUE constraint on kdf_salt
    # ------------------------------------------------------------------
    op.execute("""
        CREATE TABLE users_new (
            id       INTEGER  NOT NULL,
            password_hash VARCHAR NOT NULL,
            kdf_salt      VARCHAR NOT NULL UNIQUE,
            created_at    DATETIME NOT NULL,
            updated_at    DATETIME NOT NULL,
            PRIMARY KEY (id)
        )
    """)
    op.execute("INSERT INTO users_new SELECT id, password_hash, kdf_salt, created_at, updated_at FROM users")
    op.execute("DROP TABLE users")
    op.execute("ALTER TABLE users_new RENAME TO users")

    # ------------------------------------------------------------------
    # F3: Recreate vault_entries with ON DELETE CASCADE on the FK
    # ------------------------------------------------------------------
    op.execute("""
        CREATE TABLE vault_entries_new (
            id                  INTEGER  NOT NULL,
            user_id             INTEGER  NOT NULL,
            title               VARCHAR  NOT NULL,
            website             VARCHAR,
            category            VARCHAR,
            username_encrypted  VARCHAR  NOT NULL,
            password_encrypted  VARCHAR  NOT NULL,
            notes_encrypted     VARCHAR,
            created_at          DATETIME NOT NULL,
            updated_at          DATETIME NOT NULL,
            PRIMARY KEY (id),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)
    op.execute("""
        INSERT INTO vault_entries_new
        SELECT id, user_id, title, website, category,
               username_encrypted, password_encrypted, notes_encrypted,
               created_at, updated_at
        FROM vault_entries
    """)
    op.execute("DROP TABLE vault_entries")
    op.execute("ALTER TABLE vault_entries_new RENAME TO vault_entries")

    # ------------------------------------------------------------------
    # F4: Add index on vault_entries.user_id
    # ------------------------------------------------------------------
    op.execute("CREATE INDEX ix_vault_entries_user_id ON vault_entries (user_id)")

    op.execute("PRAGMA foreign_keys=on")


def downgrade() -> None:
    op.execute("PRAGMA foreign_keys=off")

    # Remove index on vault_entries.user_id
    op.execute("DROP INDEX IF EXISTS ix_vault_entries_user_id")

    # Revert vault_entries to FK without CASCADE
    op.execute("""
        CREATE TABLE vault_entries_old (
            id                  INTEGER  NOT NULL,
            user_id             INTEGER  NOT NULL,
            title               VARCHAR  NOT NULL,
            website             VARCHAR,
            category            VARCHAR,
            username_encrypted  VARCHAR  NOT NULL,
            password_encrypted  VARCHAR  NOT NULL,
            notes_encrypted     VARCHAR,
            created_at          DATETIME NOT NULL,
            updated_at          DATETIME NOT NULL,
            PRIMARY KEY (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    op.execute("""
        INSERT INTO vault_entries_old
        SELECT id, user_id, title, website, category,
               username_encrypted, password_encrypted, notes_encrypted,
               created_at, updated_at
        FROM vault_entries
    """)
    op.execute("DROP TABLE vault_entries")
    op.execute("ALTER TABLE vault_entries_old RENAME TO vault_entries")

    # Revert users table to kdf_salt without UNIQUE
    op.execute("""
        CREATE TABLE users_old (
            id            INTEGER  NOT NULL,
            password_hash VARCHAR  NOT NULL,
            kdf_salt      VARCHAR  NOT NULL,
            created_at    DATETIME NOT NULL,
            updated_at    DATETIME NOT NULL,
            PRIMARY KEY (id)
        )
    """)
    op.execute("INSERT INTO users_old SELECT id, password_hash, kdf_salt, created_at, updated_at FROM users")
    op.execute("DROP TABLE users")
    op.execute("ALTER TABLE users_old RENAME TO users")

    op.execute("PRAGMA foreign_keys=on")
