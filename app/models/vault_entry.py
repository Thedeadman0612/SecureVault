from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.utils.helpers import utcnow

if TYPE_CHECKING:
    from app.models.user import User


class VaultEntry(Base):
    __tablename__ = "vault_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # index=True: without this every vault query (filter by user_id) is a full
    # table scan. The DB-level ON DELETE CASCADE pairs with User.cascade so
    # vault rows are deleted automatically when the parent User is removed.
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Plaintext fields — safe to store and query directly
    title: Mapped[str] = mapped_column(String, nullable=False)
    website: Mapped[str | None] = mapped_column(String, nullable=True)
    category: Mapped[str | None] = mapped_column(String, nullable=True)

    # Encrypted fields — stored as base64 tokens, never plaintext.
    # encryption_version controls which algorithm is used to read/write them:
    #   "fernet"  — Phase 1 legacy (AES-128-CBC + HMAC-SHA256 via Fernet)
    #   "aesgcm"  — Phase 2+ (AES-256-GCM authenticated encryption)
    # server_default="fernet" ensures existing rows are stamped on migration.
    # Vault service always writes "aesgcm" for new/updated entries — the
    # Python-side default="fernet" is a safe fallback, never reached in practice.
    encryption_version: Mapped[str] = mapped_column(
        String,
        nullable=False,
        default="fernet",
        server_default="fernet",
    )
    username_encrypted: Mapped[str] = mapped_column(String, nullable=False)
    password_encrypted: Mapped[str] = mapped_column(String, nullable=False)
    notes_encrypted: Mapped[str | None] = mapped_column(String, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    # W10: typed Mapped[] form instead of legacy untyped relationship().
    user: Mapped[User] = relationship("User", back_populates="vault_entries")
