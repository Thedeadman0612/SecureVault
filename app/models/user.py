from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.utils.helpers import utcnow

if TYPE_CHECKING:
    from app.models.recovery_code import RecoveryCode
    from app.models.vault_entry import VaultEntry


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    # unique=True: in a future multi-user phase two users sharing a salt would
    # derive the same vault key — unique constraint prevents that at DB level.
    kdf_salt: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    # Phase 3: TOTP secret stored AES-GCM encrypted; NULL means 2FA is disabled.
    totp_secret: Mapped[str | None] = mapped_column(String, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )
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

    # cascade="all, delete-orphan": deleting a User automatically deletes all
    # their vault entries. Without this, SQLAlchemy would either raise an
    # IntegrityError (if the FK has no DB-level cascade) or leave orphaned rows.
    # W10: typed Mapped[] form instead of legacy untyped relationship().
    vault_entries: Mapped[list[VaultEntry]] = relationship(
        "VaultEntry",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    recovery_codes: Mapped[list[RecoveryCode]] = relationship(
        "RecoveryCode",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
