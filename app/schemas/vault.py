"""
app/schemas/vault.py

Pydantic schemas for vault entry CRUD operations.

Three schemas cover the full lifecycle of a vault entry:

  - VaultEntryCreate  — inbound fields when creating a new entry.
  - VaultEntryUpdate  — inbound fields when editing an existing entry
                        (all fields optional; only supplied fields are written).
  - VaultEntryResponse — outbound representation returned to the template /
                         API client after the vault service has decrypted the
                         sensitive fields.

FIELD NAMING NOTE:
  The ORM model (VaultEntry) stores encrypted columns as `username_encrypted`,
  `password_encrypted`, and `notes_encrypted`. These schemas expose the logical
  names (`username`, `password`, `notes`) representing the *decrypted* values.
  The vault service is responsible for translating between the two — these
  schemas never interact with raw Fernet tokens.

  Plaintext columns (`title`, `website`, `category`) use the same names in
  both the ORM model and the schemas.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator


class VaultEntryCreate(BaseModel):
    """Validated request body for POST /entry/new.

    `title` and `password` are required — every credential needs at least a
    label and a secret. All other fields are optional.

    Fields that will be encrypted before storage:
        username, password, notes

    Fields stored as plaintext (used for search / display):
        title, website, category
    """

    title: str
    website: str | None = None
    category: str | None = None

    # Sensitive fields — vault_service encrypts these before writing to DB.
    username: str = ""          # default empty string; stored encrypted
    password: str
    notes: str | None = None    # stored encrypted when present

    @field_validator("title")
    @classmethod
    def title_not_empty(cls, value: str) -> str:
        """Reject blank or whitespace-only titles."""
        if not value.strip():
            raise ValueError("Title must not be blank.")
        return value.strip()

    @field_validator("password")
    @classmethod
    def password_not_empty(cls, value: str) -> str:
        """Reject blank or whitespace-only passwords."""
        if not value.strip():
            raise ValueError("Password must not be blank.")
        return value


class VaultEntryUpdate(BaseModel):
    """Validated request body for POST /entry/{id}/edit.

    Every field is optional so callers can supply only what changed. The vault
    service applies the update by merging non-None values onto the existing
    ORM row.

    The vault service must re-encrypt any sensitive field that is supplied
    (username, password, notes). Fields left as None are not written.
    """

    title: str | None = None
    website: str | None = None
    category: str | None = None

    # Sensitive fields — re-encrypted by vault_service when not None.
    username: str | None = None
    password: str | None = None
    notes: str | None = None

    @field_validator("title")
    @classmethod
    def title_not_empty(cls, value: str | None) -> str | None:
        """If a title is supplied, it must not be blank."""
        if value is not None and not value.strip():
            raise ValueError("Title must not be blank.")
        return value.strip() if value is not None else None

    @field_validator("password")
    @classmethod
    def password_not_empty(cls, value: str | None) -> str | None:
        """If a password is supplied, it must not be blank."""
        if value is not None and not value.strip():
            raise ValueError("Password must not be blank.")
        return value


class VaultEntryResponse(BaseModel):
    """Outbound schema for a single vault entry after decryption.

    Constructed explicitly by vault_service — never built directly from an ORM
    row via from_attributes, because the ORM column names differ from the
    logical names used here (e.g. `username_encrypted` → `username`).

    Timestamps are always UTC-aware datetimes sourced from the ORM model.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    website: str | None
    category: str | None

    # Decrypted values — vault_service decrypts before populating these fields.
    # These are NEVER Fernet tokens; by the time this schema is instantiated
    # the plaintext has already been recovered.
    username: str
    password: str
    notes: str | None

    created_at: datetime
    updated_at: datetime
