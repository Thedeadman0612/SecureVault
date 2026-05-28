"""
app/services/vault_service.py

CRUD operations for vault entries with transparent field-level encryption.

All public functions:
  - Receive raw_key (bytes) decoded from session["encryption_key"] by the route.
  - Filter every query by user_id — a user can never read or modify another
    user's entries, even if they supply a valid entry ID.
  - Encrypt sensitive fields before writing (create / update).
  - Decrypt sensitive fields after reading, converting InvalidToken → HTTP 500.

FIELD MAP (schema ↔ ORM column):
  username  ↔  username_encrypted   (Fernet token, always present)
  password  ↔  password_encrypted   (Fernet token, always present)
  notes     ↔  notes_encrypted      (Fernet token, nullable)
  title     ↔  title                (plaintext VARCHAR)
  website   ↔  website              (plaintext VARCHAR, nullable)
  category  ↔  category             (plaintext VARCHAR, nullable)

INTERNAL HELPERS (prefixed _):
  _decrypt_entry()  — decrypts a single VaultEntry ORM row → VaultEntryResponse.
                       Catches InvalidToken and raises HTTP 500 with a generic
                       message; non-sensitive detail is logged.

SECURITY RULES (never violate):
  - Import InvalidToken from app.security.encryption (not cryptography.fernet).
  - Never log decrypted values, raw_key, or any sensitive field content.
  - Always include user_id in every query filter.
"""

import logging

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.vault_entry import VaultEntry
from app.schemas.vault import VaultEntryCreate, VaultEntryResponse, VaultEntryUpdate
from app.security.encryption import InvalidToken, decrypt_field, encrypt_field

logger = logging.getLogger(__name__)

# Shared 404 detail string — used by get_entry, update_entry, and delete_entry.
# Identical wording across all three prevents callers from inferring which
# operation failed from the response body.
_ENTRY_NOT_FOUND_MSG = "Entry not found."


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _decrypt_entry(entry: VaultEntry, raw_key: bytes) -> VaultEntryResponse:
    """Decrypt a VaultEntry ORM row into a VaultEntryResponse.

    Decrypts username_encrypted, password_encrypted, and (if present)
    notes_encrypted using the provided raw key. Any decryption failure
    (wrong key, tampered ciphertext) raises HTTP 500 with a generic message.

    Args:
        entry:   VaultEntry ORM row retrieved from the database.
        raw_key: Raw 32-byte vault encryption key from the session.

    Returns:
        VaultEntryResponse populated with plaintext sensitive fields.

    Raises:
        HTTPException 500: If InvalidToken is raised during decryption.
    """
    try:
        username = decrypt_field(entry.username_encrypted, raw_key)
        password = decrypt_field(entry.password_encrypted, raw_key)
        notes = (
            decrypt_field(entry.notes_encrypted, raw_key)
            if entry.notes_encrypted
            else None
        )
    except (InvalidToken, ValueError):
        # InvalidToken: wrong key or tampered ciphertext.
        # ValueError: decrypt_field() raises this when fernet_key is the wrong
        # length (e.g. corrupt session or key derivation bug).
        logger.error(
            "Decryption failed for entry id=%d — key mismatch, tampering, or bad key length.",
            entry.id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to decrypt entry.",
        )

    return VaultEntryResponse(
        id=entry.id,
        title=entry.title,
        website=entry.website,
        category=entry.category,
        username=username,
        password=password,
        notes=notes,
        created_at=entry.created_at,
        updated_at=entry.updated_at,
    )


# ---------------------------------------------------------------------------
# Public service functions
# ---------------------------------------------------------------------------

def create_entry(
    data: VaultEntryCreate,
    user_id: int,
    raw_key: bytes,
    db: Session,
) -> VaultEntryResponse:
    """Encrypt and persist a new vault entry.

    Encrypts username, password, and (if supplied) notes before writing.
    Plaintext fields (title, website, category) are stored as-is.

    Args:
        data:    Validated VaultEntryCreate from the route handler.
        user_id: Authenticated user's ID from session["user_id"].
        raw_key: Raw 32-byte vault encryption key from the session.
        db:      SQLAlchemy session.

    Returns:
        The newly created entry as a decrypted VaultEntryResponse.
    """
    entry = VaultEntry(
        user_id=user_id,
        title=data.title,
        website=data.website,
        category=data.category,
        username_encrypted=encrypt_field(data.username, raw_key),
        password_encrypted=encrypt_field(data.password, raw_key),
        notes_encrypted=encrypt_field(data.notes, raw_key) if data.notes else None,
    )
    db.add(entry)
    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("DB commit failed while creating vault entry for user id=%d.", user_id)
        raise
    db.refresh(entry)
    logger.info("Created vault entry id=%d for user id=%d.", entry.id, user_id)
    return _decrypt_entry(entry, raw_key)


def get_entries(
    user_id: int,
    raw_key: bytes,
    db: Session,
) -> list[VaultEntryResponse]:
    """Return all vault entries for the authenticated user, decrypted.

    Args:
        user_id: Authenticated user's ID from session["user_id"].
        raw_key: Raw 32-byte vault encryption key from the session.
        db:      SQLAlchemy session.

    Returns:
        List of decrypted VaultEntryResponse objects. Empty list if none exist.
    """
    entries = (
        db.query(VaultEntry)
        .filter(VaultEntry.user_id == user_id)
        .all()
    )
    return [_decrypt_entry(e, raw_key) for e in entries]


def get_entry(
    entry_id: int,
    user_id: int,
    raw_key: bytes,
    db: Session,
) -> VaultEntryResponse:
    """Return a single vault entry by ID, decrypted.

    Filters on both entry_id AND user_id — a user cannot retrieve another
    user's entry even if they guess the ID.

    Args:
        entry_id: Primary key of the VaultEntry to retrieve.
        user_id:  Authenticated user's ID from session["user_id"].
        raw_key:  Raw 32-byte vault encryption key from the session.
        db:       SQLAlchemy session.

    Returns:
        The requested entry as a decrypted VaultEntryResponse.

    Raises:
        HTTPException 404: No entry with that id exists for this user.
    """
    entry = (
        db.query(VaultEntry)
        .filter(VaultEntry.id == entry_id, VaultEntry.user_id == user_id)
        .first()
    )
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_ENTRY_NOT_FOUND_MSG,
        )
    return _decrypt_entry(entry, raw_key)


def update_entry(
    entry_id: int,
    data: VaultEntryUpdate,
    user_id: int,
    raw_key: bytes,
    db: Session,
) -> VaultEntryResponse:
    """Partially update an existing vault entry.

    Only non-None fields in `data` are written. Sensitive fields are
    re-encrypted with the current key before saving. Plaintext fields are
    written as-is.

    Args:
        entry_id: Primary key of the VaultEntry to update.
        data:     Validated VaultEntryUpdate from the route handler.
        user_id:  Authenticated user's ID from session["user_id"].
        raw_key:  Raw 32-byte vault encryption key from the session.
        db:       SQLAlchemy session.

    Returns:
        The updated entry as a decrypted VaultEntryResponse.

    Raises:
        HTTPException 404: No entry with that id exists for this user.
    """
    entry = (
        db.query(VaultEntry)
        .filter(VaultEntry.id == entry_id, VaultEntry.user_id == user_id)
        .first()
    )
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_ENTRY_NOT_FOUND_MSG,
        )

    # Plaintext fields — update only when explicitly supplied.
    if data.title is not None:
        entry.title = data.title
    # Nullable plaintext fields support clearing: "" means "remove this value"
    # (store NULL), any non-empty string means "update to this value".
    # None means "no change" (field was absent from the request / not edited).
    if data.website is not None:
        entry.website = data.website if data.website else None
    if data.category is not None:
        entry.category = data.category if data.category else None

    # Sensitive fields — re-encrypt before writing to DB.
    if data.username is not None:
        entry.username_encrypted = encrypt_field(data.username, raw_key)
    if data.password is not None:
        entry.password_encrypted = encrypt_field(data.password, raw_key)
    # Nullable encrypted field: "" clears to NULL, non-empty updates, None no-ops.
    if data.notes is not None:
        if data.notes:
            entry.notes_encrypted = encrypt_field(data.notes, raw_key)
        else:
            entry.notes_encrypted = None  # user explicitly cleared the notes field

    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("DB commit failed while updating vault entry id=%d for user id=%d.", entry_id, user_id)
        raise
    db.refresh(entry)
    logger.info("Updated vault entry id=%d for user id=%d.", entry.id, user_id)
    return _decrypt_entry(entry, raw_key)


def delete_entry(
    entry_id: int,
    user_id: int,
    db: Session,
) -> None:
    """Permanently delete a vault entry.

    No encryption key is needed — the Fernet tokens are deleted with the row
    and are never decrypted here. Filters on both entry_id AND user_id.

    Args:
        entry_id: Primary key of the VaultEntry to delete.
        user_id:  Authenticated user's ID from session["user_id"].
        db:       SQLAlchemy session.

    Raises:
        HTTPException 404: No entry with that id exists for this user.
    """
    entry = (
        db.query(VaultEntry)
        .filter(VaultEntry.id == entry_id, VaultEntry.user_id == user_id)
        .first()
    )
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_ENTRY_NOT_FOUND_MSG,
        )

    db.delete(entry)
    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("DB commit failed while deleting vault entry id=%d for user id=%d.", entry_id, user_id)
        raise
    logger.info("Deleted vault entry id=%d for user id=%d.", entry_id, user_id)
