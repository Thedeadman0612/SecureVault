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
  username  ↔  username_encrypted   (encrypted token, always present)
  password  ↔  password_encrypted   (encrypted token, always present)
  notes     ↔  notes_encrypted      (encrypted token, nullable)
  title     ↔  title                (plaintext VARCHAR)
  website   ↔  website              (plaintext VARCHAR, nullable)
  category  ↔  category             (plaintext VARCHAR, nullable)

ENCRYPTION VERSIONING (Phase 2):
  Each vault_entries row carries an encryption_version column:
    "fernet"  — Phase 1 legacy: AES-128-CBC + HMAC-SHA256 via Fernet.
    "aesgcm"  — Phase 2+: AES-256-GCM authenticated encryption.

  All writes (create / update) use "aesgcm". Legacy "fernet" rows are upgraded
  transparently on first read (lazy re-encryption in _decrypt_entry). The
  algorithm is selected at runtime via get_cipher(entry.encryption_version, key).

INTERNAL HELPERS (prefixed _):
  _decrypt_entry()  — decrypts a single VaultEntry ORM row → VaultEntryResponse.
                       Algorithm is chosen from entry.encryption_version.
                       If db is provided and the entry is still "fernet", lazily
                       re-encrypts with AES-256-GCM and saves before returning.
                       Catches InvalidToken and raises HTTP 500 with a generic
                       message; non-sensitive detail is logged.

SECURITY RULES (never violate):
  - Import InvalidToken from app.security.encryption (not cryptography.fernet).
  - Never log decrypted values, raw_key, or any sensitive field content.
  - Always include user_id in every query filter.
"""

import logging

from fastapi import HTTPException, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.vault_entry import VaultEntry
from app.schemas.vault import VaultEntryCreate, VaultEntryResponse, VaultEntryUpdate
from app.security.encryption import InvalidToken, get_cipher

logger = logging.getLogger(__name__)

# Shared 404 detail string — used by get_entry, update_entry, and delete_entry.
# Identical wording across all three prevents callers from inferring which
# operation failed from the response body.
_ENTRY_NOT_FOUND_MSG = "Entry not found."


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _decrypt_entry(
    entry: VaultEntry,
    raw_key: bytes,
    db: Session | None = None,
) -> VaultEntryResponse:
    """Decrypt a VaultEntry ORM row into a VaultEntryResponse.

    Uses get_cipher(entry.encryption_version, raw_key) to select the correct
    algorithm per row — "fernet" for Phase 1 legacy entries, "aesgcm" for
    Phase 2+ entries. Any decryption failure raises HTTP 500.

    Lazy re-encryption (Phase 2 upgrade path):
      If db is provided and the entry's encryption_version is not "aesgcm",
      this function re-encrypts all sensitive fields with AES-256-GCM and
      saves the row back to the database before returning. The user's key is
      already in memory (the entry was just successfully decrypted), so there
      is no extra authentication cost. Re-encryption failure is non-fatal —
      the decrypted response is still returned and will be retried next read.

    Args:
        entry:   VaultEntry ORM row retrieved from the database.
        raw_key: Raw 32-byte vault encryption key from the session.
        db:      SQLAlchemy session. When provided, enables lazy re-encryption
                 of legacy Fernet entries to AES-256-GCM on first read.

    Returns:
        VaultEntryResponse populated with plaintext sensitive fields.

    Raises:
        HTTPException 500: If decryption fails (wrong key, tampered ciphertext,
            bad key length).
    """
    # get_cipher() returns (encrypt_fn, decrypt_fn) pre-bound to raw_key.
    # We only need decrypt here; the encrypt closure is used in the lazy
    # re-encryption block below.
    _, decrypt = get_cipher(entry.encryption_version, raw_key)

    try:
        username = decrypt(entry.username_encrypted)
        password = decrypt(entry.password_encrypted)
        notes = decrypt(entry.notes_encrypted) if entry.notes_encrypted else None
    except (InvalidToken, ValueError):
        # InvalidToken: wrong key or tampered ciphertext (both Fernet and GCM).
        # ValueError: get_cipher raises this for an unknown encryption_version
        # string (DB corruption), or decrypt_field raises it for a wrong key
        # length (corrupt session / key derivation bug).
        logger.error(
            "Decryption failed for entry id=%d (version=%r) — "
            "key mismatch, tampering, corrupt version, or bad key length.",
            entry.id,
            entry.encryption_version,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to decrypt entry.",
        )

    # -------------------------------------------------------------------------
    # Lazy re-encryption: upgrade "fernet" entries to "aesgcm" on first read.
    #
    # Why here and not in a migration:
    #   The encryption key only exists in session memory after login — Alembic
    #   has no access to it. So the schema migration (T4) added the column;
    #   this block does the actual data upgrade, piggy-backing on reads that
    #   are already loading and decrypting the entry.
    #
    # Why non-fatal on failure:
    #   If the commit fails (e.g. transient DB error) we still return the
    #   correctly decrypted response. The entry stays "fernet" in the DB and
    #   will be retried on the next read. Prefer availability over strict
    #   upgrade enforcement.
    # -------------------------------------------------------------------------
    if db is not None and entry.encryption_version != "aesgcm":
        encrypt, _ = get_cipher("aesgcm", raw_key)
        try:
            entry.username_encrypted = encrypt(username)
            entry.password_encrypted = encrypt(password)
            entry.notes_encrypted = encrypt(notes) if notes is not None else None
            entry.encryption_version = "aesgcm"
            db.commit()
            logger.info(
                "Lazily re-encrypted entry id=%d from 'fernet' to 'aesgcm'.",
                entry.id,
            )
        except Exception:
            db.rollback()
            # Reset the in-memory ORM object so it reflects the DB state (still
            # "fernet") — avoids a stale object confusing subsequent operations.
            entry.encryption_version = "fernet"
            logger.exception(
                "Lazy re-encryption failed for entry id=%d; "
                "returning decrypted value, will retry on next read.",
                entry.id,
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
    # All new entries are written with AES-256-GCM from the start.
    # get_cipher("aesgcm", raw_key) returns an encrypt closure pre-bound to
    # the key — callers pass only the plaintext string.
    encrypt, _ = get_cipher("aesgcm", raw_key)
    entry = VaultEntry(
        user_id=user_id,
        title=data.title,
        website=data.website,
        category=data.category,
        encryption_version="aesgcm",
        username_encrypted=encrypt(data.username),
        password_encrypted=encrypt(data.password),
        notes_encrypted=encrypt(data.notes) if data.notes else None,
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


def get_categories(user_id: int, db: Session) -> list[str]:
    """Return sorted list of distinct non-null categories for a user.

    Args:
        user_id: Authenticated user's ID from session["user_id"].
        db:      SQLAlchemy session.

    Returns:
        Alphabetically sorted list of category strings.
    """
    rows = (
        db.query(VaultEntry.category)
        .filter(VaultEntry.user_id == user_id, VaultEntry.category.isnot(None))
        .distinct()
        .all()
    )
    return sorted(row[0] for row in rows)


def get_entries(
    user_id: int,
    raw_key: bytes,
    db: Session,
    q: str | None = None,
    category: str | None = None,
) -> list[VaultEntryResponse]:
    """Return vault entries for the authenticated user, decrypted.

    Optionally filters by a text query (title/website ilike) and/or by exact
    category match. Both plaintext columns — no decryption needed to filter.

    Args:
        user_id:  Authenticated user's ID from session["user_id"].
        raw_key:  Raw 32-byte vault encryption key from the session.
        db:       SQLAlchemy session.
        q:        Optional text search against title and website (case-insensitive).
        category: Optional exact category filter.

    Returns:
        List of decrypted VaultEntryResponse objects. Empty list if none match.
    """
    query = db.query(VaultEntry).filter(VaultEntry.user_id == user_id)
    if q:
        pattern = f"%{q}%"
        query = query.filter(
            or_(
                VaultEntry.title.ilike(pattern),
                VaultEntry.website.ilike(pattern),
            )
        )
    if category:
        query = query.filter(VaultEntry.category == category)
    entries = query.all()
    # Pass db so legacy "fernet" entries are lazily re-encrypted on first read.
    return [_decrypt_entry(e, raw_key, db=db) for e in entries]


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
    # Pass db so a legacy "fernet" entry is lazily re-encrypted on first read.
    return _decrypt_entry(entry, raw_key, db=db)


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

    # Sensitive fields — re-encrypt using the entry's CURRENT algorithm.
    #
    # Why not force "aesgcm" here?
    #   If we encrypted some fields with GCM but left others in Fernet, the row
    #   would have mixed ciphertexts while encryption_version could only hold one
    #   value — an inconsistency that would cause decryption failures. Instead, we
    #   keep ALL fields on the same algorithm for this commit, then let
    #   _decrypt_entry() atomically upgrade the ENTIRE row to AES-256-GCM on the
    #   read-back (the lazy re-encryption block). That upgrade always touches all
    #   three fields together, so the row is never in a mixed state.
    encrypt, _ = get_cipher(entry.encryption_version, raw_key)
    if data.username is not None:
        entry.username_encrypted = encrypt(data.username)
    if data.password is not None:
        entry.password_encrypted = encrypt(data.password)
    # Nullable encrypted field: "" clears to NULL, non-empty updates, None no-ops.
    if data.notes is not None:
        if data.notes:
            entry.notes_encrypted = encrypt(data.notes)
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
    # Pass db so _decrypt_entry() lazily upgrades any 'fernet' row to 'aesgcm'
    # after the update — all three sensitive fields are upgraded atomically.
    return _decrypt_entry(entry, raw_key, db=db)


def delete_entry(
    entry_id: int,
    user_id: int,
    db: Session,
) -> None:
    """Permanently delete a vault entry.

    No encryption key is needed — the encrypted tokens are deleted with the row
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
