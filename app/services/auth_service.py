"""
app/services/auth_service.py

Authentication lifecycle: first-time vault setup, login, and logout.

Three functions cover the full auth flow:

  - setup_vault(password, db)       — hash master password, generate KDF salt,
                                       persist the single User row (Phase 1).
  - login(password, db, session)    — verify password, derive vault encryption
                                       key, write key + user_id to session.
  - logout(session)                 — wipe all session data so the derived key
                                       is no longer in memory.

PHASE 1 — SINGLE USER:
  There is exactly one User row. setup_vault() rejects a second call if a row
  already exists. Phase 6 adds multi-user registration.

SESSION KEYS written by login() — read by vault_service and auth_guard:
  session["encryption_key"]  str  — URL-safe base64 of the raw 32-byte key.
                                     JSON-serialisable for Starlette sessions.
  session["user_id"]          int  — primary key of the authenticated user.

SECURITY RULES (never violate):
  - Never log the raw password, derived key, or base64-encoded key.
  - Use identical HTTP 401 messages for "no user" and "wrong password" to
    prevent user-enumeration timing/message side-channels.
  - Catch ValueError from derive_key() — it signals kdf_salt corruption.
"""

import base64
import logging

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.user import User
from app.security.encryption import derive_key, generate_kdf_salt
from app.security.hashing import hash_password, verify_password

logger = logging.getLogger(__name__)

# Shared 401 detail string — identical for "no user" and "wrong password"
# so the response body does not reveal whether a vault exists.
_INVALID_PASSWORD_MSG = "Invalid password."


def setup_vault(password: str, db: Session) -> User:
    """Create the single vault user on first run.

    Hashes the master password with Argon2id and generates a fresh KDF salt,
    then persists a new User row. Raises HTTP 400 if a row already exists.

    Args:
        password: Raw master password from SetupRequest. Never stored or logged.
        db:       SQLAlchemy session (from the get_db FastAPI dependency).

    Returns:
        The newly created User ORM instance.

    Raises:
        HTTPException 400: If a User row already exists (vault already set up).
    """
    existing = db.query(User).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Vault is already set up.",
        )

    user = User(
        password_hash=hash_password(password),
        kdf_salt=generate_kdf_salt(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("Vault initialised — user id=%d created.", user.id)
    return user


def login(password: str, db: Session, session: dict) -> None:
    """Verify the master password and load the encryption key into the session.

    Looks up the single User row, verifies the password against the Argon2id
    hash, derives the vault key via PBKDF2HMAC, then writes the base64-encoded
    key and user_id into the Starlette session dict.

    Args:
        password: Raw master password from LoginRequest. Never stored or logged.
        db:       SQLAlchemy session (from the get_db FastAPI dependency).
        session:  Starlette session dict (request.session). Modified in place.

    Raises:
        HTTPException 401: No user exists, or the password is wrong.
                           Same message for both — avoids user-enumeration.
        HTTPException 500: derive_key() raised ValueError (kdf_salt corrupt).
                           Generic message returned; non-sensitive detail logged.
    """
    user = db.query(User).first()

    # Evaluate "no user" and "wrong password" as the same outcome so both
    # paths return an identical HTTP 401 with the same message.
    if user is None or not verify_password(password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_INVALID_PASSWORD_MSG,
        )

    try:
        raw_key: bytes = derive_key(password, user.kdf_salt)
    except ValueError:
        logger.error(
            "kdf_salt length invalid for user id=%d — possible DB corruption.",
            user.id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed. Please contact support.",
        )

    # Store as URL-safe base64 string — Starlette sessions must be JSON-serialisable.
    # vault_service recovers raw bytes with base64.urlsafe_b64decode().
    session["encryption_key"] = base64.urlsafe_b64encode(raw_key).decode()
    session["user_id"] = user.id
    logger.info("User id=%d logged in.", user.id)


def logout(session: dict) -> None:
    """Clear all session data, including the in-memory encryption key.

    session.clear() removes every key at once — encryption_key, user_id, and
    anything else — making the derived key irrecoverable without re-login.

    Args:
        session: Starlette session dict (request.session). Cleared in place.
    """
    session.clear()
    logger.info("Session cleared — user logged out.")
