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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.recovery_code import RecoveryCode
from app.models.user import User
from app.security.encryption import derive_key, encrypt_field_gcm, generate_kdf_salt
from app.security.hashing import hash_password, needs_rehash, verify_password
from app.security.totp import generate_recovery_codes, hash_recovery_code, verify_totp
from app.utils.helpers import utcnow

logger = logging.getLogger(__name__)

# Shared 401 detail string — identical for "no user" and "wrong password"
# so the response body does not reveal whether a vault exists.
_INVALID_PASSWORD_MSG = "Invalid password."

# Dummy hash used when no User row exists so that verify_password() always
# runs its full Argon2id computation (~200 ms) regardless of whether a vault
# has been set up. Without this, the "no user" path would return immediately,
# allowing an attacker to detect vault existence via response-time difference.
# The hash is generated once at module import time — not per-request.
_DUMMY_HASH: str = hash_password("dummy-constant-for-timing-equalisation")


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
    try:
        db.commit()
    except IntegrityError:
        # Two near-simultaneous POST /setup requests can both pass the
        # existence check before either commits (TOCTOU). The unique constraint
        # on kdf_salt (or the single-row invariant) catches the second commit.
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Vault is already set up.",
        )
    db.refresh(user)
    logger.info("Vault initialised — user id=%d created.", user.id)
    return user


def login(password: str, db: Session, session: dict) -> bool:
    """Verify the master password and load the encryption key into the session.

    Looks up the single User row, verifies the password against the Argon2id
    hash, derives the vault key, then either writes the full session (no 2FA)
    or writes a pending session (2FA enabled, TOTP step still required).

    Args:
        password: Raw master password from LoginRequest. Never stored or logged.
        db:       SQLAlchemy session (from the get_db FastAPI dependency).
        session:  Starlette session dict (request.session). Modified in place.

    Returns:
        True  — TOTP step required; session contains pending_user_id and
                pending_encryption_key but NOT encryption_key. The route must
                redirect to /2fa/verify.
        False — Login complete; session contains encryption_key and user_id.

    Raises:
        HTTPException 401: No user exists, or the password is wrong.
                           Same message for both — avoids user-enumeration.
        HTTPException 500: derive_key() raised ValueError (kdf_salt corrupt).
                           Generic message returned; non-sensitive detail logged.
    """
    user = db.query(User).first()

    # Always run the full Argon2id verification to equalise timing between
    # "no user" and "wrong password" — prevents vault-existence detection.
    # When no user row exists, verify against _DUMMY_HASH (which will always
    # fail) so we still pay the ~200 ms Argon2id cost before returning 401.
    hash_to_check = user.password_hash if user is not None else _DUMMY_HASH
    password_ok = verify_password(password, hash_to_check)

    if user is None or not password_ok:
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

    # Check whether the stored hash was produced with old Argon2 parameters.
    # If argon2-cffi's defaults ever change (e.g. a new release bumps memory_cost),
    # old hashes stored in the DB will lag behind. We silently upgrade the hash
    # here — after we've already verified the plaintext password is correct —
    # so future logins use the stronger parameters automatically.
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        db.commit()
        logger.info("Rehashed password for user id=%d — Argon2 parameters upgraded.", user.id)

    # Clear any pre-existing session data before writing new keys.
    # Prevents session fixation: an attacker who plants session data before
    # login cannot have it merged with the newly authenticated session.
    session.clear()

    key_b64: str = base64.urlsafe_b64encode(raw_key).decode()

    if user.totp_enabled:
        # Password verified, key derived — but TOTP must be checked before
        # granting vault access. Store a pending state; AuthGuard grants
        # access only on encryption_key, not pending_user_id.
        session["pending_user_id"] = user.id
        session["pending_encryption_key"] = key_b64
        logger.info("User id=%d passed password check; awaiting TOTP.", user.id)
        return True

    # 2FA not enabled — complete the session immediately.
    session["encryption_key"] = key_b64
    session["user_id"] = user.id
    logger.info("User id=%d logged in.", user.id)
    return False


def logout(session: dict) -> None:
    """Clear all session data, including the in-memory encryption key.

    session.clear() removes every key at once — encryption_key, user_id, and
    anything else — making the derived key irrecoverable without re-login.

    Args:
        session: Starlette session dict (request.session). Cleared in place.
    """
    session.clear()
    logger.info("Session cleared — user logged out.")


def enable_2fa(
    user_id: int,
    secret: str,
    confirmation_token: str,
    raw_key: bytes,
    db: Session,
) -> list[str]:
    """Activate TOTP 2FA for the user after confirming their authenticator is synced.

    Verifies the first TOTP code before persisting anything — ensures the user
    can actually produce valid codes before 2FA is locked in. On success the
    secret is AES-GCM encrypted and stored, 8 recovery codes are generated and
    hashed (Argon2id), and the plaintext codes are returned once to the caller.

    Args:
        user_id:            Primary key of the authenticated user.
        secret:             Plaintext Base32 TOTP secret from the setup session.
                            Never stored in plaintext — encrypted before saving.
        confirmation_token: 6-digit code from the user's authenticator app,
                            used to confirm the secret is correctly configured.
        raw_key:            Raw 32-byte vault encryption key from the session,
                            used to AES-GCM encrypt the secret at rest.
        db:                 SQLAlchemy session.

    Returns:
        List of 8 plaintext recovery codes. Show to the user exactly once;
        only Argon2id hashes are stored in the DB.

    Raises:
        HTTPException 422: confirmation_token is invalid (wrong code, expired).
        HTTPException 404: No User row found for user_id (should not happen in
                           normal flow since the session already has user_id).
    """
    if not verify_totp(secret, confirmation_token):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid confirmation code. Please try again.",
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    # Delete any existing recovery codes (handles the re-setup case where
    # the user is cycling their 2FA configuration).
    db.query(RecoveryCode).filter(RecoveryCode.user_id == user_id).delete()

    user.totp_secret = encrypt_field_gcm(secret, raw_key)
    user.totp_enabled = True
    user.updated_at = utcnow()

    codes = generate_recovery_codes()
    for code in codes:
        db.add(RecoveryCode(user_id=user_id, code_hash=hash_recovery_code(code)))

    db.commit()
    logger.info("2FA enabled for user id=%d; %d recovery codes issued.", user_id, len(codes))
    return codes


def disable_2fa(user_id: int, db: Session) -> None:
    """Deactivate TOTP 2FA and delete all recovery codes for the user.

    Args:
        user_id: Primary key of the authenticated user.
        db:      SQLAlchemy session.

    Raises:
        HTTPException 404: No User row found for user_id.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    user.totp_secret = None
    user.totp_enabled = False
    user.updated_at = utcnow()
    db.query(RecoveryCode).filter(RecoveryCode.user_id == user_id).delete()
    db.commit()
    logger.info("2FA disabled for user id=%d.", user_id)
