"""
app/security/encryption.py

Fernet-based field encryption and PBKDF2HMAC key derivation.

This module covers two distinct cryptographic responsibilities:

  1. KDF salt generation + key derivation:
       - generate_kdf_salt()  — produces a random 32-byte salt, base64-encoded,
                                 for storage in users.kdf_salt.
       - derive_key()         — runs PBKDF2HMAC(SHA-256, 600_000 iterations) to
                                 produce a 32-byte encryption key from the master
                                 password and the stored salt. The key is held in
                                 session memory only — never written to disk.

  2. Vault field encryption / decryption:
       - encrypt_field()  — encrypts a plaintext string with Fernet, returns a
                            base64 token string for storage in the DB.
       - decrypt_field()  — decrypts a stored Fernet token back to plaintext.

KEY ENCODING NOTE:
  derive_key() returns raw 32 bytes.
  Fernet requires a 44-byte URL-safe base64-encoded key (not raw bytes).
  encrypt_field() and decrypt_field() perform this conversion internally:

    base64.urlsafe_b64encode(raw_32_bytes)  →  44-byte Fernet-compatible key

  Callers (auth_service, vault_service) always work with raw key bytes.
  The base64-of-key step is an implementation detail of this module.

SECURITY INVARIANTS — never violate these:
  - Never log the derived key, decrypted values, or any password.
  - Never store the derived key outside session memory.
  - Never hardcode salts, keys, or passwords.
"""

import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Re-export InvalidToken so callers import it from this module rather than
# reaching into cryptography internals:
#   from app.security.encryption import InvalidToken
# This keeps vault_service and any future callers decoupled from the
# underlying cryptography library's package structure.
__all__ = [
    "generate_kdf_salt",
    "derive_key",
    "encrypt_field",
    "decrypt_field",
    "InvalidToken",
]

# PBKDF2HMAC iteration count — NIST SP 800-132 recommends ≥310,000 for SHA-256
# as of 2023; OWASP recommends 600,000. Phase 2 can upgrade to Argon2id.
_PBKDF2_ITERATIONS: int = 600_000

# Salt length in bytes. 32 bytes (256 bits) exceeds the 16-byte minimum and
# provides substantial resistance against precomputed rainbow tables.
_SALT_BYTES: int = 32

# Derived key length in bytes. Fernet uses AES-128 internally, but we derive
# 32 bytes because PBKDF2 output length should match the hash output size
# (SHA-256 → 32 bytes). base64.urlsafe_b64encode(32 bytes) → 44-byte Fernet key.
_KEY_BYTES: int = 32


def generate_kdf_salt() -> str:
    """Generate a cryptographically random 32-byte KDF salt.

    The salt is encoded as URL-safe base64 so it can be stored directly in the
    users.kdf_salt VARCHAR column without escaping. The same encoding is decoded
    back in derive_key() before use.

    Returns:
        A URL-safe base64-encoded string representing 32 random bytes.
        Example: "A3bF9...==" (44 characters, no line breaks).

    Note:
        os.urandom() is backed by the OS CSPRNG (/dev/urandom on Linux/macOS,
        CryptGenRandom on Windows). It is safe for cryptographic use.

    Warning:
        Call this ONCE at user setup and store the result in users.kdf_salt.
        Never regenerate it — doing so would make all existing vault entries
        permanently unrecoverable.
    """
    raw_salt: bytes = os.urandom(_SALT_BYTES)
    return base64.urlsafe_b64encode(raw_salt).decode("ascii")


def derive_key(master_password: str, kdf_salt_b64: str) -> bytes:
    """Derive a 32-byte encryption key from the master password and stored salt.

    Uses PBKDF2HMAC with SHA-256 and 600,000 iterations. The derivation is
    deterministic: identical (password, salt) pairs always produce the same key.
    This is what allows the vault to be decrypted on every login without storing
    the key anywhere.

    The returned raw bytes are what the session stores in memory. They are NOT
    suitable for passing directly to Fernet(); use encrypt_field() /
    decrypt_field() which handle the base64 encoding step internally.

    Args:
        master_password: The raw master password entered at login (plaintext).
        kdf_salt_b64:    The URL-safe base64 salt string from users.kdf_salt.

    Returns:
        32 raw bytes — the derived vault encryption key.
        Store this in the session; clear it on logout.

    Raises:
        ValueError: If kdf_salt_b64 is not valid base64 or decodes to the wrong
            length (indicates data corruption in users.kdf_salt).
    """
    # Decode the base64 salt back to raw bytes for use as the PBKDF2 salt.
    raw_salt: bytes = base64.urlsafe_b64decode(kdf_salt_b64.encode("ascii"))

    # Validate the decoded length. PBKDF2 accepts any salt length, so a
    # corrupt kdf_salt column would silently produce the wrong key — making
    # all vault entries permanently unrecoverable. Fail loudly instead.
    if len(raw_salt) != _SALT_BYTES:
        raise ValueError(
            f"Decoded KDF salt must be {_SALT_BYTES} bytes; "
            f"got {len(raw_salt)}. Possible data corruption in users.kdf_salt."
        )

    # PBKDF2HMAC instances are single-use — construct a new one each call.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_BYTES,
        salt=raw_salt,
        iterations=_PBKDF2_ITERATIONS,
    )

    # Encode the password as UTF-8 to correctly handle any non-ASCII characters
    # the user may have included in their master password.
    raw_key: bytes = kdf.derive(master_password.encode("utf-8"))
    return raw_key


def encrypt_field(value: str, fernet_key: bytes) -> str:
    """Encrypt a plaintext vault field with Fernet symmetric encryption.

    Fernet provides AES-128-CBC + HMAC-SHA256 authenticated encryption.
    The resulting token includes a timestamp, IV, ciphertext, and MAC —
    all base64-encoded into a single opaque string that is safe to store
    directly in the VARCHAR columns (username_encrypted, password_encrypted,
    notes_encrypted).

    Args:
        value:       The plaintext string to encrypt (e.g. a stored username
                     or credential password).
        fernet_key:  The raw 32-byte key from derive_key(). This function
                     performs the urlsafe-base64 encoding internally before
                     constructing the Fernet instance — callers pass raw bytes.

    Returns:
        A URL-safe base64 Fernet token string (e.g. "gAAAAAB...==").
        Store this directly in the DB encrypted field column.

    Raises:
        ValueError: If fernet_key is not exactly 32 bytes.
    """
    if len(fernet_key) != _KEY_BYTES:
        raise ValueError(
            f"fernet_key must be exactly {_KEY_BYTES} bytes."
        )

    # Fernet requires a 44-byte URL-safe base64-encoded key, not raw bytes.
    # This is the critical bridge between derive_key() output and Fernet().
    encoded_key: bytes = base64.urlsafe_b64encode(fernet_key)
    f = Fernet(encoded_key)

    token_bytes: bytes = f.encrypt(value.encode("utf-8"))
    return token_bytes.decode("ascii")


def decrypt_field(token: str, fernet_key: bytes) -> str:
    """Decrypt a stored Fernet token back to its plaintext string.

    Args:
        token:       The Fernet token string retrieved from the DB
                     (e.g. the value of username_encrypted).
        fernet_key:  The raw 32-byte key from derive_key(). Urlsafe-base64
                     encoding is handled internally.

    Returns:
        The original plaintext string that was passed to encrypt_field().

    Raises:
        ValueError: If fernet_key is not exactly 32 bytes.
        cryptography.fernet.InvalidToken: If the token has been tampered with
            or the key is wrong. Callers should catch InvalidToken and return
            a generic error — never expose this exception to the browser.
    """
    if len(fernet_key) != _KEY_BYTES:
        raise ValueError(
            f"fernet_key must be exactly {_KEY_BYTES} bytes."
        )

    encoded_key: bytes = base64.urlsafe_b64encode(fernet_key)
    f = Fernet(encoded_key)

    plaintext_bytes: bytes = f.decrypt(token.encode("ascii"))
    return plaintext_bytes.decode("utf-8")
