"""
app/security/encryption.py

Fernet-based field encryption and Argon2id key derivation.

This module covers two distinct cryptographic responsibilities:

  1. KDF salt generation + key derivation:
       - generate_kdf_salt()  — produces a random 32-byte salt, base64-encoded,
                                 for storage in users.kdf_salt.
       - derive_key()         — runs Argon2id (time_cost=3, memory_cost=64 MiB,
                                 parallelism=4) to produce a 32-byte encryption
                                 key from the master password and the stored salt.
                                 The key is held in session memory only — never
                                 written to disk.

  2. Vault field encryption / decryption:
       - encrypt_field()  — encrypts a plaintext string with Fernet, returns a
                            base64 token string for storage in the DB.
       - decrypt_field()  — decrypts a stored Fernet token back to plaintext.

PHASE 2 UPGRADE — PBKDF2HMAC → Argon2id:
  Phase 1 used PBKDF2HMAC (SHA-256, 600,000 iterations). Argon2id is
  memory-hard: it requires both CPU time AND RAM, making GPU/ASIC
  brute-force attacks orders of magnitude more expensive. The function
  signature of derive_key() is unchanged — no callers need updating.

  ⚠️  Breaking change: Argon2id derives a DIFFERENT key from the same
  (password, salt) pair than PBKDF2HMAC did. Existing Phase 1 vaults
  will fail to decrypt after this upgrade. Delete securevault.db and
  re-run /setup to create a fresh vault.

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

from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet, InvalidToken

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

# Salt length in bytes. 32 bytes (256 bits) exceeds the 16-byte minimum and
# provides substantial resistance against precomputed rainbow tables.
_SALT_BYTES: int = 32

# Derived key length in bytes. 32 bytes (256 bits) used for both Fernet
# (which base64-encodes this to a 44-byte key internally) and AES-256-GCM
# (added in Task 2).
_KEY_BYTES: int = 32

# Argon2id parameters — OWASP recommended minimums for interactive login
# (https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html):
#   time_cost   = 3 iterations through memory
#   memory_cost = 64 MiB (65536 KiB)  ← the "memory-hard" property;
#                                        GPU/ASIC attacks require this RAM per guess
#   parallelism = 4 parallel threads
#
# Changing these constants after deployment is a BREAKING CHANGE — all existing
# vaults would derive a different key and become permanently unrecoverable.
_ARGON2_TIME_COST: int = 3
_ARGON2_MEMORY_COST: int = 65_536   # KiB → 64 MiB
_ARGON2_PARALLELISM: int = 4


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

    Uses Argon2id with OWASP-recommended interactive parameters (time_cost=3,
    memory_cost=64 MiB, parallelism=4). The derivation is deterministic:
    identical (password, salt) pairs always produce the same key, which is
    what allows the vault to be decrypted on every login without storing
    the key anywhere.

    Why Argon2id over PBKDF2HMAC (Phase 1):
      PBKDF2 is CPU-only — an attacker with a GPU farm can test billions of
      password guesses per second. Argon2id requires a fixed amount of RAM
      per guess (64 MiB here), so GPU/ASIC attacks gain far less parallelism.
      An attacker needs 64 MiB × (number of parallel guesses), making
      large-scale brute-force economically impractical.

    The returned raw bytes are held in session memory only. They are NOT
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
    # Decode the base64 salt back to raw bytes.
    raw_salt: bytes = base64.urlsafe_b64decode(kdf_salt_b64.encode("ascii"))

    # Validate the decoded length. Argon2id accepts any salt length, so a
    # corrupt kdf_salt column would silently produce the wrong key — making
    # all vault entries permanently unrecoverable. Fail loudly instead.
    if len(raw_salt) != _SALT_BYTES:
        raise ValueError(
            f"Decoded KDF salt must be {_SALT_BYTES} bytes; "
            f"got {len(raw_salt)}. Possible data corruption in users.kdf_salt."
        )

    # hash_secret_raw() returns raw bytes (no PHC string wrapping), which is
    # exactly what we need for a KDF. This is the low-level API of argon2-cffi;
    # the high-level PasswordHasher is for password storage, not key derivation.
    raw_key: bytes = hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=raw_salt,
        time_cost=_ARGON2_TIME_COST,
        memory_cost=_ARGON2_MEMORY_COST,
        parallelism=_ARGON2_PARALLELISM,
        hash_len=_KEY_BYTES,
        type=Type.ID,   # Argon2id — the "ID" variant combines resistance to
                        # side-channel attacks (Argon2i) and GPU attacks (Argon2d)
    )
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

    # Use utf-8 (not ascii) so that a corrupt token containing non-ASCII bytes
    # raises UnicodeDecodeError rather than being silently mis-encoded.
    # The resulting bytes are passed straight to Fernet.decrypt() which will
    # raise InvalidToken if the content is not a valid Fernet token — that
    # exception is what callers expect to catch.
    plaintext_bytes: bytes = f.decrypt(token.encode("utf-8"))
    return plaintext_bytes.decode("utf-8")
