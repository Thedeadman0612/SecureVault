"""
app/security/encryption.py

Field encryption (Fernet + AES-256-GCM) and Argon2id key derivation.

This module covers two distinct cryptographic responsibilities:

  1. KDF salt generation + key derivation:
       - generate_kdf_salt()  — produces a random 32-byte salt, base64-encoded,
                                 for storage in users.kdf_salt.
       - derive_key()         — runs Argon2id (time_cost=3, memory_cost=64 MiB,
                                 parallelism=4) to produce a 32-byte encryption
                                 key from the master password and the stored salt.
                                 The key is held in session memory only — never
                                 written to disk.

  2. Vault field encryption / decryption — two algorithms, both permanent:
       - encrypt_field()      — Phase 1 Fernet (AES-128-CBC + HMAC-SHA256).
                                Kept permanently to read legacy entries.
       - decrypt_field()      — decrypts a Fernet token.
       - encrypt_field_gcm()  — Phase 2 AES-256-GCM authenticated encryption.
                                Used for all new writes after the Phase 2 upgrade.
       - decrypt_field_gcm()  — decrypts an AES-256-GCM token.

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

  AES-256-GCM (AESGCM) accepts the raw 32 bytes directly — no base64 step.
  Callers (auth_service, vault_service) always work with raw key bytes.

GCM STORAGE FORMAT:
  encrypt_field_gcm() returns: base64url( nonce ‖ ciphertext ‖ tag )
    nonce       — 12 bytes, random per encryption (prepended)
    ciphertext  — same length as plaintext (AESGCM encrypts in place)
    tag         — 16 bytes, appended by cryptography library automatically

  decrypt_field_gcm() reverses this: decode base64 → split nonce (first 12
  bytes) → pass nonce + ciphertext+tag to AESGCM.decrypt().

EXCEPTION CONSISTENCY:
  Both decrypt_field() and decrypt_field_gcm() raise InvalidToken on any
  authentication failure (wrong key, tampered ciphertext, tampered tag).
  Fernet raises InvalidToken natively. AESGCM raises InvalidTag, which
  decrypt_field_gcm() catches and converts to InvalidToken so vault_service
  uses a single except clause regardless of which algorithm was used.

SECURITY INVARIANTS — never violate these:
  - Never log the derived key, decrypted values, or any password.
  - Never store the derived key outside session memory.
  - Never hardcode salts, keys, or passwords.
"""

import base64
import os
from collections.abc import Callable

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Re-export InvalidToken so callers import it from this module rather than
# reaching into cryptography internals:
#   from app.security.encryption import InvalidToken
# This keeps vault_service and any future callers decoupled from the
# underlying cryptography library's package structure.
# InvalidTag (raised by AESGCM) is caught internally and converted to
# InvalidToken — callers never need to import InvalidTag directly.
__all__ = [
    "generate_kdf_salt",
    "derive_key",
    "encrypt_field",
    "decrypt_field",
    "encrypt_field_gcm",
    "decrypt_field_gcm",
    "get_cipher",
    "InvalidToken",
]

# Salt length in bytes. 32 bytes (256 bits) exceeds the 16-byte minimum and
# provides substantial resistance against precomputed rainbow tables.
_SALT_BYTES: int = 32

# Derived key length in bytes. 32 bytes (256 bits) used for both Fernet
# (which base64-encodes this to a 44-byte key internally) and AES-256-GCM
# (AESGCM accepts raw 32 bytes directly).
_KEY_BYTES: int = 32

# GCM nonce length in bytes. NIST SP 800-38D recommends 96-bit (12-byte)
# nonces for GCM as the "standard" construction — it avoids the extra GHASH
# computation required for other lengths and provides the strongest security
# margin. A fresh random nonce is generated for every encryption call.
_GCM_NONCE_BYTES: int = 12

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


# ---------------------------------------------------------------------------
# AES-256-GCM field encryption (Phase 2)
# ---------------------------------------------------------------------------


def encrypt_field_gcm(value: str, key: bytes) -> str:
    """Encrypt a plaintext vault field with AES-256-GCM authenticated encryption.

    AES-256-GCM provides two guarantees in a single operation:
      - Confidentiality: ciphertext reveals nothing about the plaintext.
      - Integrity / authenticity: any modification to the ciphertext or tag
        is detected at decrypt time (raises InvalidToken).

    Why GCM over Fernet (Phase 1):
      Fernet uses AES-128-CBC + a separate HMAC-SHA256. GCM uses AES-256
      with a built-in authentication tag, giving a larger key (256 vs 128
      bits) and a single-pass authenticated encryption primitive.

    Storage format: URL-safe base64( nonce ‖ ciphertext ‖ tag )
      nonce      — 12 random bytes prepended (fresh per call)
      ciphertext — same byte length as plaintext
      tag        — 16 bytes appended automatically by AESGCM

    Args:
        value: The plaintext string to encrypt.
        key:   Raw 32-byte key from derive_key(). AESGCM accepts raw bytes
               directly — no base64 encoding step needed.

    Returns:
        A URL-safe base64 string storing nonce+ciphertext+tag.
        Store directly in the DB encrypted field column.

    Raises:
        ValueError: If key is not exactly 32 bytes.
    """
    if len(key) != _KEY_BYTES:
        raise ValueError(f"key must be exactly {_KEY_BYTES} bytes.")

    # A fresh random nonce for every encryption call.
    # Never reuse a nonce with the same key — GCM nonce reuse catastrophically
    # leaks the authentication key and allows plaintext recovery.
    nonce: bytes = os.urandom(_GCM_NONCE_BYTES)

    aesgcm = AESGCM(key)
    # encrypt() appends the 16-byte authentication tag to the ciphertext.
    # The third argument is Additional Authenticated Data (AAD) — None here
    # because we have no per-record metadata to bind into the tag.
    ciphertext_and_tag: bytes = aesgcm.encrypt(nonce, value.encode("utf-8"), None)

    # Prepend the nonce so decrypt_field_gcm() can extract it without needing
    # any out-of-band storage.
    token_bytes: bytes = nonce + ciphertext_and_tag
    return base64.urlsafe_b64encode(token_bytes).decode("ascii")


def decrypt_field_gcm(token: str, key: bytes) -> str:
    """Decrypt an AES-256-GCM token back to its plaintext string.

    Args:
        token: URL-safe base64 string produced by encrypt_field_gcm()
               (layout: nonce ‖ ciphertext ‖ tag).
        key:   Raw 32-byte key from derive_key().

    Returns:
        The original plaintext string that was passed to encrypt_field_gcm().

    Raises:
        ValueError:    If key is not exactly 32 bytes, or the token is too
                       short to contain a valid nonce (indicates corruption).
        InvalidToken:  If authentication fails — wrong key, tampered
                       ciphertext, or tampered tag. Callers should catch
                       InvalidToken and return a generic error — never expose
                       this exception to the browser.

                       Note: AESGCM natively raises InvalidTag; this function
                       converts it to InvalidToken so vault_service uses a
                       single except clause for both algorithms.
    """
    if len(key) != _KEY_BYTES:
        raise ValueError(f"key must be exactly {_KEY_BYTES} bytes.")

    raw: bytes = base64.urlsafe_b64decode(token.encode("ascii"))

    # A token shorter than the nonce alone cannot be valid — fail loudly
    # rather than passing an empty ciphertext to AESGCM.decrypt().
    if len(raw) < _GCM_NONCE_BYTES:
        raise ValueError(
            f"GCM token is too short: expected at least {_GCM_NONCE_BYTES} bytes, "
            f"got {len(raw)}. Token may be corrupt or from the wrong algorithm."
        )

    nonce: bytes = raw[:_GCM_NONCE_BYTES]
    ciphertext_and_tag: bytes = raw[_GCM_NONCE_BYTES:]

    aesgcm = AESGCM(key)
    try:
        plaintext_bytes: bytes = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
    except InvalidTag:
        # Convert AESGCM's InvalidTag to Fernet's InvalidToken so callers
        # use a single except clause regardless of which algorithm was used:
        #   except InvalidToken:
        #       raise HTTPException(status_code=500, ...)
        raise InvalidToken

    return plaintext_bytes.decode("utf-8")


# ---------------------------------------------------------------------------
# Algorithm factory (Phase 2)
# ---------------------------------------------------------------------------


def get_cipher(
    version: str, key: bytes
) -> tuple[Callable[[str], str], Callable[[str], str]]:
    """Return the (encrypt_fn, decrypt_fn) pair for the given encryption version.

    This is the single point of truth for algorithm routing. vault_service
    calls get_cipher(entry.encryption_version, raw_key) and works with the
    returned callables — it never imports encrypt_field* / decrypt_field*
    directly. Adding a third algorithm later means touching only this function.

    Both returned callables share the same interface:
        encrypt_fn(plaintext: str) -> str   # returns a base64 token
        decrypt_fn(token:     str) -> str   # returns plaintext

    The key is bound into the closures — callers pass only the plaintext or
    token string. This keeps vault_service free of any key-passing boilerplate.

    Args:
        version: The encryption_version string stored on the VaultEntry row.
                 One of: "fernet" (Phase 1 legacy), "aesgcm" (Phase 2+).
        key:     Raw 32-byte key from derive_key() (held in session memory).

    Returns:
        (encrypt_fn, decrypt_fn) — both pre-bound to `key`.

    Raises:
        ValueError: If `version` is not a recognised algorithm string. This
                    is a hard fail — silently falling back to the wrong
                    algorithm would silently produce unreadable ciphertext.

    Example:
        encrypt, decrypt = get_cipher(entry.encryption_version, raw_key)
        plaintext = decrypt(entry.username_encrypted)
        new_token = encrypt(new_plaintext)
    """
    if version == "fernet":
        return (
            lambda value: encrypt_field(value, key),
            lambda token: decrypt_field(token, key),
        )
    if version == "aesgcm":
        return (
            lambda value: encrypt_field_gcm(value, key),
            lambda token: decrypt_field_gcm(token, key),
        )
    raise ValueError(
        f"Unknown encryption_version {version!r}. "
        "Expected 'fernet' or 'aesgcm'. "
        "Possible data corruption in vault_entries.encryption_version."
    )
