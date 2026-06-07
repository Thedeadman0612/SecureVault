"""
app/security/totp.py

TOTP two-factor authentication utilities for Phase 3.

Responsibilities:
  - Secret generation and provisioning URI construction (for QR code setup).
  - TOTP token verification with a configurable time window.
  - Recovery code generation, hashing, and verification.

SECURITY INVARIANTS:
  - The raw TOTP secret must never be logged. The caller (auth_service) is
    responsible for encrypting it with encrypt_field_gcm() before storing it.
  - Recovery codes are single-use: mark used_at in the DB immediately after
    a successful verify_recovery_code() call.
  - Hash recovery codes with Argon2id (same strength as master password hashing)
    so a DB dump does not yield usable codes.
"""

import secrets

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

__all__ = [
    "generate_secret",
    "get_provisioning_uri",
    "verify_totp",
    "generate_recovery_codes",
    "hash_recovery_code",
    "verify_recovery_code",
]

# Shared hasher instance — stateless, safe to reuse across calls.
_ph = PasswordHasher()

_RECOVERY_CODE_BYTES: int = 6   # secrets.token_urlsafe(6) → exactly 8 chars
_RECOVERY_CODE_COUNT: int = 8


def generate_secret() -> str:
    """Generate a fresh random Base32 TOTP secret.

    Returns:
        A 32-character Base32 string compatible with pyotp and authenticator
        apps (Google Authenticator, Authy, 1Password, etc.).
    """
    return pyotp.random_base32()


def get_provisioning_uri(
    secret: str,
    issuer: str = "SecureVault",
    account: str = "vault",
) -> str:
    """Build the otpauth:// URI used to generate the QR code for setup.

    Args:
        secret:  Raw Base32 TOTP secret from generate_secret().
        issuer:  App name shown in the authenticator (default: "SecureVault").
        account: Account label shown under the issuer (default: "vault").

    Returns:
        An otpauth://totp/... URI string suitable for encoding as a QR code.
    """
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=issuer)


def verify_totp(secret: str, token: str, valid_window: int = 1) -> bool:
    """Verify a 6-digit TOTP code against a stored secret.

    Args:
        secret:       Raw Base32 secret (decrypt from DB before calling).
        token:        The 6-digit code entered by the user.
        valid_window: Number of 30-second steps to accept on each side of
                      "now" to account for clock drift (default: 1 = ±30 s).

    Returns:
        True if the token is valid within the allowed window; False otherwise.
    """
    return bool(pyotp.TOTP(secret).verify(token, valid_window=valid_window))


def generate_recovery_codes() -> list[str]:
    """Generate 8 single-use recovery codes.

    Each code is 8 URL-safe characters (6 random bytes, Base64url-encoded).
    Return the plaintext list once to the user — store only hashed versions.

    Returns:
        A list of 8 plaintext recovery code strings.
    """
    return [secrets.token_urlsafe(_RECOVERY_CODE_BYTES) for _ in range(_RECOVERY_CODE_COUNT)]


def hash_recovery_code(code: str) -> str:
    """Hash a plaintext recovery code with Argon2id for safe DB storage.

    Args:
        code: Plaintext recovery code from generate_recovery_codes().

    Returns:
        An Argon2id PHC-format hash string to store in recovery_codes.code_hash.
    """
    return _ph.hash(code)


def verify_recovery_code(code: str, stored_hash: str) -> bool:
    """Verify a user-supplied recovery code against its stored Argon2id hash.

    Args:
        code:        Plaintext code entered by the user.
        stored_hash: The Argon2id PHC string from recovery_codes.code_hash.

    Returns:
        True if the code matches; False otherwise.
    """
    try:
        _ph.verify(stored_hash, code)
        return True
    except VerifyMismatchError:
        return False
