"""
app/security/hashing.py

Argon2 password hashing and verification for the master password.

This module is responsible ONLY for authentication verification — it does NOT
derive encryption keys. The hash stored in users.password_hash is one-way and
is never used for anything except confirming that the correct master password
was entered at login.

Uses argon2-cffi with its default parameters (Argon2id algorithm):
  - time_cost=3 (iterations)
  - memory_cost=65536 (64 MB)
  - parallelism=4
  - hash_len=32
  - salt_len=16

These defaults are appropriate for Phase 1 local use. Phase 2 can tune them
further or switch to explicit Argon2id configuration.
"""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

__all__ = ["hash_password", "verify_password", "needs_rehash"]

# One shared PasswordHasher instance — stateless and safe to reuse.
# Creating it at import time avoids per-call construction overhead.
_hasher = PasswordHasher()


def hash_password(plain_password: str) -> str:
    """Hash a plaintext master password using Argon2id.

    The resulting hash string is self-contained — it encodes the algorithm,
    parameters, salt, and digest in a single PHC-format string. Store this
    directly in users.password_hash.

    Args:
        plain_password: The raw master password entered by the user.

    Returns:
        An Argon2 PHC-format hash string, e.g.
        "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>"

    Raises:
        argon2.exceptions.HashingError: If the hashing operation fails
            (rare hardware/memory errors — should propagate up).
    """
    return _hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored Argon2 hash.

    Returns True if the password matches, False if it does not. This function
    NEVER raises on a wrong password — VerifyMismatchError is caught and
    converted to a False return.

    Any other exception (e.g. VerificationError for a malformed hash string)
    is intentionally allowed to propagate so the caller can handle it as a
    data/programming error rather than a silent auth failure.

    Args:
        plain_password:   The raw password entered at login.
        hashed_password:  The Argon2 PHC string stored in users.password_hash.

    Returns:
        True  — password matches the stored hash.
        False — password does not match (wrong password entered).
    """
    try:
        _hasher.verify(hashed_password, plain_password)
        return True
    except VerifyMismatchError:
        # Expected path for a wrong password — not an error, just a mismatch.
        return False


def needs_rehash(hashed_password: str) -> bool:
    """Return True if the stored hash was produced with outdated Argon2 parameters.

    argon2-cffi's ``check_needs_rehash`` compares the parameters encoded in
    the PHC hash string against the current PasswordHasher defaults. If they
    differ (e.g. after an argon2-cffi upgrade bumps the default time_cost or
    memory_cost), this returns True and the caller should re-hash and persist
    the new hash.

    Call this after a successful login — only re-hash when we can verify the
    original plaintext password is correct, because rehashing requires it.

    Args:
        hashed_password: The PHC-format Argon2 hash stored in users.password_hash.

    Returns:
        True if the hash was computed with different parameters than the
        current defaults and should be upgraded; False otherwise.
    """
    return _hasher.check_needs_rehash(hashed_password)
