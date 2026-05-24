"""
app/tests/test_hashing.py

Unit tests for app/security/hashing.py.

Covers:
  - hash_password: output format, uniqueness (salting), non-reversibility
  - verify_password: correct password, wrong password, empty strings,
    malformed hash propagation
"""

import pytest
from argon2.exceptions import InvalidHashError, VerificationError

from app.security.hashing import hash_password, verify_password


# ---------------------------------------------------------------------------
# hash_password
# ---------------------------------------------------------------------------


class TestHashPassword:
    def test_returns_argon2id_phc_string(self):
        """Output must be an Argon2id PHC-format string."""
        result = hash_password("supersecretpassword")
        assert result.startswith("$argon2id$")

    def test_hash_is_string(self):
        result = hash_password("somepassword")
        assert isinstance(result, str)

    def test_different_calls_produce_different_hashes(self):
        """Each call uses a fresh random salt — identical passwords must not
        produce identical hashes."""
        h1 = hash_password("samepassword")
        h2 = hash_password("samepassword")
        assert h1 != h2

    def test_hash_does_not_contain_plaintext(self):
        """The plaintext password must never appear in the stored hash."""
        plain = "mysecretpassword"
        result = hash_password(plain)
        assert plain not in result

    def test_hash_minimum_length(self):
        """Argon2id PHC strings are well over 50 chars; a short result
        would indicate something went wrong."""
        result = hash_password("password123")
        assert len(result) > 50

    def test_empty_string_password(self):
        """hash_password should hash any string, including an empty one,
        without raising."""
        result = hash_password("")
        assert result.startswith("$argon2id$")

    def test_unicode_password(self):
        """Non-ASCII characters in the master password must be accepted."""
        result = hash_password("pässwörð!🔒")
        assert result.startswith("$argon2id$")

    def test_long_password(self):
        """Very long passwords must not cause errors."""
        result = hash_password("a" * 1000)
        assert result.startswith("$argon2id$")


# ---------------------------------------------------------------------------
# verify_password
# ---------------------------------------------------------------------------


class TestVerifyPassword:
    def test_correct_password_returns_true(self):
        plain = "correctpassword"
        hashed = hash_password(plain)
        assert verify_password(plain, hashed) is True

    def test_wrong_password_returns_false(self):
        hashed = hash_password("correctpassword")
        assert verify_password("wrongpassword", hashed) is False

    def test_empty_password_wrong_returns_false(self):
        hashed = hash_password("nonemptypassword")
        assert verify_password("", hashed) is False

    def test_empty_password_correct_returns_true(self):
        """An empty string is a valid (if bad) password — verify must work."""
        hashed = hash_password("")
        assert verify_password("", hashed) is True

    def test_similar_password_returns_false(self):
        """A password differing by a single character must not verify."""
        hashed = hash_password("Password1!")
        assert verify_password("Password1 ", hashed) is False

    def test_case_sensitive(self):
        hashed = hash_password("SecretPassword")
        assert verify_password("secretpassword", hashed) is False

    def test_unicode_password_roundtrip(self):
        plain = "pässwörð!🔒"
        hashed = hash_password(plain)
        assert verify_password(plain, hashed) is True

    def test_verify_does_not_raise_on_mismatch(self):
        """VerifyMismatchError must be swallowed — wrong password is not an
        exception from the caller's perspective."""
        hashed = hash_password("realpassword")
        try:
            result = verify_password("wrongpassword", hashed)
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"verify_password raised unexpectedly: {exc}")
        assert result is False

    def test_malformed_hash_propagates_error(self):
        """A completely unparseable hash raises InvalidHashError; a structurally
        valid but corrupted hash raises VerificationError. Either way it must
        raise — never silently return False — so callers know the stored value
        is corrupt rather than mistaking it for a wrong password."""
        # "not-a-valid-hash" cannot be parsed at all → InvalidHashError
        with pytest.raises(InvalidHashError):
            verify_password("anypassword", "not-a-valid-hash")

    def test_corrupted_hash_propagates_verification_error(self):
        """A hash with a valid $argon2id$ header but corrupted body raises
        VerificationError, which is distinct from InvalidHashError."""
        with pytest.raises(VerificationError):
            verify_password("anypassword", "$argon2id$v=19$m=65536,t=3,p=4$corrupted$corrupted")

    def test_returns_bool_not_truthy(self):
        """Return type must be exactly bool, not a truthy/falsy value."""
        hashed = hash_password("mypassword")
        assert type(verify_password("mypassword", hashed)) is bool
        assert type(verify_password("wrongpassword", hashed)) is bool
