"""
app/tests/test_totp.py

Unit tests for app/security/totp.py.

Covers:
  generate_secret       — format (Base32, 32 chars), randomness
  get_provisioning_uri  — otpauth:// URI format, issuer/account, secret param
  verify_totp           — valid accepted, invalid rejected, wrong secret
  generate_recovery_codes — count (8), length (8 chars), uniqueness
  hash_recovery_code    — Argon2id PHC format, salt randomness
  verify_recovery_code  — correct accepted, wrong rejected
"""

import re

import pyotp

from app.security.totp import (
    generate_recovery_codes,
    generate_secret,
    get_provisioning_uri,
    hash_recovery_code,
    verify_recovery_code,
    verify_totp,
)

_BASE32_RE = re.compile(r"^[A-Z2-7]+=*$")


class TestGenerateSecret:
    def test_length_is_32(self):
        assert len(generate_secret()) == 32

    def test_is_valid_base32(self):
        assert _BASE32_RE.match(generate_secret())

    def test_different_calls_produce_different_secrets(self):
        assert generate_secret() != generate_secret()


class TestGetProvisioningUri:
    def test_starts_with_otpauth_totp(self):
        uri = get_provisioning_uri(generate_secret())
        assert uri.startswith("otpauth://totp/")

    def test_contains_default_issuer(self):
        uri = get_provisioning_uri(generate_secret())
        assert "SecureVault" in uri

    def test_custom_issuer_appears_in_uri(self):
        uri = get_provisioning_uri(generate_secret(), issuer="MyApp")
        assert "MyApp" in uri

    def test_secret_param_present_in_uri(self):
        secret = generate_secret()
        uri = get_provisioning_uri(secret)
        assert f"secret={secret}" in uri

    def test_account_label_in_uri(self):
        uri = get_provisioning_uri(generate_secret(), account="testuser")
        assert "testuser" in uri


class TestVerifyTotp:
    def test_current_token_is_accepted(self):
        secret = generate_secret()
        token = pyotp.TOTP(secret).now()
        assert verify_totp(secret, token) is True

    def test_all_zeros_rejected(self):
        assert verify_totp(generate_secret(), "000000") is False

    def test_wrong_length_rejected(self):
        assert verify_totp(generate_secret(), "12345") is False

    def test_token_from_different_secret_rejected(self):
        secret_a = generate_secret()
        secret_b = generate_secret()
        token = pyotp.TOTP(secret_a).now()
        assert verify_totp(secret_b, token) is False

    def test_return_type_is_bool(self):
        secret = generate_secret()
        result = verify_totp(secret, "000000")
        assert isinstance(result, bool)


class TestGenerateRecoveryCodes:
    def test_returns_exactly_eight_codes(self):
        assert len(generate_recovery_codes()) == 8

    def test_each_code_is_eight_characters(self):
        for code in generate_recovery_codes():
            assert len(code) == 8, f"Expected 8 chars, got {len(code)}: {code!r}"

    def test_all_codes_are_unique(self):
        codes = generate_recovery_codes()
        assert len(set(codes)) == 8

    def test_different_calls_produce_different_sets(self):
        assert generate_recovery_codes() != generate_recovery_codes()


class TestHashAndVerifyRecoveryCode:
    def test_correct_code_verifies(self):
        code = "ABCD1234"
        h = hash_recovery_code(code)
        assert verify_recovery_code(code, h) is True

    def test_wrong_code_does_not_verify(self):
        h = hash_recovery_code("ABCD1234")
        assert verify_recovery_code("WRONGCOD", h) is False

    def test_empty_string_does_not_verify_against_real_code(self):
        h = hash_recovery_code("ABCD1234")
        assert verify_recovery_code("", h) is False

    def test_hash_uses_argon2id(self):
        h = hash_recovery_code("TESTCODE")
        assert h.startswith("$argon2id$")

    def test_two_hashes_of_same_code_differ(self):
        code = "SAMECODE"
        assert hash_recovery_code(code) != hash_recovery_code(code)

    def test_return_type_is_bool(self):
        h = hash_recovery_code("ABCD1234")
        result = verify_recovery_code("ABCD1234", h)
        assert isinstance(result, bool)
