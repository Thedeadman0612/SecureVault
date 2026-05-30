"""
app/tests/test_encryption.py

Unit tests for app/security/encryption.py.

Covers:
  - generate_kdf_salt: format, randomness, length
  - derive_key: determinism, output length, wrong-length salt raises ValueError
  - derive_key (Argon2id-specific): proves the Phase 2 algorithm upgrade is active
  - encrypt_field: output format, ciphertext differs from plaintext, IV randomness,
    wrong-length key raises ValueError
  - decrypt_field: roundtrip, wrong key raises InvalidToken, tampered token raises
    InvalidToken, wrong-length key raises ValueError
  - InvalidToken re-export: importable from this module (not cryptography internals)
"""

import base64

import pytest

from app.security.encryption import (
    InvalidToken,
    decrypt_field,
    decrypt_field_gcm,
    derive_key,
    encrypt_field,
    encrypt_field_gcm,
    generate_kdf_salt,
    get_cipher,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

# A valid 32-byte raw key — used in encrypt/decrypt tests so they don't
# depend on derive_key() (unit tests stay isolated).
_RAW_KEY: bytes = b"A" * 32

# A valid salt produced by generate_kdf_salt() — used where a real salt is
# needed without calling generate_kdf_salt() again.
_KNOWN_SALT: str = base64.urlsafe_b64encode(b"S" * 32).decode("ascii")


# ---------------------------------------------------------------------------
# generate_kdf_salt
# ---------------------------------------------------------------------------


class TestGenerateKdfSalt:
    def test_returns_string(self):
        assert isinstance(generate_kdf_salt(), str)

    def test_is_valid_base64(self):
        """The result must be decodable URL-safe base64 without padding errors."""
        salt = generate_kdf_salt()
        decoded = base64.urlsafe_b64decode(salt.encode("ascii"))
        assert isinstance(decoded, bytes)

    def test_decodes_to_32_bytes(self):
        """32 raw bytes encode to exactly 44 base64 characters."""
        salt = generate_kdf_salt()
        decoded = base64.urlsafe_b64decode(salt.encode("ascii"))
        assert len(decoded) == 32

    def test_output_length_is_44_chars(self):
        """32 bytes → 44 URL-safe base64 characters (with padding)."""
        salt = generate_kdf_salt()
        assert len(salt) == 44

    def test_each_call_is_unique(self):
        """CSPRNG — two calls must not produce the same salt."""
        salts = {generate_kdf_salt() for _ in range(10)}
        assert len(salts) == 10

    def test_ascii_safe(self):
        """Stored in a VARCHAR column — must contain only ASCII characters."""
        salt = generate_kdf_salt()
        salt.encode("ascii")  # raises if non-ASCII


# ---------------------------------------------------------------------------
# derive_key
# ---------------------------------------------------------------------------


class TestDeriveKey:
    def test_returns_bytes(self):
        assert isinstance(derive_key("password", _KNOWN_SALT), bytes)

    def test_output_is_32_bytes(self):
        key = derive_key("password", _KNOWN_SALT)
        assert len(key) == 32

    def test_deterministic(self):
        """Same password + salt must always produce the same key."""
        k1 = derive_key("mypassword", _KNOWN_SALT)
        k2 = derive_key("mypassword", _KNOWN_SALT)
        assert k1 == k2

    def test_different_passwords_produce_different_keys(self):
        k1 = derive_key("password1", _KNOWN_SALT)
        k2 = derive_key("password2", _KNOWN_SALT)
        assert k1 != k2

    def test_different_salts_produce_different_keys(self):
        salt2 = base64.urlsafe_b64encode(b"T" * 32).decode("ascii")
        k1 = derive_key("samepassword", _KNOWN_SALT)
        k2 = derive_key("samepassword", salt2)
        assert k1 != k2

    def test_unicode_password(self):
        """Non-ASCII master passwords must be handled via UTF-8 encoding."""
        key = derive_key("pässwörð!🔒", _KNOWN_SALT)
        assert len(key) == 32

    def test_empty_password_still_derives(self):
        """derive_key does not validate password strength — that is the
        caller's job. An empty password must not crash."""
        key = derive_key("", _KNOWN_SALT)
        assert len(key) == 32

    def test_wrong_length_salt_raises_value_error(self):
        """A salt that decodes to anything other than 32 bytes indicates
        DB corruption — must raise ValueError, not silently produce a wrong key."""
        short_salt = base64.urlsafe_b64encode(b"X" * 16).decode("ascii")
        with pytest.raises(ValueError, match="32 bytes"):
            derive_key("password", short_salt)

    def test_long_salt_raises_value_error(self):
        long_salt = base64.urlsafe_b64encode(b"X" * 64).decode("ascii")
        with pytest.raises(ValueError, match="32 bytes"):
            derive_key("password", long_salt)

    def test_real_salt_roundtrip(self):
        """End-to-end: generate a real salt, derive a key, check length."""
        salt = generate_kdf_salt()
        key = derive_key("somepassword", salt)
        assert len(key) == 32


# ---------------------------------------------------------------------------
# derive_key — Argon2id algorithm verification (Phase 2)
# ---------------------------------------------------------------------------


class TestDeriveKeyArgon2id:
    """Verify that the Phase 2 Argon2id upgrade is actually in effect.

    These tests are separate from TestDeriveKey so the intent is explicit:
    we are not just checking that derive_key() works — we are checking that
    it uses the correct algorithm and will catch any accidental regression
    back to PBKDF2HMAC.
    """

    def test_output_differs_from_pbkdf2(self):
        """Argon2id MUST produce a different key than PBKDF2HMAC for the
        same (password, salt) pair.

        This is the core regression guard for the Phase 2 upgrade. If this
        test fails, derive_key() has been silently reverted to PBKDF2HMAC.
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        raw_salt = b"S" * 32
        salt_b64 = base64.urlsafe_b64encode(raw_salt).decode("ascii")
        password = "testpassword"

        # What PBKDF2HMAC (Phase 1) would have derived.
        pbkdf2 = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=raw_salt,
            iterations=600_000,
        )
        pbkdf2_key = pbkdf2.derive(password.encode("utf-8"))

        # What Argon2id (Phase 2) derives.
        argon2id_key = derive_key(password, salt_b64)

        assert argon2id_key != pbkdf2_key, (
            "derive_key() returned the same output as PBKDF2HMAC — "
            "the Argon2id upgrade may not be active."
        )

    def test_uses_argon2id_variant(self):
        """Confirm derive_key() uses the ID variant (Argon2id), not Argon2i
        or Argon2d.

        Argon2id combines resistance to side-channel attacks (Argon2i) with
        resistance to GPU/ASIC attacks (Argon2d). The other variants provide
        only one of these properties.
        """
        from argon2.low_level import Type, hash_secret_raw

        raw_salt = b"T" * 32
        salt_b64 = base64.urlsafe_b64encode(raw_salt).decode("ascii")
        kdf_input = "verifyvariant"

        # Expected output using Argon2id (Type.ID) directly.
        expected = hash_secret_raw(
            secret=kdf_input.encode("utf-8"),
            salt=raw_salt,
            time_cost=3,
            memory_cost=65_536,
            parallelism=4,
            hash_len=32,
            type=Type.ID,
        )

        assert derive_key(kdf_input, salt_b64) == expected

    def test_argon2i_variant_produces_different_output(self):
        """Argon2i (Type.I) must not match our output — confirming we are
        using Type.ID and not Type.I."""
        from argon2.low_level import Type, hash_secret_raw

        raw_salt = b"U" * 32
        salt_b64 = base64.urlsafe_b64encode(raw_salt).decode("ascii")
        kdf_input = "variantcheck"

        argon2i_key = hash_secret_raw(
            secret=kdf_input.encode("utf-8"),
            salt=raw_salt,
            time_cost=3,
            memory_cost=65_536,
            parallelism=4,
            hash_len=32,
            type=Type.I,
        )

        assert derive_key(kdf_input, salt_b64) != argon2i_key


# ---------------------------------------------------------------------------
# get_cipher() factory
# ---------------------------------------------------------------------------


class TestGetCipher:
    """Tests for the algorithm factory function.

    get_cipher() is the single routing point that vault_service depends on.
    These tests verify that the right algorithm is selected, the key is
    correctly bound into the closures, and unknown versions fail loudly.
    """

    def test_fernet_version_returns_callables(self):
        encrypt, decrypt = get_cipher("fernet", _RAW_KEY)
        assert callable(encrypt)
        assert callable(decrypt)

    def test_aesgcm_version_returns_callables(self):
        encrypt, decrypt = get_cipher("aesgcm", _RAW_KEY)
        assert callable(encrypt)
        assert callable(decrypt)

    def test_fernet_roundtrip_via_factory(self):
        """Factory pair for 'fernet' must produce a working round-trip."""
        encrypt, decrypt = get_cipher("fernet", _RAW_KEY)
        plaintext = "fernet_vault_secret"
        assert decrypt(encrypt(plaintext)) == plaintext

    def test_aesgcm_roundtrip_via_factory(self):
        """Factory pair for 'aesgcm' must produce a working round-trip."""
        encrypt, decrypt = get_cipher("aesgcm", _RAW_KEY)
        plaintext = "aesgcm_vault_secret"
        assert decrypt(encrypt(plaintext)) == plaintext

    def test_fernet_token_format(self):
        """'fernet' encrypt_fn must produce a Fernet token (starts with gAAAAA)."""
        encrypt, _ = get_cipher("fernet", _RAW_KEY)
        assert encrypt("hello").startswith("gAAAAA")

    def test_aesgcm_token_differs_from_fernet_format(self):
        """'aesgcm' encrypt_fn must NOT produce a Fernet token."""
        encrypt, _ = get_cipher("aesgcm", _RAW_KEY)
        assert not encrypt("hello").startswith("gAAAAA")

    def test_key_is_bound_fernet(self):
        """encrypt_fn must not require the key as an argument — it is
        pre-bound in the closure."""
        encrypt, decrypt = get_cipher("fernet", _RAW_KEY)
        # If key were NOT bound, calling encrypt("hello") would TypeError.
        token = encrypt("hello")
        assert decrypt(token) == "hello"

    def test_key_is_bound_aesgcm(self):
        encrypt, decrypt = get_cipher("aesgcm", _RAW_KEY)
        token = encrypt("hello")
        assert decrypt(token) == "hello"

    def test_wrong_key_raises_invalid_token_fernet(self):
        """Encrypting with key_a and decrypting with key_b must raise
        InvalidToken — key binding is per-cipher-pair, not global."""
        key_b = b"B" * 32
        encrypt, _ = get_cipher("fernet", _RAW_KEY)
        _, decrypt = get_cipher("fernet", key_b)
        with pytest.raises(InvalidToken):
            decrypt(encrypt("secret"))

    def test_wrong_key_raises_invalid_token_aesgcm(self):
        key_b = b"B" * 32
        encrypt, _ = get_cipher("aesgcm", _RAW_KEY)
        _, decrypt = get_cipher("aesgcm", key_b)
        with pytest.raises(InvalidToken):
            decrypt(encrypt("secret"))

    def test_cross_algorithm_fernet_token_into_aesgcm_decrypt(self):
        """A token produced by the 'fernet' pair must be rejected by the
        'aesgcm' decrypt_fn — get_cipher() isolation guard."""
        _, decrypt_aesgcm = get_cipher("aesgcm", _RAW_KEY)
        encrypt_fernet, _ = get_cipher("fernet", _RAW_KEY)
        with pytest.raises((InvalidToken, ValueError)):
            decrypt_aesgcm(encrypt_fernet("secret"))

    def test_cross_algorithm_aesgcm_token_into_fernet_decrypt(self):
        """A token produced by the 'aesgcm' pair must be rejected by the
        'fernet' decrypt_fn."""
        _, decrypt_fernet = get_cipher("fernet", _RAW_KEY)
        encrypt_aesgcm, _ = get_cipher("aesgcm", _RAW_KEY)
        with pytest.raises((InvalidToken, ValueError)):
            decrypt_fernet(encrypt_aesgcm("secret"))

    def test_unknown_version_raises_value_error(self):
        """An unrecognised version string must raise ValueError immediately —
        never silently fall back to a default algorithm."""
        with pytest.raises(ValueError, match="Unknown encryption_version"):
            get_cipher("unknown_v3", _RAW_KEY)

    def test_empty_string_version_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown encryption_version"):
            get_cipher("", _RAW_KEY)

    def test_case_sensitive_version(self):
        """'Fernet' (capital F) is not a valid version — must raise ValueError,
        not silently match 'fernet'."""
        with pytest.raises(ValueError):
            get_cipher("Fernet", _RAW_KEY)


# ---------------------------------------------------------------------------
# AES-256-GCM encrypt
# ---------------------------------------------------------------------------


class TestEncryptFieldGcm:
    def test_returns_string(self):
        assert isinstance(encrypt_field_gcm("hello", _RAW_KEY), str)

    def test_is_valid_base64(self):
        token = encrypt_field_gcm("hello", _RAW_KEY)
        decoded = base64.urlsafe_b64decode(token.encode("ascii"))
        assert isinstance(decoded, bytes)

    def test_minimum_length(self):
        """Even an empty string produces at least nonce(12) + tag(16) = 28 bytes."""
        token = encrypt_field_gcm("", _RAW_KEY)
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        assert len(raw) >= 28  # 12-byte nonce + 16-byte tag + 0 ciphertext

    def test_ciphertext_does_not_contain_plaintext(self):
        token = encrypt_field_gcm("supersecretvalue", _RAW_KEY)
        assert "supersecretvalue" not in token

    def test_same_plaintext_produces_different_tokens(self):
        """Random nonce — same plaintext encrypted twice must produce
        different tokens."""
        t1 = encrypt_field_gcm("hello", _RAW_KEY)
        t2 = encrypt_field_gcm("hello", _RAW_KEY)
        assert t1 != t2

    def test_nonce_differs_between_calls(self):
        """The first 12 bytes of each token (the nonce) must be unique."""
        raw1 = base64.urlsafe_b64decode(encrypt_field_gcm("hello", _RAW_KEY))
        raw2 = base64.urlsafe_b64decode(encrypt_field_gcm("hello", _RAW_KEY))
        assert raw1[:12] != raw2[:12]

    def test_empty_string_encrypts(self):
        token = encrypt_field_gcm("", _RAW_KEY)
        assert isinstance(token, str)
        assert len(token) > 0

    def test_unicode_plaintext(self):
        token = encrypt_field_gcm("pässwörð!🔒", _RAW_KEY)
        assert isinstance(token, str)

    def test_long_plaintext(self):
        token = encrypt_field_gcm("a" * 10_000, _RAW_KEY)
        assert isinstance(token, str)

    def test_wrong_key_length_raises_value_error(self):
        with pytest.raises(ValueError, match="32 bytes"):
            encrypt_field_gcm("hello", b"tooshort")

    def test_key_31_bytes_raises_value_error(self):
        with pytest.raises(ValueError, match="32 bytes"):
            encrypt_field_gcm("hello", b"A" * 31)

    def test_key_33_bytes_raises_value_error(self):
        with pytest.raises(ValueError, match="32 bytes"):
            encrypt_field_gcm("hello", b"A" * 33)


# ---------------------------------------------------------------------------
# AES-256-GCM decrypt
# ---------------------------------------------------------------------------


class TestDecryptFieldGcm:
    def test_roundtrip_basic(self):
        plaintext = "my_secret_password"
        token = encrypt_field_gcm(plaintext, _RAW_KEY)
        assert decrypt_field_gcm(token, _RAW_KEY) == plaintext

    def test_roundtrip_empty_string(self):
        token = encrypt_field_gcm("", _RAW_KEY)
        assert decrypt_field_gcm(token, _RAW_KEY) == ""

    def test_roundtrip_unicode(self):
        plaintext = "pässwörð!🔒"
        token = encrypt_field_gcm(plaintext, _RAW_KEY)
        assert decrypt_field_gcm(token, _RAW_KEY) == plaintext

    def test_roundtrip_long_value(self):
        plaintext = "x" * 10_000
        token = encrypt_field_gcm(plaintext, _RAW_KEY)
        assert decrypt_field_gcm(token, _RAW_KEY) == plaintext

    def test_returns_string(self):
        token = encrypt_field_gcm("hello", _RAW_KEY)
        result = decrypt_field_gcm(token, _RAW_KEY)
        assert isinstance(result, str)

    def test_wrong_key_raises_invalid_token(self):
        """Wrong key means the auth tag will not verify — must raise
        InvalidToken (converted from AESGCM's InvalidTag internally)."""
        token = encrypt_field_gcm("secret", _RAW_KEY)
        wrong_key = b"B" * 32
        with pytest.raises(InvalidToken):
            decrypt_field_gcm(token, wrong_key)

    def test_tampered_ciphertext_raises_invalid_token(self):
        """Flipping a byte in the ciphertext body must fail the auth tag
        check — GCM detects any modification."""
        token = encrypt_field_gcm("secret", _RAW_KEY)
        raw = bytearray(base64.urlsafe_b64decode(token))
        # Flip a byte in the ciphertext region (after the 12-byte nonce,
        # before the last 16 bytes which are the tag).
        raw[12] ^= 0xFF
        tampered = base64.urlsafe_b64encode(bytes(raw)).decode("ascii")
        with pytest.raises(InvalidToken):
            decrypt_field_gcm(tampered, _RAW_KEY)

    def test_tampered_tag_raises_invalid_token(self):
        """Flipping a byte in the authentication tag must also be detected."""
        token = encrypt_field_gcm("secret", _RAW_KEY)
        raw = bytearray(base64.urlsafe_b64decode(token))
        # Flip the last byte (end of the 16-byte tag).
        raw[-1] ^= 0xFF
        tampered = base64.urlsafe_b64encode(bytes(raw)).decode("ascii")
        with pytest.raises(InvalidToken):
            decrypt_field_gcm(tampered, _RAW_KEY)

    def test_tampered_nonce_raises_invalid_token(self):
        """Changing the nonce means decrypt uses a different IV, producing
        a different keystream, so the tag will not verify."""
        token = encrypt_field_gcm("secret", _RAW_KEY)
        raw = bytearray(base64.urlsafe_b64decode(token))
        # Flip the first byte of the nonce.
        raw[0] ^= 0xFF
        tampered = base64.urlsafe_b64encode(bytes(raw)).decode("ascii")
        with pytest.raises(InvalidToken):
            decrypt_field_gcm(tampered, _RAW_KEY)

    def test_wrong_key_length_raises_value_error(self):
        token = encrypt_field_gcm("hello", _RAW_KEY)
        with pytest.raises(ValueError, match="32 bytes"):
            decrypt_field_gcm(token, b"tooshort")

    def test_token_too_short_raises_value_error(self):
        """A base64 string that decodes to fewer than 12 bytes cannot hold
        a valid nonce — must raise ValueError, not crash inside AESGCM."""
        too_short = base64.urlsafe_b64encode(b"short").decode("ascii")
        with pytest.raises(ValueError, match="too short"):
            decrypt_field_gcm(too_short, _RAW_KEY)

    def test_fernet_token_not_decryptable_as_gcm(self):
        """A Fernet token passed to decrypt_field_gcm() must fail — the two
        algorithms must not accidentally accept each other's tokens.
        This is a cross-algorithm isolation guard for get_cipher() (Task 3)."""
        fernet_token = encrypt_field("secret", _RAW_KEY)
        with pytest.raises((InvalidToken, ValueError)):
            decrypt_field_gcm(fernet_token, _RAW_KEY)

    def test_gcm_token_not_decryptable_as_fernet(self):
        """A GCM token passed to decrypt_field() must also fail."""
        gcm_token = encrypt_field_gcm("secret", _RAW_KEY)
        with pytest.raises((InvalidToken, ValueError)):
            decrypt_field(gcm_token, _RAW_KEY)

    def test_roundtrip_with_derived_key(self):
        """Full integration: derive key → GCM encrypt → GCM decrypt."""
        salt = generate_kdf_salt()
        key = derive_key("masterpassword123", salt)
        plaintext = "vault_entry_password"
        token = encrypt_field_gcm(plaintext, key)
        assert decrypt_field_gcm(token, key) == plaintext

    def test_key_derived_from_different_password_raises_invalid_token(self):
        salt = generate_kdf_salt()
        key_a = derive_key("correct_master", salt)
        key_b = derive_key("wrong_master", salt)
        token = encrypt_field_gcm("secret", key_a)
        with pytest.raises(InvalidToken):
            decrypt_field_gcm(token, key_b)


# ---------------------------------------------------------------------------
# encrypt_field
# ---------------------------------------------------------------------------


class TestEncryptField:
    def test_returns_string(self):
        assert isinstance(encrypt_field("hello", _RAW_KEY), str)

    def test_token_starts_with_fernet_prefix(self):
        """Fernet tokens always start with 'gAAAAA' when base64-decoded."""
        token = encrypt_field("hello", _RAW_KEY)
        assert token.startswith("gAAAAA")

    def test_ciphertext_does_not_contain_plaintext(self):
        token = encrypt_field("supersecretvalue", _RAW_KEY)
        assert "supersecretvalue" not in token

    def test_same_plaintext_produces_different_tokens(self):
        """Fernet uses a random IV — encrypting the same value twice must
        produce different tokens."""
        t1 = encrypt_field("hello", _RAW_KEY)
        t2 = encrypt_field("hello", _RAW_KEY)
        assert t1 != t2

    def test_empty_string_encrypts(self):
        """Optional vault fields (e.g. notes) can be empty strings."""
        token = encrypt_field("", _RAW_KEY)
        assert isinstance(token, str)
        assert len(token) > 0

    def test_unicode_plaintext(self):
        token = encrypt_field("pässwörð!🔒", _RAW_KEY)
        assert isinstance(token, str)

    def test_long_plaintext(self):
        token = encrypt_field("a" * 10_000, _RAW_KEY)
        assert isinstance(token, str)

    def test_wrong_key_length_raises_value_error(self):
        with pytest.raises(ValueError, match="32 bytes"):
            encrypt_field("hello", b"tooshort")

    def test_key_31_bytes_raises_value_error(self):
        with pytest.raises(ValueError, match="32 bytes"):
            encrypt_field("hello", b"A" * 31)

    def test_key_33_bytes_raises_value_error(self):
        with pytest.raises(ValueError, match="32 bytes"):
            encrypt_field("hello", b"A" * 33)


# ---------------------------------------------------------------------------
# decrypt_field
# ---------------------------------------------------------------------------


class TestDecryptField:
    def test_roundtrip_basic(self):
        plaintext = "my_secret_password"
        token = encrypt_field(plaintext, _RAW_KEY)
        assert decrypt_field(token, _RAW_KEY) == plaintext

    def test_roundtrip_empty_string(self):
        token = encrypt_field("", _RAW_KEY)
        assert decrypt_field(token, _RAW_KEY) == ""

    def test_roundtrip_unicode(self):
        plaintext = "pässwörð!🔒"
        token = encrypt_field(plaintext, _RAW_KEY)
        assert decrypt_field(token, _RAW_KEY) == plaintext

    def test_roundtrip_long_value(self):
        plaintext = "x" * 10_000
        token = encrypt_field(plaintext, _RAW_KEY)
        assert decrypt_field(token, _RAW_KEY) == plaintext

    def test_returns_string(self):
        token = encrypt_field("hello", _RAW_KEY)
        result = decrypt_field(token, _RAW_KEY)
        assert isinstance(result, str)

    def test_wrong_key_raises_invalid_token(self):
        """Decrypting with a different key must fail authentication — the
        HMAC will not verify."""
        token = encrypt_field("secret", _RAW_KEY)
        wrong_key = b"B" * 32
        with pytest.raises(InvalidToken):
            decrypt_field(token, wrong_key)

    def test_tampered_token_raises_invalid_token(self):
        """Any byte modification to the token must be detected by the MAC."""
        token = encrypt_field("secret", _RAW_KEY)
        # Flip the last character of the base64 string
        tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
        with pytest.raises(InvalidToken):
            decrypt_field(tampered, _RAW_KEY)

    def test_garbage_token_raises_invalid_token(self):
        with pytest.raises(InvalidToken):
            decrypt_field("notavalidtoken", _RAW_KEY)

    def test_wrong_key_length_raises_value_error(self):
        token = encrypt_field("hello", _RAW_KEY)
        with pytest.raises(ValueError, match="32 bytes"):
            decrypt_field(token, b"tooshort")

    def test_encrypt_with_derived_key_decrypts_correctly(self):
        """Full integration of derive_key → encrypt_field → decrypt_field."""
        salt = generate_kdf_salt()
        key = derive_key("masterpassword123", salt)
        plaintext = "vault_entry_password"
        token = encrypt_field(plaintext, key)
        assert decrypt_field(token, key) == plaintext

    def test_key_derived_from_different_password_raises_invalid_token(self):
        """Keys derived from different passwords must not decrypt each other's
        ciphertext."""
        salt = generate_kdf_salt()
        key_a = derive_key("correct_master", salt)
        key_b = derive_key("wrong_master", salt)
        token = encrypt_field("secret", key_a)
        with pytest.raises(InvalidToken):
            decrypt_field(token, key_b)


# ---------------------------------------------------------------------------
# InvalidToken re-export
# ---------------------------------------------------------------------------


class TestInvalidTokenReExport:
    def test_invalid_token_importable_from_this_module(self):
        """Callers import InvalidToken from app.security.encryption — not from
        cryptography.fernet directly. Verify the re-export is in place."""
        from app.security.encryption import InvalidToken as IT  # noqa: PLC0415
        assert IT is not None

    def test_invalid_token_is_same_object_as_cryptography_fernet(self):
        """The re-exported symbol must be the exact same class so that
        'except InvalidToken' catches exceptions raised by cryptography."""
        from cryptography.fernet import InvalidToken as CryptoIT  # noqa: PLC0415
        assert InvalidToken is CryptoIT
