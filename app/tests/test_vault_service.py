"""
app/tests/test_vault_service.py

Integration tests for app/services/vault_service.py.

Uses an in-memory SQLite database (separate from securevault.db) so every
test runs against a clean, isolated schema with no shared state.

Covers:
  - create_entry : encryption on write, plaintext fields stored as-is,
                   decrypted response matches input, notes optional
  - get_entries  : empty list, multiple entries, user isolation
  - get_entry    : happy path, 404 on missing id, 404 on wrong user_id
  - update_entry : partial update (plaintext + sensitive), no-op fields
                   unchanged, 404 on wrong owner
  - delete_entry : entry removed, 404 on second delete, user isolation
  - _decrypt_entry (via service calls): InvalidToken → HTTP 500
"""

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.models.user import User  # noqa: F401 — registers users table with Base.metadata
from app.models.vault_entry import VaultEntry  # noqa: F401 — registers ORM model
from app.schemas.vault import VaultEntryCreate, VaultEntryUpdate
from app.security.encryption import (
    decrypt_field_gcm,
    encrypt_field,
)
from app.services import vault_service


# ---------------------------------------------------------------------------
# In-memory database fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def db():
    """Provide a fresh in-memory SQLite session for each test.

    Creates all tables before the test and drops them after, so every test
    starts with a completely empty database. Using scope="function" ensures
    there is no shared state between tests.
    """
    # StaticPool forces all sessions to reuse the same underlying connection.
    # Without it, each new session opens a fresh connection — and SQLite
    # in-memory databases are per-connection, so the tables created by
    # create_all() would be invisible to every subsequent session.
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)


# ---------------------------------------------------------------------------
# Shared test data helpers
# ---------------------------------------------------------------------------

# Two distinct 32-byte raw keys — used to simulate two different users.
_KEY_USER_1: bytes = b"K" * 32
_KEY_USER_2: bytes = b"Z" * 32

_USER_1_ID = 1
_USER_2_ID = 2


def _make_create_data(
    title: str = "GitHub",
    password: str = "s3cr3t!",
    username: str = "alice",
    website: str | None = "https://github.com",
    category: str | None = "Dev",
    notes: str | None = None,
) -> VaultEntryCreate:
    return VaultEntryCreate(
        title=title,
        password=password,
        username=username,
        website=website,
        category=category,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# create_entry
# ---------------------------------------------------------------------------

class TestCreateEntry:
    def test_returns_vault_entry_response(self, db):
        data = _make_create_data()
        result = vault_service.create_entry(data, _USER_1_ID, _KEY_USER_1, db)
        assert result.id is not None
        assert isinstance(result.id, int)

    def test_decrypted_sensitive_fields_match_input(self, db):
        data = _make_create_data(username="alice", password="s3cr3t!", notes="my note")
        result = vault_service.create_entry(data, _USER_1_ID, _KEY_USER_1, db)
        assert result.username == "alice"
        assert result.password == "s3cr3t!"
        assert result.notes == "my note"

    def test_plaintext_fields_stored_correctly(self, db):
        data = _make_create_data(
            title="GitHub", website="https://github.com", category="Dev"
        )
        result = vault_service.create_entry(data, _USER_1_ID, _KEY_USER_1, db)
        assert result.title == "GitHub"
        assert result.website == "https://github.com"
        assert result.category == "Dev"

    def test_sensitive_fields_are_encrypted_in_db(self, db):
        """The raw DB row must never contain plaintext for encrypted fields."""
        data = _make_create_data(username="alice", password="s3cr3t!")
        result = vault_service.create_entry(data, _USER_1_ID, _KEY_USER_1, db)

        row = db.query(VaultEntry).filter(VaultEntry.id == result.id).first()
        assert row.username_encrypted != "alice"
        assert row.password_encrypted != "s3cr3t!"
        # Phase 2 writes AES-256-GCM tokens. Verify by round-tripping through
        # the GCM decrypt — InvalidToken would be raised on any tampering.
        assert row.encryption_version == "aesgcm"
        assert decrypt_field_gcm(row.username_encrypted, _KEY_USER_1) == "alice"
        assert decrypt_field_gcm(row.password_encrypted, _KEY_USER_1) == "s3cr3t!"

    def test_notes_none_stored_as_null(self, db):
        data = _make_create_data(notes=None)
        result = vault_service.create_entry(data, _USER_1_ID, _KEY_USER_1, db)

        row = db.query(VaultEntry).filter(VaultEntry.id == result.id).first()
        assert row.notes_encrypted is None
        assert result.notes is None

    def test_notes_provided_encrypted_and_decrypted(self, db):
        data = _make_create_data(notes="backup codes: 123456")
        result = vault_service.create_entry(data, _USER_1_ID, _KEY_USER_1, db)
        assert result.notes == "backup codes: 123456"

    def test_timestamps_populated(self, db):
        data = _make_create_data()
        result = vault_service.create_entry(data, _USER_1_ID, _KEY_USER_1, db)
        assert result.created_at is not None
        assert result.updated_at is not None

    def test_user_id_stored_on_row(self, db):
        data = _make_create_data()
        result = vault_service.create_entry(data, _USER_1_ID, _KEY_USER_1, db)
        row = db.query(VaultEntry).filter(VaultEntry.id == result.id).first()
        assert row.user_id == _USER_1_ID

    def test_empty_username_defaults_to_empty_string(self, db):
        """username defaults to "" in the schema — must roundtrip correctly."""
        data = VaultEntryCreate(title="AWS", password="hunter2")
        result = vault_service.create_entry(data, _USER_1_ID, _KEY_USER_1, db)
        assert result.username == ""


# ---------------------------------------------------------------------------
# get_entries
# ---------------------------------------------------------------------------

class TestGetEntries:
    def test_returns_empty_list_for_new_user(self, db):
        result = vault_service.get_entries(_USER_1_ID, _KEY_USER_1, db)
        assert result == []

    def test_returns_all_entries_for_user(self, db):
        vault_service.create_entry(_make_create_data(title="A"), _USER_1_ID, _KEY_USER_1, db)
        vault_service.create_entry(_make_create_data(title="B"), _USER_1_ID, _KEY_USER_1, db)
        vault_service.create_entry(_make_create_data(title="C"), _USER_1_ID, _KEY_USER_1, db)
        result = vault_service.get_entries(_USER_1_ID, _KEY_USER_1, db)
        assert len(result) == 3

    def test_decrypted_values_in_list(self, db):
        vault_service.create_entry(
            _make_create_data(title="GitHub", username="alice", password="s3cr3t!"),
            _USER_1_ID, _KEY_USER_1, db,
        )
        results = vault_service.get_entries(_USER_1_ID, _KEY_USER_1, db)
        assert results[0].username == "alice"
        assert results[0].password == "s3cr3t!"

    def test_user_isolation_get_entries(self, db):
        """User 1's entries must not appear in User 2's list."""
        vault_service.create_entry(_make_create_data(title="User1Entry"), _USER_1_ID, _KEY_USER_1, db)
        vault_service.create_entry(_make_create_data(title="User2Entry"), _USER_2_ID, _KEY_USER_2, db)

        user1_results = vault_service.get_entries(_USER_1_ID, _KEY_USER_1, db)
        user2_results = vault_service.get_entries(_USER_2_ID, _KEY_USER_2, db)

        assert len(user1_results) == 1
        assert user1_results[0].title == "User1Entry"
        assert len(user2_results) == 1
        assert user2_results[0].title == "User2Entry"


# ---------------------------------------------------------------------------
# get_entry
# ---------------------------------------------------------------------------

class TestGetEntry:
    def test_returns_correct_entry(self, db):
        created = vault_service.create_entry(
            _make_create_data(title="GitHub", password="mypass"),
            _USER_1_ID, _KEY_USER_1, db,
        )
        result = vault_service.get_entry(created.id, _USER_1_ID, _KEY_USER_1, db)
        assert result.id == created.id
        assert result.title == "GitHub"
        assert result.password == "mypass"

    def test_raises_404_for_nonexistent_id(self, db):
        with pytest.raises(HTTPException) as exc_info:
            vault_service.get_entry(9999, _USER_1_ID, _KEY_USER_1, db)
        assert exc_info.value.status_code == 404

    def test_raises_404_for_wrong_user(self, db):
        """User 2 must not be able to fetch User 1's entry even with the correct id."""
        created = vault_service.create_entry(
            _make_create_data(), _USER_1_ID, _KEY_USER_1, db
        )
        with pytest.raises(HTTPException) as exc_info:
            vault_service.get_entry(created.id, _USER_2_ID, _KEY_USER_2, db)
        assert exc_info.value.status_code == 404

    def test_404_detail_message_is_generic(self, db):
        """The 404 detail must not reveal whether the entry exists at all."""
        with pytest.raises(HTTPException) as exc_info:
            vault_service.get_entry(9999, _USER_1_ID, _KEY_USER_1, db)
        assert exc_info.value.detail == "Entry not found."


# ---------------------------------------------------------------------------
# update_entry
# ---------------------------------------------------------------------------

class TestUpdateEntry:
    def test_update_plaintext_fields(self, db):
        created = vault_service.create_entry(
            _make_create_data(title="Old Title", website="https://old.com"),
            _USER_1_ID, _KEY_USER_1, db,
        )
        update = VaultEntryUpdate(title="New Title", website="https://new.com")
        result = vault_service.update_entry(created.id, update, _USER_1_ID, _KEY_USER_1, db)
        assert result.title == "New Title"
        assert result.website == "https://new.com"

    def test_update_sensitive_fields(self, db):
        created = vault_service.create_entry(
            _make_create_data(username="olduser", password="oldpass"),
            _USER_1_ID, _KEY_USER_1, db,
        )
        update = VaultEntryUpdate(username="newuser", password="newpass")
        result = vault_service.update_entry(created.id, update, _USER_1_ID, _KEY_USER_1, db)
        assert result.username == "newuser"
        assert result.password == "newpass"

    def test_partial_update_leaves_other_fields_unchanged(self, db):
        """Supplying only title must not change password or other fields."""
        created = vault_service.create_entry(
            _make_create_data(title="GitHub", password="s3cr3t!", category="Dev"),
            _USER_1_ID, _KEY_USER_1, db,
        )
        update = VaultEntryUpdate(title="GitLab")
        result = vault_service.update_entry(created.id, update, _USER_1_ID, _KEY_USER_1, db)
        assert result.title == "GitLab"
        assert result.password == "s3cr3t!"
        assert result.category == "Dev"

    def test_update_notes_field(self, db):
        created = vault_service.create_entry(
            _make_create_data(notes=None), _USER_1_ID, _KEY_USER_1, db
        )
        update = VaultEntryUpdate(notes="added later")
        result = vault_service.update_entry(created.id, update, _USER_1_ID, _KEY_USER_1, db)
        assert result.notes == "added later"

    def test_updated_sensitive_field_re_encrypted_in_db(self, db):
        """After update, the DB column must store an AES-GCM token, not plaintext."""
        created = vault_service.create_entry(
            _make_create_data(password="oldpass"), _USER_1_ID, _KEY_USER_1, db
        )
        vault_service.update_entry(
            created.id, VaultEntryUpdate(password="newpass"), _USER_1_ID, _KEY_USER_1, db
        )
        row = db.query(VaultEntry).filter(VaultEntry.id == created.id).first()
        assert row.password_encrypted != "newpass"
        # Phase 2 always writes AES-256-GCM tokens on update.
        assert row.encryption_version == "aesgcm"
        assert decrypt_field_gcm(row.password_encrypted, _KEY_USER_1) == "newpass"

    def test_raises_404_for_nonexistent_entry(self, db):
        with pytest.raises(HTTPException) as exc_info:
            vault_service.update_entry(
                9999, VaultEntryUpdate(title="X"), _USER_1_ID, _KEY_USER_1, db
            )
        assert exc_info.value.status_code == 404

    def test_raises_404_for_wrong_user(self, db):
        """User 2 must not be able to update User 1's entry."""
        created = vault_service.create_entry(
            _make_create_data(), _USER_1_ID, _KEY_USER_1, db
        )
        with pytest.raises(HTTPException) as exc_info:
            vault_service.update_entry(
                created.id, VaultEntryUpdate(title="Hijacked"), _USER_2_ID, _KEY_USER_2, db
            )
        assert exc_info.value.status_code == 404

    def test_no_op_update_returns_unchanged_entry(self, db):
        """An empty VaultEntryUpdate (all None) must not alter any field."""
        created = vault_service.create_entry(
            _make_create_data(title="GitHub", password="original"),
            _USER_1_ID, _KEY_USER_1, db,
        )
        result = vault_service.update_entry(
            created.id, VaultEntryUpdate(), _USER_1_ID, _KEY_USER_1, db
        )
        assert result.title == "GitHub"
        assert result.password == "original"


# ---------------------------------------------------------------------------
# delete_entry
# ---------------------------------------------------------------------------

class TestDeleteEntry:
    def test_delete_removes_entry(self, db):
        created = vault_service.create_entry(
            _make_create_data(), _USER_1_ID, _KEY_USER_1, db
        )
        vault_service.delete_entry(created.id, _USER_1_ID, db)

        with pytest.raises(HTTPException) as exc_info:
            vault_service.get_entry(created.id, _USER_1_ID, _KEY_USER_1, db)
        assert exc_info.value.status_code == 404

    def test_delete_returns_none(self, db):
        created = vault_service.create_entry(
            _make_create_data(), _USER_1_ID, _KEY_USER_1, db
        )
        result = vault_service.delete_entry(created.id, _USER_1_ID, db)
        assert result is None

    def test_delete_raises_404_on_second_delete(self, db):
        created = vault_service.create_entry(
            _make_create_data(), _USER_1_ID, _KEY_USER_1, db
        )
        vault_service.delete_entry(created.id, _USER_1_ID, db)
        with pytest.raises(HTTPException) as exc_info:
            vault_service.delete_entry(created.id, _USER_1_ID, db)
        assert exc_info.value.status_code == 404

    def test_delete_raises_404_for_nonexistent_id(self, db):
        with pytest.raises(HTTPException) as exc_info:
            vault_service.delete_entry(9999, _USER_1_ID, db)
        assert exc_info.value.status_code == 404

    def test_delete_user_isolation(self, db):
        """User 2 must not be able to delete User 1's entry."""
        created = vault_service.create_entry(
            _make_create_data(), _USER_1_ID, _KEY_USER_1, db
        )
        with pytest.raises(HTTPException) as exc_info:
            vault_service.delete_entry(created.id, _USER_2_ID, db)
        assert exc_info.value.status_code == 404

        # Entry must still exist for User 1 after the failed delete attempt.
        still_there = vault_service.get_entry(created.id, _USER_1_ID, _KEY_USER_1, db)
        assert still_there.id == created.id

    def test_delete_only_removes_target_entry(self, db):
        """Deleting one entry must leave the other entries untouched."""
        e1 = vault_service.create_entry(_make_create_data(title="Keep"), _USER_1_ID, _KEY_USER_1, db)
        e2 = vault_service.create_entry(_make_create_data(title="Delete"), _USER_1_ID, _KEY_USER_1, db)

        vault_service.delete_entry(e2.id, _USER_1_ID, db)

        remaining = vault_service.get_entries(_USER_1_ID, _KEY_USER_1, db)
        assert len(remaining) == 1
        assert remaining[0].id == e1.id


# ---------------------------------------------------------------------------
# Decryption failure → HTTP 500
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Encryption versioning and lazy re-encryption (Phase 2)
# ---------------------------------------------------------------------------

class TestEncryptionVersioning:
    """Tests for the Phase 2 encryption_version column and lazy re-encryption.

    Lazy re-encryption pattern:
      _decrypt_entry(entry, key, db) — if the row carries encryption_version
      == "fernet", it decrypts with Fernet, re-encrypts with AES-256-GCM,
      saves the row, and stamps encryption_version = "aesgcm". The caller
      (get_entry / get_entries / update_entry) always passes db=db to enable
      this upgrade path.
    """

    # --- New entries (create_entry) -----------------------------------------

    def test_create_entry_stores_aesgcm_version(self, db):
        """New entries must be stamped with encryption_version='aesgcm'."""
        result = vault_service.create_entry(_make_create_data(), _USER_1_ID, _KEY_USER_1, db)
        row = db.query(VaultEntry).filter(VaultEntry.id == result.id).first()
        assert row.encryption_version == "aesgcm"

    def test_create_entry_token_is_not_fernet_format(self, db):
        """AES-GCM tokens must not start with the Fernet 'gAAAAA' prefix."""
        result = vault_service.create_entry(
            _make_create_data(username="alice"), _USER_1_ID, _KEY_USER_1, db
        )
        row = db.query(VaultEntry).filter(VaultEntry.id == result.id).first()
        assert not row.username_encrypted.startswith("gAAAAA")

    # --- Lazy re-encryption via get_entry -----------------------------------

    def test_get_entry_upgrades_fernet_row_to_aesgcm(self, db):
        """get_entry() must transparently upgrade a legacy 'fernet' row to 'aesgcm'."""
        # Simulate a pre-Phase-2 row by inserting with Fernet-encrypted fields.
        row = VaultEntry(
            user_id=_USER_1_ID,
            title="Legacy Entry",
            encryption_version="fernet",
            username_encrypted=encrypt_field("alice", _KEY_USER_1),
            password_encrypted=encrypt_field("s3cr3t!", _KEY_USER_1),
            notes_encrypted=None,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        entry_id = row.id

        # get_entry() should decrypt correctly and trigger the upgrade.
        result = vault_service.get_entry(entry_id, _USER_1_ID, _KEY_USER_1, db)
        assert result.username == "alice"
        assert result.password == "s3cr3t!"

        # The DB row must now carry the upgraded version and valid GCM ciphertext.
        db.refresh(row)
        assert row.encryption_version == "aesgcm"
        # Verify by decrypting the stored ciphertext with the GCM function directly.
        assert decrypt_field_gcm(row.username_encrypted, _KEY_USER_1) == "alice"
        assert decrypt_field_gcm(row.password_encrypted, _KEY_USER_1) == "s3cr3t!"

    def test_get_entries_upgrades_fernet_row_to_aesgcm(self, db):
        """get_entries() must upgrade all legacy 'fernet' rows it reads."""
        row = VaultEntry(
            user_id=_USER_1_ID,
            title="Old Entry",
            encryption_version="fernet",
            username_encrypted=encrypt_field("bob", _KEY_USER_1),
            password_encrypted=encrypt_field("hunter2", _KEY_USER_1),
            notes_encrypted=None,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        entry_id = row.id

        results = vault_service.get_entries(_USER_1_ID, _KEY_USER_1, db)
        assert len(results) == 1
        assert results[0].username == "bob"
        assert results[0].password == "hunter2"

        db.refresh(row)
        assert row.encryption_version == "aesgcm"
        assert decrypt_field_gcm(
            db.query(VaultEntry).filter(VaultEntry.id == entry_id).first().username_encrypted,
            _KEY_USER_1,
        ) == "bob"

    def test_fernet_version_unchanged_when_decryption_fails(self, db):
        """If decryption fails (wrong key), encryption_version stays 'fernet'."""
        row = VaultEntry(
            user_id=_USER_2_ID,
            title="Trapped Entry",
            encryption_version="fernet",
            username_encrypted=encrypt_field("eve", _KEY_USER_1),
            password_encrypted=encrypt_field("password", _KEY_USER_1),
            notes_encrypted=None,
        )
        db.add(row)
        db.commit()
        db.refresh(row)

        # Decryption with the wrong key must fail before any re-encryption occurs.
        with pytest.raises(HTTPException) as exc_info:
            vault_service.get_entry(row.id, _USER_2_ID, _KEY_USER_2, db)
        assert exc_info.value.status_code == 500

        # The row must remain 'fernet' — no re-encryption happened.
        db.refresh(row)
        assert row.encryption_version == "fernet"

    # --- Lazy re-encryption via update_entry --------------------------------

    def test_update_sensitive_field_stamps_aesgcm(self, db):
        """Updating a sensitive field on a legacy row must stamp 'aesgcm'."""
        row = VaultEntry(
            user_id=_USER_1_ID,
            title="Legacy",
            encryption_version="fernet",
            username_encrypted=encrypt_field("olduser", _KEY_USER_1),
            password_encrypted=encrypt_field("oldpass", _KEY_USER_1),
            notes_encrypted=None,
        )
        db.add(row)
        db.commit()
        db.refresh(row)

        vault_service.update_entry(
            row.id, VaultEntryUpdate(password="newpass"), _USER_1_ID, _KEY_USER_1, db
        )

        db.refresh(row)
        assert row.encryption_version == "aesgcm"
        assert decrypt_field_gcm(row.password_encrypted, _KEY_USER_1) == "newpass"

    def test_update_plaintext_only_still_triggers_lazy_reencrypt(self, db):
        """Updating only plaintext fields still triggers lazy re-encryption.

        update_entry() calls _decrypt_entry(entry, key, db=db) after every
        commit, which upgrades any 'fernet' row to 'aesgcm' on the read-back,
        even when no sensitive fields were changed in the update itself.
        """
        row = VaultEntry(
            user_id=_USER_1_ID,
            title="Old Title",
            encryption_version="fernet",
            username_encrypted=encrypt_field("alice", _KEY_USER_1),
            password_encrypted=encrypt_field("s3cr3t!", _KEY_USER_1),
            notes_encrypted=None,
        )
        db.add(row)
        db.commit()
        db.refresh(row)

        # Only change a plaintext field — no sensitive field updated.
        vault_service.update_entry(
            row.id, VaultEntryUpdate(title="New Title"), _USER_1_ID, _KEY_USER_1, db
        )

        db.refresh(row)
        # The lazy re-encryption in _decrypt_entry() must have fired.
        assert row.encryption_version == "aesgcm"
        assert decrypt_field_gcm(row.username_encrypted, _KEY_USER_1) == "alice"
        assert decrypt_field_gcm(row.password_encrypted, _KEY_USER_1) == "s3cr3t!"


class TestDecryptionFailure:
    def test_get_entry_with_wrong_key_raises_http_500(self, db):
        """If a row was encrypted with Key A but decrypted with Key B,
        _decrypt_entry must raise HTTP 500 — not leak any detail."""
        # Encrypt the entry with _KEY_USER_1
        created = vault_service.create_entry(
            _make_create_data(), _USER_1_ID, _KEY_USER_1, db
        )
        # Manually assign the entry to _USER_2_ID so the query succeeds,
        # then try to decrypt it with _KEY_USER_2 (the wrong key).
        row = db.query(VaultEntry).filter(VaultEntry.id == created.id).first()
        row.user_id = _USER_2_ID
        db.commit()

        with pytest.raises(HTTPException) as exc_info:
            vault_service.get_entry(created.id, _USER_2_ID, _KEY_USER_2, db)
        assert exc_info.value.status_code == 500
        assert exc_info.value.detail == "Unable to decrypt entry."

    def test_get_entries_with_tampered_token_raises_http_500(self, db):
        """A tampered ciphertext in the DB must surface as HTTP 500."""
        created = vault_service.create_entry(
            _make_create_data(), _USER_1_ID, _KEY_USER_1, db
        )
        # Corrupt the stored token directly.
        row = db.query(VaultEntry).filter(VaultEntry.id == created.id).first()
        row.password_encrypted = "gAAAAA_this_is_not_a_real_fernet_token"
        db.commit()

        with pytest.raises(HTTPException) as exc_info:
            vault_service.get_entries(_USER_1_ID, _KEY_USER_1, db)
        assert exc_info.value.status_code == 500
        assert exc_info.value.detail == "Unable to decrypt entry."
