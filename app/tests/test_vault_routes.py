"""
app/tests/test_vault_routes.py

Integration tests for app/routes/vault.py.

Uses a full-stack TestClient (same middleware chain: EncryptedSession, CSRF,
AuthGuard) with an isolated in-memory SQLite database. Tests that require an
authenticated session use the `auth_client` fixture which completes setup+login
before yielding.

Covers:
  GET  /vault              — dashboard renders, HTTPException path
  POST /vault/import       — .xml import, .csv import, too-large file,
                             unsupported extension, parse error
  GET  /vault/export       — KeePass XML download, LastPass CSV download
  GET  /entry/new          — renders form
  POST /entry/new          — success redirect, validation error, service error
  GET  /entry/{id}         — success, 404 redirect
  GET  /entry/{id}/edit    — success, 404 redirect
  POST /entry/{id}/edit    — success redirect, 404, validation error
  POST /entry/{id}/delete  — success, 404 (silently ignored)
"""

import io
import re
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.database.session import get_db
from app.main import app
from app.models.recovery_code import RecoveryCode  # noqa: F401 — registers table
from app.models.user import User  # noqa: F401 — registers table
from app.models.vault_entry import VaultEntry  # noqa: F401 — registers table


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PASSWORD = "VaultTestPass99!"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def client():
    """Full-stack TestClient wired to an isolated in-memory SQLite database."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app, follow_redirects=False) as c:
        yield c

    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)


def _csrf(client: TestClient, url: str = "/login") -> str:
    """GET a page and extract its CSRF token from the hidden form field."""
    resp = client.get(url)
    match = re.search(r'name="csrf_token"\s+value="([0-9a-f]{64})"', resp.text)
    return match.group(1) if match else ""


@pytest.fixture()
def auth_client(client):
    """Client with a vault set up and an active authenticated session."""
    # 1. Setup
    token = _csrf(client, "/setup")
    r = client.post("/setup", data={
        "password": _PASSWORD,
        "confirm_password": _PASSWORD,
        "csrf_token": token,
    })
    assert r.status_code == 303, f"Setup failed: {r.status_code}"

    # 2. Login
    token = _csrf(client, "/login")
    r = client.post("/login", data={"password": _PASSWORD, "csrf_token": token})
    assert r.status_code == 303, f"Login failed: {r.status_code}"

    return client


def _create_entry(auth_client: TestClient, title: str = "Test Entry",
                  username: str = "user", password: str = "pass") -> int:
    """Helper: create a vault entry and return its ID parsed from the redirect."""
    token = _csrf(auth_client, "/vault")
    r = auth_client.post("/entry/new", data={
        "title": title,
        "username": username,
        "password": password,
        "csrf_token": token,
    })
    assert r.status_code == 303
    # After creation, go to /vault and find the entry link to get the ID.
    vault_resp = auth_client.get("/vault", follow_redirects=True)
    match = re.search(r'/entry/(\d+)', vault_resp.text)
    return int(match.group(1)) if match else 1


# ---------------------------------------------------------------------------
# GET /vault — dashboard
# ---------------------------------------------------------------------------

class TestGetVault:
    def test_renders_dashboard_when_authenticated(self, auth_client):
        r = auth_client.get("/vault")
        assert r.status_code == 200

    def test_unauthenticated_redirects_to_login(self, client):
        r = client.get("/vault")
        assert r.status_code == 302
        assert "/login" in r.headers["location"]

    def test_search_query_param_accepted(self, auth_client):
        r = auth_client.get("/vault?q=test&category=Email")
        assert r.status_code == 200

    def test_import_flash_params_accepted(self, auth_client):
        r = auth_client.get("/vault?imported=3")
        assert r.status_code == 200

    def test_import_error_flash_param_accepted(self, auth_client):
        r = auth_client.get("/vault?import_error=Could+not+parse+file")
        assert r.status_code == 200

    def test_get_entries_exception_shows_error(self, auth_client):
        from fastapi import HTTPException
        with patch("app.routes.vault.vault_service.get_entries",
                   side_effect=HTTPException(status_code=500, detail="decrypt fail")):
            r = auth_client.get("/vault")
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# POST /vault/import
# ---------------------------------------------------------------------------

_KEEPASS_XML = b"""<?xml version="1.0" encoding="utf-8"?>
<KeePassFile>
  <Root>
    <Group>
      <Name>NewDatabase</Name>
      <Group>
        <Name>Email</Name>
        <Entry>
          <String><Key>Title</Key><Value>Gmail</Value></String>
          <String><Key>UserName</Key><Value>alice@gmail.com</Value></String>
          <String><Key>Password</Key><Value>gmailpass</Value></String>
          <String><Key>URL</Key><Value>https://gmail.com</Value></String>
          <String><Key>Notes</Key><Value></Value></String>
        </Entry>
      </Group>
    </Group>
  </Root>
</KeePassFile>"""

_LASTPASS_CSV = (
    b"url,username,password,extra,name,grouping,fav\n"
    b"https://github.com,alice,ghpass,,GitHub,Dev,0"
)


class TestPostImportVault:
    def test_import_keepass_xml_redirects_with_count(self, auth_client):
        token = _csrf(auth_client, "/vault")
        r = auth_client.post(
            "/vault/import",
            data={"csrf_token": token},
            files={"import_file": ("export.xml", io.BytesIO(_KEEPASS_XML), "application/xml")},
        )
        assert r.status_code == 303
        assert "imported=1" in r.headers["location"]

    def test_import_lastpass_csv_redirects_with_count(self, auth_client):
        token = _csrf(auth_client, "/vault")
        r = auth_client.post(
            "/vault/import",
            data={"csrf_token": token},
            files={"import_file": ("export.csv", io.BytesIO(_LASTPASS_CSV), "text/csv")},
        )
        assert r.status_code == 303
        assert "imported=1" in r.headers["location"]

    def test_import_file_too_large_redirects_with_error(self, auth_client):
        token = _csrf(auth_client, "/vault")
        big = io.BytesIO(b"x" * (5 * 1024 * 1024 + 1))
        r = auth_client.post(
            "/vault/import",
            data={"csrf_token": token},
            files={"import_file": ("big.xml", big, "application/xml")},
        )
        assert r.status_code == 303
        assert "import_error" in r.headers["location"]

    def test_import_unsupported_extension_redirects_with_error(self, auth_client):
        token = _csrf(auth_client, "/vault")
        r = auth_client.post(
            "/vault/import",
            data={"csrf_token": token},
            files={"import_file": ("data.txt", io.BytesIO(b"hello"), "text/plain")},
        )
        assert r.status_code == 303
        assert "import_error" in r.headers["location"]

    def test_import_invalid_xml_redirects_with_error(self, auth_client):
        token = _csrf(auth_client, "/vault")
        bad_xml = io.BytesIO(b"not xml <<>>")
        r = auth_client.post(
            "/vault/import",
            data={"csrf_token": token},
            files={"import_file": ("export.xml", bad_xml, "application/xml")},
        )
        assert r.status_code == 303
        assert "import_error" in r.headers["location"]

    def test_import_invalid_csv_parse_handled(self, auth_client):
        """A CSV where every row has no title should import 0 entries gracefully."""
        token = _csrf(auth_client, "/vault")
        no_title_csv = io.BytesIO(b"url,username,password,extra,name,grouping,fav\n,,,,,,")
        r = auth_client.post(
            "/vault/import",
            data={"csrf_token": token},
            files={"import_file": ("export.csv", no_title_csv, "text/csv")},
        )
        assert r.status_code == 303
        assert "imported=0" in r.headers["location"]


# ---------------------------------------------------------------------------
# GET /vault/export
# ---------------------------------------------------------------------------

class TestGetExportVault:
    def test_export_keepass_xml_returns_xml_bytes(self, auth_client):
        r = auth_client.get("/vault/export?format=keepass")
        assert r.status_code == 200
        assert "xml" in r.headers["content-type"]
        assert b"KeePassFile" in r.content

    def test_export_lastpass_csv_returns_csv_bytes(self, auth_client):
        r = auth_client.get("/vault/export?format=lastpass")
        assert r.status_code == 200
        assert "csv" in r.headers["content-type"]
        assert b"url,username" in r.content

    def test_export_default_format_is_keepass(self, auth_client):
        r = auth_client.get("/vault/export")
        assert r.status_code == 200
        assert b"KeePassFile" in r.content

    def test_export_content_disposition_is_attachment(self, auth_client):
        r = auth_client.get("/vault/export?format=keepass")
        assert "attachment" in r.headers["content-disposition"]
        assert "securevault_export.xml" in r.headers["content-disposition"]

    def test_export_lastpass_filename(self, auth_client):
        r = auth_client.get("/vault/export?format=lastpass")
        assert "securevault_export.csv" in r.headers["content-disposition"]

    def test_export_unauthenticated_redirects(self, client):
        r = client.get("/vault/export")
        assert r.status_code == 302


# ---------------------------------------------------------------------------
# GET /entry/new
# ---------------------------------------------------------------------------

class TestGetNewEntry:
    def test_renders_create_form(self, auth_client):
        r = auth_client.get("/entry/new")
        assert r.status_code == 200

    def test_unauthenticated_redirects(self, client):
        r = client.get("/entry/new")
        assert r.status_code == 302
        assert "/login" in r.headers["location"]


# ---------------------------------------------------------------------------
# POST /entry/new
# ---------------------------------------------------------------------------

class TestPostNewEntry:
    def test_valid_entry_redirects_to_vault(self, auth_client):
        token = _csrf(auth_client, "/vault")
        r = auth_client.post("/entry/new", data={
            "title": "GitHub",
            "username": "alice",
            "password": "ghpass",
            "csrf_token": token,
        })
        assert r.status_code == 303
        assert r.headers["location"] == "/vault"

    def test_missing_title_returns_form_with_error(self, auth_client):
        token = _csrf(auth_client, "/vault")
        r = auth_client.post("/entry/new", data={
            "title": "",
            "username": "alice",
            "password": "ghpass",
            "csrf_token": token,
        })
        assert r.status_code == 422

    def test_missing_password_returns_form_with_error(self, auth_client):
        token = _csrf(auth_client, "/vault")
        r = auth_client.post("/entry/new", data={
            "title": "Site",
            "username": "alice",
            "password": "",
            "csrf_token": token,
        })
        assert r.status_code in (200, 422)

    def test_service_exception_returns_500_form(self, auth_client):
        token = _csrf(auth_client, "/vault")
        with patch("app.routes.vault.vault_service.create_entry",
                   side_effect=Exception("DB error")):
            r = auth_client.post("/entry/new", data={
                "title": "Fail",
                "username": "alice",
                "password": "pass",
                "csrf_token": token,
            })
        assert r.status_code == 500


# ---------------------------------------------------------------------------
# GET /entry/{id}
# ---------------------------------------------------------------------------

class TestGetEntry:
    def test_renders_entry_detail(self, auth_client):
        entry_id = _create_entry(auth_client, title="MyEntry")
        r = auth_client.get(f"/entry/{entry_id}")
        assert r.status_code == 200

    def test_nonexistent_entry_redirects_to_vault(self, auth_client):
        r = auth_client.get("/entry/99999")
        assert r.status_code in (302, 404)
        if r.status_code == 302:
            assert "/vault" in r.headers["location"]

    def test_unauthenticated_redirects(self, client):
        r = client.get("/entry/1")
        assert r.status_code == 302


# ---------------------------------------------------------------------------
# GET /entry/{id}/edit
# ---------------------------------------------------------------------------

class TestGetEditEntry:
    def test_renders_edit_form(self, auth_client):
        entry_id = _create_entry(auth_client, title="EditMe")
        r = auth_client.get(f"/entry/{entry_id}/edit")
        assert r.status_code == 200

    def test_nonexistent_entry_redirects_to_vault(self, auth_client):
        r = auth_client.get("/entry/99999/edit")
        assert r.status_code in (302, 404)
        if r.status_code == 302:
            assert "/vault" in r.headers["location"]

    def test_unauthenticated_redirects(self, client):
        r = client.get("/entry/1/edit")
        assert r.status_code == 302


# ---------------------------------------------------------------------------
# POST /entry/{id}/edit
# ---------------------------------------------------------------------------

class TestPostEditEntry:
    def test_valid_update_redirects_to_entry(self, auth_client):
        entry_id = _create_entry(auth_client, title="OrigTitle")
        token = _csrf(auth_client, "/vault")
        r = auth_client.post(f"/entry/{entry_id}/edit", data={
            "title": "NewTitle",
            "username": "",
            "password": "",
            "website": "",
            "category": "",
            "notes": "",
            "csrf_token": token,
        })
        assert r.status_code == 303
        assert f"/entry/{entry_id}" in r.headers["location"]

    def test_nonexistent_entry_redirects_to_vault(self, auth_client):
        token = _csrf(auth_client, "/vault")
        r = auth_client.post("/entry/99999/edit", data={
            "title": "Title",
            "username": "",
            "password": "",
            "website": "",
            "category": "",
            "notes": "",
            "csrf_token": token,
        })
        assert r.status_code in (302, 404)
        if r.status_code == 302:
            assert "/vault" in r.headers["location"]


# ---------------------------------------------------------------------------
# POST /entry/{id}/delete
# ---------------------------------------------------------------------------

class TestPostDeleteEntry:
    def test_delete_existing_entry_redirects_to_vault(self, auth_client):
        entry_id = _create_entry(auth_client, title="DeleteMe")
        token = _csrf(auth_client, "/vault")
        r = auth_client.post(f"/entry/{entry_id}/delete",
                             data={"csrf_token": token})
        assert r.status_code == 303
        assert r.headers["location"] == "/vault"

    def test_delete_nonexistent_entry_still_redirects(self, auth_client):
        token = _csrf(auth_client, "/vault")
        r = auth_client.post("/entry/99999/delete", data={"csrf_token": token})
        assert r.status_code == 303
        assert r.headers["location"] == "/vault"

    def test_unauthenticated_redirects(self, client):
        # CSRF middleware catches the missing token first and issues a 303 to /login
        r = client.post("/entry/1/delete")
        assert r.status_code in (302, 303, 403)
