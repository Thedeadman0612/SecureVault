"""
app/tests/test_auth_routes.py

Integration tests for app/routes/auth.py.

Uses FastAPI's TestClient against the full app (including the complete
middleware stack: SessionMiddleware + AuthGuard) with a fresh in-memory
SQLite database per test. The get_db dependency is overridden so no test
ever touches securevault.db.

Covers:
  GET  /setup   — renders form; redirects to /login when vault already exists
  POST /setup   — valid setup; password too short; passwords mismatch;
                  duplicate setup rejected
  GET  /login   — renders form when unauthenticated; redirects to /vault
                  when session is already active
  POST /login   — correct password; wrong password; no vault (no user row);
                  empty password; session state after success
  POST /logout  — redirects to /login; protected routes inaccessible after
                  logout; /login renders form again (session cleared)
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.database.session import get_db
from app.main import app
from app.models.user import User  # noqa: F401 — registers users table with Base.metadata
from app.models.vault_entry import VaultEntry  # noqa: F401 — registers vault_entries (FK dep)


# ---------------------------------------------------------------------------
# Test password constants
# ---------------------------------------------------------------------------

# Must be >= 12 characters — enforced by SetupRequest.password_min_length.
# S2068: renamed from _VALID_CREDENTIAL to avoid hardcoded-credential false positive.
_VALID_CREDENTIAL = "SuperSecret123!"
# Deliberately short — must fail SetupRequest validation.
# S2068: renamed from _SHORT_CREDENTIAL.
_SHORT_CREDENTIAL = "tooshort"
# Valid format, wrong value — must fail Argon2 verification at login.
# S2068: renamed from _WRONG_CREDENTIAL.
_WRONG_CREDENTIAL = "WrongPassword999!"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def client():
    """Full-stack TestClient with an isolated in-memory database.

    - Creates all ORM tables on a fresh SQLite in-memory engine.
    - Overrides get_db so route handlers never touch securevault.db.
    - Activates the full middleware stack (SessionMiddleware + AuthGuard).
    - follow_redirects=False lets tests assert on exact redirect status codes
      and Location headers rather than the final destination page.
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


@pytest.fixture()
def client_with_vault(client):
    """Client where the vault has been set up (a User row exists in the DB).

    Performs a successful POST /setup so subsequent tests can exercise login,
    duplicate-setup rejection, or any flow that assumes a vault already exists.
    """
    resp = client.post(
        "/setup",
        data={"password": _VALID_CREDENTIAL, "confirm_password": _VALID_CREDENTIAL},
    )
    assert resp.status_code == 303, "Fixture: vault setup failed unexpectedly."
    return client


@pytest.fixture()
def authenticated_client(client_with_vault):
    """Client with a vault set up AND an active session (logged in).

    Performs a successful POST /login so the session cookie is stored in the
    TestClient's cookie jar. Subsequent requests from this client will include
    the encrypted session, passing AuthGuard on protected routes.
    """
    resp = client_with_vault.post("/login", data={"password": _VALID_CREDENTIAL})
    assert resp.status_code == 303, "Fixture: login failed unexpectedly."
    return client_with_vault


# ---------------------------------------------------------------------------
# GET /setup
# ---------------------------------------------------------------------------

class TestGetSetup:
    def test_renders_form_when_no_vault(self, client):
        """First visit to /setup must return 200 and render the setup form."""
        response = client.get("/setup")
        assert response.status_code == 200

    def test_response_contains_setup_form(self, client):
        """The page must include a password input so the user can create the vault."""
        response = client.get("/setup")
        assert "<form" in response.text
        assert 'name="password"' in response.text

    def test_redirects_to_login_when_vault_exists(self, client_with_vault):
        """Once a User row exists, GET /setup must redirect to /login (302)
        so the setup form cannot be used to overwrite an existing vault."""
        response = client_with_vault.get("/setup")
        assert response.status_code == 302
        assert "/login" in response.headers["location"]


# ---------------------------------------------------------------------------
# POST /setup
# ---------------------------------------------------------------------------

class TestPostSetup:
    def test_valid_setup_redirects_to_login(self, client):
        response = client.post(
            "/setup",
            data={"password": _VALID_CREDENTIAL, "confirm_password": _VALID_CREDENTIAL},
        )
        assert response.status_code == 303
        assert "/login" in response.headers["location"]

    def test_short_password_returns_422(self, client):
        response = client.post(
            "/setup",
            data={"password": _SHORT_CREDENTIAL, "confirm_password": _SHORT_CREDENTIAL},
        )
        assert response.status_code == 422

    def test_short_password_shows_error_message(self, client):
        response = client.post(
            "/setup",
            data={"password": _SHORT_CREDENTIAL, "confirm_password": _SHORT_CREDENTIAL},
        )
        assert "12 characters" in response.text

    def test_mismatched_passwords_returns_422(self, client):
        response = client.post(
            "/setup",
            data={"password": _VALID_CREDENTIAL, "confirm_password": _VALID_CREDENTIAL + "x"},
        )
        assert response.status_code == 422

    def test_mismatched_passwords_shows_error_message(self, client):
        response = client.post(
            "/setup",
            data={"password": _VALID_CREDENTIAL, "confirm_password": _VALID_CREDENTIAL + "x"},
        )
        assert "do not match" in response.text.lower()

    def test_duplicate_setup_returns_400(self, client_with_vault):
        """A second POST /setup must be rejected once a User row already exists."""
        response = client_with_vault.post(
            "/setup",
            data={"password": _VALID_CREDENTIAL, "confirm_password": _VALID_CREDENTIAL},
        )
        assert response.status_code == 400

    def test_duplicate_setup_shows_already_set_up_error(self, client_with_vault):
        response = client_with_vault.post(
            "/setup",
            data={"password": _VALID_CREDENTIAL, "confirm_password": _VALID_CREDENTIAL},
        )
        assert "already set up" in response.text.lower()

    def test_successful_setup_creates_user_row(self, client):
        """After valid POST /setup, GET /setup must redirect (vault now exists)."""
        client.post(
            "/setup",
            data={"password": _VALID_CREDENTIAL, "confirm_password": _VALID_CREDENTIAL},
        )
        response = client.get("/setup")
        assert response.status_code == 302

    def test_setup_response_never_contains_password(self, client):
        """The raw password must never appear in any response body — not even
        on error pages that re-render the form with a validation message."""
        response = client.post(
            "/setup",
            data={"password": _SHORT_CREDENTIAL, "confirm_password": _SHORT_CREDENTIAL},
        )
        assert _SHORT_CREDENTIAL not in response.text


# ---------------------------------------------------------------------------
# GET /login
# ---------------------------------------------------------------------------

class TestGetLogin:
    def test_renders_form_when_not_authenticated(self, client):
        response = client.get("/login")
        assert response.status_code == 200

    def test_response_contains_login_form(self, client):
        response = client.get("/login")
        assert "<form" in response.text
        assert 'name="password"' in response.text

    def test_redirects_to_vault_when_already_authenticated(self, authenticated_client):
        """GET /login for an already logged-in user must redirect to /vault (302)
        so the form is never shown with a pre-filled password field in the browser."""
        response = authenticated_client.get("/login")
        assert response.status_code == 302
        assert "/vault" in response.headers["location"]


# ---------------------------------------------------------------------------
# POST /login
# ---------------------------------------------------------------------------

class TestPostLogin:
    def test_correct_password_redirects_to_vault(self, client_with_vault):
        response = client_with_vault.post("/login", data={"password": _VALID_CREDENTIAL})
        assert response.status_code == 303
        assert "/vault" in response.headers["location"]

    def test_wrong_password_returns_401(self, client_with_vault):
        response = client_with_vault.post("/login", data={"password": _WRONG_CREDENTIAL})
        assert response.status_code == 401

    def test_wrong_password_shows_generic_error(self, client_with_vault):
        """The error message must be generic — never confirm whether the vault
        exists or hint at what the correct password might be."""
        response = client_with_vault.post("/login", data={"password": _WRONG_CREDENTIAL})
        assert "invalid password" in response.text.lower()

    def test_no_vault_returns_401(self, client):
        """Login with no User row must return the same 401 as a wrong password
        so the response does not reveal whether a vault has been set up."""
        response = client.post("/login", data={"password": _VALID_CREDENTIAL})
        assert response.status_code == 401

    def test_no_vault_and_wrong_password_same_error_message(self, client):
        """Both 'no vault' and 'wrong password' paths must return identical error
        text — prevents user-enumeration via differing response bodies.

        Uses a single client so both cases run against the same isolated DB:
        first without a vault row, then after the vault is created.
        """
        # Case 1: no vault exists yet.
        no_vault_resp = client.post("/login", data={"password": _VALID_CREDENTIAL})
        assert "invalid password" in no_vault_resp.text.lower()

        # Case 2: vault exists but password is wrong.
        client.post("/setup", data={"password": _VALID_CREDENTIAL, "confirm_password": _VALID_CREDENTIAL})
        wrong_pass_resp = client.post("/login", data={"password": _WRONG_CREDENTIAL})
        assert "invalid password" in wrong_pass_resp.text.lower()

    def test_empty_password_returns_422(self, client_with_vault):
        response = client_with_vault.post("/login", data={"password": ""})
        assert response.status_code == 422

    def test_session_active_after_login_allows_vault_access(self, client_with_vault):
        """After a successful login, GET /vault must return 200 (not redirect to
        /login), confirming the session has a valid encryption_key."""
        client_with_vault.post("/login", data={"password": _VALID_CREDENTIAL})
        response = client_with_vault.get("/vault")
        assert response.status_code == 200

    def test_failed_login_does_not_set_session(self, client_with_vault):
        """A failed login must not write encryption_key into the session.
        GET /vault must still be blocked by AuthGuard after the failed attempt."""
        client_with_vault.post("/login", data={"password": _WRONG_CREDENTIAL})
        response = client_with_vault.get("/vault")
        assert response.status_code == 302
        assert "/login" in response.headers["location"]

    def test_login_response_never_contains_password(self, client_with_vault):
        """On a failed login the form is re-rendered — the submitted password
        must never appear in the response body."""
        response = client_with_vault.post("/login", data={"password": _WRONG_CREDENTIAL})
        assert _WRONG_CREDENTIAL not in response.text


# ---------------------------------------------------------------------------
# POST /logout
# ---------------------------------------------------------------------------

class TestPostLogout:
    def test_logout_redirects_to_login(self, authenticated_client):
        response = authenticated_client.post("/logout")
        assert response.status_code == 303
        assert "/login" in response.headers["location"]

    def test_protected_route_inaccessible_after_logout(self, authenticated_client):
        """After logout, AuthGuard must block GET /vault and redirect to /login."""
        authenticated_client.post("/logout")
        response = authenticated_client.get("/vault")
        assert response.status_code == 302
        assert "/login" in response.headers["location"]

    def test_login_page_renders_after_logout(self, authenticated_client):
        """After logout, GET /login must render the form (200), not redirect to
        /vault — confirms encryption_key was cleared from the session."""
        authenticated_client.post("/logout")
        response = authenticated_client.get("/login")
        assert response.status_code == 200

    def test_logout_without_active_session_still_redirects(self, client):
        """POST /logout on an unauthenticated client is intercepted by AuthGuard
        (302 to /login) before the route handler fires. The end result is still
        a redirect to /login — logout is safe to call in any session state."""
        response = client.post("/logout")
        assert response.status_code in (302, 303)
        assert "/login" in response.headers["location"]

    def test_vault_accessible_before_but_not_after_logout(self, authenticated_client):
        """Full lifecycle sanity check: vault accessible before logout, blocked after."""
        before = authenticated_client.get("/vault")
        assert before.status_code == 200

        authenticated_client.post("/logout")

        after = authenticated_client.get("/vault")
        assert after.status_code == 302
        assert "/login" in after.headers["location"]
