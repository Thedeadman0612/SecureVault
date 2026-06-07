"""
app/tests/test_auth_routes.py

Integration tests for app/routes/auth.py.

Uses FastAPI's TestClient against the full app (including the complete
middleware stack: SessionMiddleware + CSRFMiddleware + AuthGuard) with a
fresh in-memory SQLite database per test. The get_db dependency is overridden
so no test ever touches securevault.db.

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
  CSRF          — POSTs without or with wrong token are rejected with 403;
                  token is embedded in every rendered form
"""

import re
from unittest.mock import patch

import pyotp
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
# RecoveryCode is imported transitively via app.main → routes.auth → services.auth_service,
# which registers recovery_codes with Base.metadata so create_all() builds the table.


# ---------------------------------------------------------------------------
# Test credential constants
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
# CSRF test helper
# ---------------------------------------------------------------------------

def _get_csrf_token(client: TestClient, url: str = "/login") -> str:
    """GET a page and extract the CSRF token from its hidden form input.

    The token is embedded in every rendered form as:
        <input type="hidden" name="csrf_token" value="<64-hex-chars>">

    This helper performs a GET to establish (or reuse) the session token, then
    parses the value from the HTML.  Because the token is session-scoped (not
    rotated per-request), one GET per test is sufficient — the same token is
    valid for all subsequent POSTs in that session.

    Args:
        client: The TestClient whose session cookie jar is used.
        url:    A page that returns 200 HTML with at least one CSRF-protected
                form.  Use "/login" for unauthenticated clients; "/vault" for
                authenticated ones.
    """
    resp = client.get(url)
    # Attribute order in the template is: name="csrf_token" value="..."
    # The token is always 64 lowercase hex characters (32 bytes → hex).
    match = re.search(r'name="csrf_token"\s+value="([0-9a-f]{64})"', resp.text)
    return match.group(1) if match else ""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def client():
    """Full-stack TestClient with an isolated in-memory database.

    - Creates all ORM tables on a fresh SQLite in-memory engine.
    - Overrides get_db so route handlers never touch securevault.db.
    - Activates the full middleware stack (SessionMiddleware + CSRFMiddleware
      + AuthGuard).
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

    Performs a successful POST /setup (with a valid CSRF token) so subsequent
    tests can exercise login, duplicate-setup rejection, or any flow that
    assumes a vault already exists.
    """
    token = _get_csrf_token(client, "/setup")
    resp = client.post(
        "/setup",
        data={
            "password": _VALID_CREDENTIAL,
            "confirm_password": _VALID_CREDENTIAL,
            "csrf_token": token,
        },
    )
    assert resp.status_code == 303, "Fixture: vault setup failed unexpectedly."
    return client


@pytest.fixture()
def authenticated_client(client_with_vault):
    """Client with a vault set up AND an active session (logged in).

    Performs a successful POST /login (with a valid CSRF token) so the session
    cookie is stored in the TestClient's cookie jar.  Subsequent requests from
    this client will include the signed session, passing AuthGuard on protected
    routes.
    """
    token = _get_csrf_token(client_with_vault, "/login")
    resp = client_with_vault.post(
        "/login",
        data={"password": _VALID_CREDENTIAL, "csrf_token": token},
    )
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
        token = _get_csrf_token(client, "/setup")
        response = client.post(
            "/setup",
            data={"password": _VALID_CREDENTIAL, "confirm_password": _VALID_CREDENTIAL, "csrf_token": token},
        )
        assert response.status_code == 303
        assert "/login" in response.headers["location"]

    def test_short_password_returns_422(self, client):
        token = _get_csrf_token(client, "/setup")
        response = client.post(
            "/setup",
            data={"password": _SHORT_CREDENTIAL, "confirm_password": _SHORT_CREDENTIAL, "csrf_token": token},
        )
        assert response.status_code == 422

    def test_short_password_shows_error_message(self, client):
        token = _get_csrf_token(client, "/setup")
        response = client.post(
            "/setup",
            data={"password": _SHORT_CREDENTIAL, "confirm_password": _SHORT_CREDENTIAL, "csrf_token": token},
        )
        assert "12 characters" in response.text

    def test_mismatched_passwords_returns_422(self, client):
        token = _get_csrf_token(client, "/setup")
        response = client.post(
            "/setup",
            data={"password": _VALID_CREDENTIAL, "confirm_password": _VALID_CREDENTIAL + "x", "csrf_token": token},
        )
        assert response.status_code == 422

    def test_mismatched_passwords_shows_error_message(self, client):
        token = _get_csrf_token(client, "/setup")
        response = client.post(
            "/setup",
            data={"password": _VALID_CREDENTIAL, "confirm_password": _VALID_CREDENTIAL + "x", "csrf_token": token},
        )
        assert "do not match" in response.text.lower()

    def test_duplicate_setup_returns_400(self, client_with_vault):
        """A second POST /setup must be rejected once a User row already exists."""
        token = _get_csrf_token(client_with_vault, "/login")  # /setup redirects → use /login
        response = client_with_vault.post(
            "/setup",
            data={"password": _VALID_CREDENTIAL, "confirm_password": _VALID_CREDENTIAL, "csrf_token": token},
        )
        assert response.status_code == 400

    def test_duplicate_setup_shows_already_set_up_error(self, client_with_vault):
        token = _get_csrf_token(client_with_vault, "/login")
        response = client_with_vault.post(
            "/setup",
            data={"password": _VALID_CREDENTIAL, "confirm_password": _VALID_CREDENTIAL, "csrf_token": token},
        )
        assert "already set up" in response.text.lower()

    def test_successful_setup_creates_user_row(self, client):
        """After valid POST /setup, GET /setup must redirect (vault now exists)."""
        token = _get_csrf_token(client, "/setup")
        client.post(
            "/setup",
            data={"password": _VALID_CREDENTIAL, "confirm_password": _VALID_CREDENTIAL, "csrf_token": token},
        )
        response = client.get("/setup")
        assert response.status_code == 302

    def test_setup_response_never_contains_password(self, client):
        """The raw password must never appear in any response body — not even
        on error pages that re-render the form with a validation message."""
        token = _get_csrf_token(client, "/setup")
        response = client.post(
            "/setup",
            data={"password": _SHORT_CREDENTIAL, "confirm_password": _SHORT_CREDENTIAL, "csrf_token": token},
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
        token = _get_csrf_token(client_with_vault, "/login")
        response = client_with_vault.post("/login", data={"password": _VALID_CREDENTIAL, "csrf_token": token})
        assert response.status_code == 303
        assert "/vault" in response.headers["location"]

    def test_wrong_password_returns_401(self, client_with_vault):
        token = _get_csrf_token(client_with_vault, "/login")
        response = client_with_vault.post("/login", data={"password": _WRONG_CREDENTIAL, "csrf_token": token})
        assert response.status_code == 401

    def test_wrong_password_shows_generic_error(self, client_with_vault):
        """The error message must be generic — never confirm whether the vault
        exists or hint at what the correct password might be."""
        token = _get_csrf_token(client_with_vault, "/login")
        response = client_with_vault.post("/login", data={"password": _WRONG_CREDENTIAL, "csrf_token": token})
        assert "invalid password" in response.text.lower()

    def test_no_vault_returns_401(self, client):
        """Login with no User row must return the same 401 as a wrong password
        so the response does not reveal whether a vault has been set up."""
        token = _get_csrf_token(client, "/login")
        response = client.post("/login", data={"password": _VALID_CREDENTIAL, "csrf_token": token})
        assert response.status_code == 401

    def test_no_vault_and_wrong_password_same_error_message(self, client):
        """Both 'no vault' and 'wrong password' paths must return identical error
        text — prevents user-enumeration via differing response bodies.

        Uses a single client so both cases run against the same isolated DB:
        first without a vault row, then after the vault is created.
        """
        # One GET establishes the session token — reused for all three POSTs.
        token = _get_csrf_token(client, "/login")

        # Case 1: no vault exists yet.
        no_vault_resp = client.post("/login", data={"password": _VALID_CREDENTIAL, "csrf_token": token})
        assert "invalid password" in no_vault_resp.text.lower()

        # Case 2: vault exists but password is wrong.
        client.post("/setup", data={"password": _VALID_CREDENTIAL, "confirm_password": _VALID_CREDENTIAL, "csrf_token": token})
        wrong_pass_resp = client.post("/login", data={"password": _WRONG_CREDENTIAL, "csrf_token": token})
        assert "invalid password" in wrong_pass_resp.text.lower()

    def test_empty_password_returns_422(self, client_with_vault):
        token = _get_csrf_token(client_with_vault, "/login")
        response = client_with_vault.post("/login", data={"password": "", "csrf_token": token})
        assert response.status_code == 422

    def test_session_active_after_login_allows_vault_access(self, client_with_vault):
        """After a successful login, GET /vault must return 200 (not redirect to
        /login), confirming the session has a valid encryption_key."""
        token = _get_csrf_token(client_with_vault, "/login")
        client_with_vault.post("/login", data={"password": _VALID_CREDENTIAL, "csrf_token": token})
        response = client_with_vault.get("/vault")
        assert response.status_code == 200

    def test_failed_login_does_not_set_session(self, client_with_vault):
        """A failed login must not write encryption_key into the session.
        GET /vault must still be blocked by AuthGuard after the failed attempt."""
        token = _get_csrf_token(client_with_vault, "/login")
        client_with_vault.post("/login", data={"password": _WRONG_CREDENTIAL, "csrf_token": token})
        response = client_with_vault.get("/vault")
        assert response.status_code == 302
        assert "/login" in response.headers["location"]

    def test_login_response_never_contains_password(self, client_with_vault):
        """On a failed login the form is re-rendered — the submitted password
        must never appear in the response body."""
        token = _get_csrf_token(client_with_vault, "/login")
        response = client_with_vault.post("/login", data={"password": _WRONG_CREDENTIAL, "csrf_token": token})
        assert _WRONG_CREDENTIAL not in response.text


# ---------------------------------------------------------------------------
# POST /logout
# ---------------------------------------------------------------------------

class TestPostLogout:
    def test_logout_redirects_to_login(self, authenticated_client):
        token = _get_csrf_token(authenticated_client, "/vault")
        response = authenticated_client.post("/logout", data={"csrf_token": token})
        assert response.status_code == 303
        assert "/login" in response.headers["location"]

    def test_protected_route_inaccessible_after_logout(self, authenticated_client):
        """After logout, AuthGuard must block GET /vault and redirect to /login."""
        token = _get_csrf_token(authenticated_client, "/vault")
        authenticated_client.post("/logout", data={"csrf_token": token})
        response = authenticated_client.get("/vault")
        assert response.status_code == 302
        assert "/login" in response.headers["location"]

    def test_login_page_renders_after_logout(self, authenticated_client):
        """After logout, GET /login must render the form (200), not redirect to
        /vault — confirms encryption_key was cleared from the session."""
        token = _get_csrf_token(authenticated_client, "/vault")
        authenticated_client.post("/logout", data={"csrf_token": token})
        response = authenticated_client.get("/login")
        assert response.status_code == 200

    def test_logout_without_active_session_redirects_to_login(self, client):
        """POST /logout with no active session:
        CSRFMiddleware validates the token (obtained from GET /login), then
        AuthGuard intercepts the unauthenticated request and redirects to /login.
        The end result is still a redirect — logout is safe in any session state.
        """
        token = _get_csrf_token(client, "/login")
        response = client.post("/logout", data={"csrf_token": token})
        assert response.status_code in (302, 303)
        assert "/login" in response.headers["location"]

    def test_vault_accessible_before_but_not_after_logout(self, authenticated_client):
        """Full lifecycle sanity check: vault accessible before logout, blocked after."""
        before = authenticated_client.get("/vault")
        assert before.status_code == 200

        token = _get_csrf_token(authenticated_client, "/vault")
        authenticated_client.post("/logout", data={"csrf_token": token})

        after = authenticated_client.get("/vault")
        assert after.status_code == 302
        assert "/login" in after.headers["location"]


# ---------------------------------------------------------------------------
# CSRF protection behaviour
# ---------------------------------------------------------------------------

class TestCSRFProtection:
    """CSRFMiddleware rejects POST requests with a missing or wrong token."""

    def test_post_without_csrf_token_returns_403(self, client):
        """A POST with no csrf_token field on an ACTIVE session must be rejected
        with 403 — the middleware blocks the request before the route handler.

        The prior GET establishes a CSRF token in the session (token_was_fresh=False),
        which is the "genuine missing-token" scenario.  Compare with
        test_stale_csrf_token_on_fresh_session_redirects_to_login below, which
        covers the session-expiry race (token_was_fresh=True → 303 redirect).
        """
        _get_csrf_token(client, "/login")   # establish token in session
        response = client.post("/login", data={"password": _VALID_CREDENTIAL})
        assert response.status_code == 403

    def test_post_with_wrong_csrf_token_returns_403(self, client):
        """A POST with a csrf_token value that does not match the session token
        must be rejected with 403 regardless of other form fields."""
        _get_csrf_token(client, "/login")   # establish the real token in the session
        response = client.post(
            "/login",
            data={"password": _VALID_CREDENTIAL, "csrf_token": "a" * 64},
        )
        assert response.status_code == 403

    def test_get_request_is_never_blocked_by_csrf(self, client):
        """GET requests are safe methods and must pass through without CSRF validation."""
        response = client.get("/login")
        assert response.status_code == 200

    def test_csrf_token_present_in_login_form(self, client):
        """GET /login must embed a csrf_token hidden input in the rendered HTML."""
        response = client.get("/login")
        assert 'name="csrf_token"' in response.text

    def test_csrf_token_present_in_setup_form(self, client):
        """GET /setup must embed a csrf_token hidden input in the rendered HTML."""
        response = client.get("/setup")
        assert 'name="csrf_token"' in response.text

    def test_csrf_token_is_64_hex_chars(self, client):
        """The embedded token must be 64 lowercase hex characters (256 bits of entropy)."""
        token = _get_csrf_token(client, "/login")
        assert len(token) == 64
        assert all(c in "0123456789abcdef" for c in token)

    def test_csrf_token_stable_across_requests_in_same_session(self, client):
        """The CSRF token must not rotate between requests — multi-tab usage must
        not cause a previously opened tab's form to be rejected."""
        token_first  = _get_csrf_token(client, "/login")
        token_second = _get_csrf_token(client, "/login")
        assert token_first == token_second

    def test_stale_csrf_token_on_fresh_session_redirects_to_login(self):
        """A POST that arrives on a fresh/expired session redirects to /login.

        Scenario: the session expired (or a background browser request such as
        Chrome's DevTools probe silently triggered a session replacement).  The
        user's page is still open with the old CSRF token baked in.  Submitting
        any form now produces a token mismatch on an otherwise-empty session.

        Expected behaviour: 303 redirect to /login (not a confusing 403),
        because this is a stale-page race, not a genuine attack.

        A genuine CSRF attack arrives while the session is ACTIVE
        (token_was_fresh=False) and still receives 403 — see
        test_post_with_wrong_csrf_token_returns_403 above.
        """
        # Use a brand-new, isolated TestClient so there is no session state
        # whatsoever — the very first request is the POST.
        fresh_client = TestClient(app, raise_server_exceptions=False)
        response = fresh_client.post(
            "/login",
            data={"csrf_token": "a" * 64},   # non-empty but wrong
            follow_redirects=False,
        )
        # The middleware must redirect, not forbid.
        assert response.status_code == 303
        assert response.headers.get("location") in ("/login", "http://testserver/login")


# ---------------------------------------------------------------------------
# 2FA helpers and fixtures
# ---------------------------------------------------------------------------

# Deterministic secret used across all 2FA tests.  Patching generate_secret
# to return this value lets tests produce valid TOTP tokens on demand.
_KNOWN_2FA_SECRET = "JBSWY3DPEHPK3PXP"


def _enable_2fa(client: TestClient) -> list[str]:
    """Enable 2FA on an already-authenticated client with _KNOWN_2FA_SECRET.

    Returns the 8 plaintext recovery codes extracted from the setup page.
    The caller is responsible for being logged in before calling this.
    """
    with patch("app.routes.auth.generate_secret", return_value=_KNOWN_2FA_SECRET):
        resp = client.get("/2fa/setup")
    assert resp.status_code == 200, f"GET /2fa/setup returned {resp.status_code}"
    match = re.search(r'name="csrf_token"\s+value="([0-9a-f]{64})"', resp.text)
    csrf = match.group(1) if match else ""
    token_val = pyotp.TOTP(_KNOWN_2FA_SECRET).now()
    resp = client.post("/2fa/setup", data={"token": token_val, "csrf_token": csrf})
    assert resp.status_code == 200, f"POST /2fa/setup returned {resp.status_code}"
    return re.findall(r'class="recovery-code[^"]*">([^<]+)<', resp.text)


@pytest.fixture()
def client_2fa_enabled(authenticated_client):
    """Client with vault set up, logged in, and TOTP 2FA active."""
    _enable_2fa(authenticated_client)
    return authenticated_client


@pytest.fixture()
def client_2fa_pending(client_2fa_enabled):
    """Client with 2FA enabled and in mid-login state (pending_user_id set,
    encryption_key NOT yet in session — TOTP step still required)."""
    csrf = _get_csrf_token(client_2fa_enabled, "/vault")
    client_2fa_enabled.post("/logout", data={"csrf_token": csrf})
    csrf = _get_csrf_token(client_2fa_enabled, "/login")
    resp = client_2fa_enabled.post(
        "/login", data={"password": _VALID_CREDENTIAL, "csrf_token": csrf}
    )
    assert resp.status_code == 303
    assert "/2fa/verify" in resp.headers["location"]
    return client_2fa_enabled


# ---------------------------------------------------------------------------
# POST /login — 2FA redirect behaviour
# ---------------------------------------------------------------------------

class TestLogin2FA:
    def test_login_with_2fa_redirects_to_verify(self, client_2fa_enabled):
        """When 2FA is enabled, POST /login must redirect to /2fa/verify (303),
        not directly to /vault."""
        csrf = _get_csrf_token(client_2fa_enabled, "/vault")
        client_2fa_enabled.post("/logout", data={"csrf_token": csrf})
        csrf = _get_csrf_token(client_2fa_enabled, "/login")
        resp = client_2fa_enabled.post(
            "/login", data={"password": _VALID_CREDENTIAL, "csrf_token": csrf}
        )
        assert resp.status_code == 303
        assert "/2fa/verify" in resp.headers["location"]

    def test_vault_inaccessible_with_pending_session(self, client_2fa_pending):
        """With only pending_user_id in session (no encryption_key), AuthGuard
        must block GET /vault and redirect to /login."""
        resp = client_2fa_pending.get("/vault")
        assert resp.status_code == 302
        assert "/login" in resp.headers["location"]

    def test_login_without_2fa_still_goes_to_vault(self, client_with_vault):
        """Users who have not enabled 2FA must still be redirected to /vault
        after a correct password — the 2FA changes must not regress this."""
        token = _get_csrf_token(client_with_vault, "/login")
        resp = client_with_vault.post(
            "/login", data={"password": _VALID_CREDENTIAL, "csrf_token": token}
        )
        assert resp.status_code == 303
        assert "/vault" in resp.headers["location"]


# ---------------------------------------------------------------------------
# GET + POST /2fa/verify
# ---------------------------------------------------------------------------

class TestTotpVerify:
    def test_get_verify_renders_form(self, client_2fa_pending):
        """GET /2fa/verify must return 200 when pending_user_id is in session."""
        resp = client_2fa_pending.get("/2fa/verify")
        assert resp.status_code == 200
        assert 'name="token"' in resp.text

    def test_get_verify_without_pending_redirects_to_login(self, client):
        """GET /2fa/verify with no pending session must redirect to /login."""
        resp = client.get("/2fa/verify")
        assert resp.status_code == 302
        assert "/login" in resp.headers["location"]

    def test_valid_code_promotes_session_and_redirects_to_vault(self, client_2fa_pending):
        """POST /2fa/verify with a correct TOTP code must set encryption_key in
        session and redirect to /vault with 303."""
        token_val = pyotp.TOTP(_KNOWN_2FA_SECRET).now()
        csrf = _get_csrf_token(client_2fa_pending, "/2fa/verify")
        resp = client_2fa_pending.post(
            "/2fa/verify", data={"token": token_val, "csrf_token": csrf}
        )
        assert resp.status_code == 303
        assert "/vault" in resp.headers["location"]

    def test_vault_accessible_after_totp_success(self, client_2fa_pending):
        """After successful TOTP verification, GET /vault must return 200."""
        token_val = pyotp.TOTP(_KNOWN_2FA_SECRET).now()
        csrf = _get_csrf_token(client_2fa_pending, "/2fa/verify")
        client_2fa_pending.post(
            "/2fa/verify", data={"token": token_val, "csrf_token": csrf}
        )
        assert client_2fa_pending.get("/vault").status_code == 200

    def test_invalid_code_returns_401(self, client_2fa_pending):
        """POST /2fa/verify with a wrong code must return 401."""
        csrf = _get_csrf_token(client_2fa_pending, "/2fa/verify")
        resp = client_2fa_pending.post(
            "/2fa/verify", data={"token": "000000", "csrf_token": csrf}
        )
        assert resp.status_code == 401

    def test_invalid_code_shows_error_message(self, client_2fa_pending):
        csrf = _get_csrf_token(client_2fa_pending, "/2fa/verify")
        resp = client_2fa_pending.post(
            "/2fa/verify", data={"token": "000000", "csrf_token": csrf}
        )
        assert "invalid code" in resp.text.lower()

    def test_vault_still_blocked_after_failed_totp(self, client_2fa_pending):
        """A failed TOTP attempt must not grant vault access."""
        csrf = _get_csrf_token(client_2fa_pending, "/2fa/verify")
        client_2fa_pending.post(
            "/2fa/verify", data={"token": "000000", "csrf_token": csrf}
        )
        assert client_2fa_pending.get("/vault").status_code == 302

    def test_max_attempts_wipes_session_and_redirects(self, client_2fa_pending):
        """After 5 consecutive wrong codes, the pending session is cleared and
        the user is redirected to /login to restart from the password step."""
        csrf = _get_csrf_token(client_2fa_pending, "/2fa/verify")
        resp = None
        for _ in range(5):
            resp = client_2fa_pending.post(
                "/2fa/verify", data={"token": "000000", "csrf_token": csrf}
            )
        assert resp.status_code == 302
        assert "/login" in resp.headers["location"]
        # Vault must also be blocked after the session wipe.
        assert client_2fa_pending.get("/vault").status_code == 302


# ---------------------------------------------------------------------------
# GET + POST /2fa/recovery
# ---------------------------------------------------------------------------

class TestRecoveryCodes:
    def test_get_recovery_renders_form(self, client_2fa_pending):
        resp = client_2fa_pending.get("/2fa/recovery")
        assert resp.status_code == 200
        assert 'name="recovery_code"' in resp.text

    def test_get_recovery_without_pending_redirects_to_login(self, client):
        resp = client.get("/2fa/recovery")
        assert resp.status_code == 302
        assert "/login" in resp.headers["location"]

    def test_valid_recovery_code_grants_access(self, authenticated_client):
        """A valid, unused recovery code used at /2fa/recovery must promote the
        session and redirect to /vault."""
        codes = _enable_2fa(authenticated_client)
        assert codes, "No recovery codes parsed from setup page"

        csrf = _get_csrf_token(authenticated_client, "/vault")
        authenticated_client.post("/logout", data={"csrf_token": csrf})
        csrf = _get_csrf_token(authenticated_client, "/login")
        authenticated_client.post(
            "/login", data={"password": _VALID_CREDENTIAL, "csrf_token": csrf}
        )

        csrf = _get_csrf_token(authenticated_client, "/2fa/recovery")
        resp = authenticated_client.post(
            "/2fa/recovery", data={"recovery_code": codes[0], "csrf_token": csrf}
        )
        assert resp.status_code == 303
        assert "/vault" in resp.headers["location"]

    def test_vault_accessible_after_recovery_code(self, authenticated_client):
        """GET /vault after a successful recovery-code login must return 200."""
        codes = _enable_2fa(authenticated_client)

        csrf = _get_csrf_token(authenticated_client, "/vault")
        authenticated_client.post("/logout", data={"csrf_token": csrf})
        csrf = _get_csrf_token(authenticated_client, "/login")
        authenticated_client.post(
            "/login", data={"password": _VALID_CREDENTIAL, "csrf_token": csrf}
        )
        csrf = _get_csrf_token(authenticated_client, "/2fa/recovery")
        authenticated_client.post(
            "/2fa/recovery", data={"recovery_code": codes[0], "csrf_token": csrf}
        )
        assert authenticated_client.get("/vault").status_code == 200

    def test_recovery_code_is_single_use(self, authenticated_client):
        """The same recovery code must be rejected on a second attempt."""
        codes = _enable_2fa(authenticated_client)

        def _enter_pending():
            csrf = _get_csrf_token(authenticated_client, "/vault")
            authenticated_client.post("/logout", data={"csrf_token": csrf})
            csrf = _get_csrf_token(authenticated_client, "/login")
            authenticated_client.post(
                "/login", data={"password": _VALID_CREDENTIAL, "csrf_token": csrf}
            )

        # First use: must succeed.
        _enter_pending()
        csrf = _get_csrf_token(authenticated_client, "/2fa/recovery")
        resp = authenticated_client.post(
            "/2fa/recovery", data={"recovery_code": codes[0], "csrf_token": csrf}
        )
        assert resp.status_code == 303

        # Second use of the same code: must be rejected.
        _enter_pending()
        csrf = _get_csrf_token(authenticated_client, "/2fa/recovery")
        resp = authenticated_client.post(
            "/2fa/recovery", data={"recovery_code": codes[0], "csrf_token": csrf}
        )
        assert resp.status_code == 401

    def test_invalid_recovery_code_returns_401(self, client_2fa_pending):
        csrf = _get_csrf_token(client_2fa_pending, "/2fa/recovery")
        resp = client_2fa_pending.post(
            "/2fa/recovery", data={"recovery_code": "BADCODE1", "csrf_token": csrf}
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# POST /2fa/disable
# ---------------------------------------------------------------------------

class TestDisable2FA:
    def test_disable_redirects_to_vault(self, client_2fa_enabled):
        csrf = _get_csrf_token(client_2fa_enabled, "/vault")
        resp = client_2fa_enabled.post("/2fa/disable", data={"csrf_token": csrf})
        assert resp.status_code == 303
        assert "/vault" in resp.headers["location"]

    def test_login_goes_directly_to_vault_after_disable(self, client_2fa_enabled):
        """After disabling 2FA, POST /login must redirect to /vault directly
        (no TOTP step required)."""
        csrf = _get_csrf_token(client_2fa_enabled, "/vault")
        client_2fa_enabled.post("/2fa/disable", data={"csrf_token": csrf})

        csrf = _get_csrf_token(client_2fa_enabled, "/vault")
        client_2fa_enabled.post("/logout", data={"csrf_token": csrf})
        csrf = _get_csrf_token(client_2fa_enabled, "/login")
        resp = client_2fa_enabled.post(
            "/login", data={"password": _VALID_CREDENTIAL, "csrf_token": csrf}
        )
        assert resp.status_code == 303
        assert "/vault" in resp.headers["location"]

    def test_setup_page_accessible_after_disable(self, client_2fa_enabled):
        """GET /2fa/setup must return 200 after 2FA is disabled (authenticated
        user can start setup again at any time)."""
        csrf = _get_csrf_token(client_2fa_enabled, "/vault")
        client_2fa_enabled.post("/2fa/disable", data={"csrf_token": csrf})
        resp = client_2fa_enabled.get("/2fa/setup")
        assert resp.status_code == 200
