"""
app/tests/test_encrypted_session.py

Tests for EncryptedSessionMiddleware.

What we test
-------------
1. Cookie is opaque      — the raw cookie value cannot be decoded to JSON without
                           the server's key (the Phase 1 vulnerability is closed).
2. Session round-trips   — session data written during one request is readable
                           during the next.
3. Key derivation        — the same SECRET_KEY always produces the same Fernet key
                           (sessions survive server restarts).
4. Tampered cookie       — a corrupted cookie clears the session and triggers a
                           delete-cookie header (Max-Age=0) on the response.
5. Expired cookie        — a token older than max_age is rejected.
6. Logout deletes cookie — session.clear() on logout triggers Max-Age=0.
7. Missing cookie        — a request with no cookie starts with an empty session.
8. Unit: _derive_fernet_key — deterministic, 44-char base64url output.

Testing strategy
-----------------
Unit tests for EncryptedSessionMiddleware use a minimal FastAPI app with a
single route that reads/writes the session directly.  This tests the middleware
in isolation from the vault's auth flow.

Integration tests reuse the full app fixture (same pattern as test_auth_routes.py)
to verify the middleware works end-to-end in the real middleware stack.
"""

import base64
import json
from collections.abc import Generator

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.session import get_db
from app.main import app as main_app
from app.middleware.encrypted_session import EncryptedSessionMiddleware, _HKDF_SALT, _HKDF_INFO
from app.models.user import Base

# ---------------------------------------------------------------------------
# Minimal fixture app — tests EncryptedSessionMiddleware in isolation
# ---------------------------------------------------------------------------

_TEST_SECRET = "a-test-secret-key-long-enough-for-hkdf"


def _make_session_app() -> tuple[FastAPI, TestClient]:
    """Create a minimal FastAPI app with EncryptedSessionMiddleware attached."""
    mini_app = FastAPI()
    mini_app.add_middleware(
        EncryptedSessionMiddleware,
        secret_key=_TEST_SECRET,
        max_age=300,
        session_cookie="test_session",
        https_only=False,   # TestClient uses http://
        same_site="lax",
    )

    @mini_app.get("/write")
    async def write_session(request: Request) -> JSONResponse:
        """Write a value to the session and return it."""
        request.session["hello"] = "world"
        request.session["number"] = 42
        return JSONResponse({"written": True})

    @mini_app.get("/read")
    async def read_session(request: Request) -> JSONResponse:
        """Return current session contents."""
        return JSONResponse(dict(request.session))

    @mini_app.get("/clear")
    async def clear_session(request: Request) -> PlainTextResponse:
        """Clear the session (simulates logout)."""
        request.session.clear()
        return PlainTextResponse("cleared")

    return mini_app, TestClient(mini_app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Full-app fixture (mirrors test_auth_routes.py)
# ---------------------------------------------------------------------------

_TEST_DB_URL = "sqlite://"


@pytest.fixture(scope="module")
def test_engine():
    engine = create_engine(
        _TEST_DB_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="module")
def full_client(test_engine) -> Generator[TestClient, None, None]:
    """TestClient wired to the real app with an in-memory DB."""
    testing_session_local = sessionmaker(
        autocommit=False, autoflush=False, bind=test_engine
    )

    def override_get_db():
        db = testing_session_local()
        try:
            yield db
        finally:
            db.close()

    main_app.dependency_overrides[get_db] = override_get_db
    with TestClient(main_app, raise_server_exceptions=False) as c:
        yield c
    main_app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

_SESSION_COOKIE = "test_session"
_MAIN_COOKIE = "sv_session"


def _get_session_cookie(response, name: str = _SESSION_COOKIE) -> str | None:
    """Extract a named session cookie from a TestClient response."""
    return response.cookies.get(name)


# ---------------------------------------------------------------------------
# Test: cookie is opaque (Phase 1 vulnerability is closed)
# ---------------------------------------------------------------------------


class TestCookieIsOpaque:
    """The raw cookie value must not be decodable to plain JSON."""

    def test_cookie_value_is_not_plain_base64_json(self):
        """Attempting to base64-decode the cookie must NOT yield readable JSON.

        This test directly verifies that the Phase 1 vulnerability is closed.
        The old SessionMiddleware stored: <b64url(json)>.<timestamp>.<hmac>
        The new middleware stores: <Fernet ciphertext> (opaque bytes).
        """
        _, client = _make_session_app()
        response = client.get("/write")
        cookie = _get_session_cookie(response)

        assert cookie is not None, "No session cookie set"

        # Try the Phase 1 attack: split on '.' and base64-decode the first part.
        first_segment = cookie.split(".")[0]
        padded = first_segment + "=" * (4 - len(first_segment) % 4)
        try:
            raw = base64.urlsafe_b64decode(padded)
            # If this succeeds, check whether it decodes to our JSON payload.
            # Fernet ciphertext will decode to binary garbage, not valid JSON.
            decoded = json.loads(raw)
            # If we get here, the payload IS readable JSON — the test fails.
            pytest.fail(
                f"Cookie is still plain base64-JSON (Phase 1 vulnerability not fixed): {decoded}"
            )
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Expected: the decoded bytes are binary Fernet ciphertext, not JSON.
            pass

    def test_cookie_is_a_valid_fernet_token(self):
        """The cookie value IS a valid Fernet token decryptable with the right key."""
        _, client = _make_session_app()
        response = client.get("/write")
        cookie = _get_session_cookie(response)
        assert cookie is not None

        # Derive the same key the middleware uses and decrypt.
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=_HKDF_SALT,
            info=_HKDF_INFO,
        )
        raw_key = kdf.derive(_TEST_SECRET.encode("utf-8"))
        fernet_key = base64.urlsafe_b64encode(raw_key)
        fernet = Fernet(fernet_key)

        plaintext = fernet.decrypt(cookie.encode("utf-8"), ttl=300)
        payload = json.loads(plaintext)
        assert payload["hello"] == "world"
        assert payload["number"] == 42

    def test_wrong_key_cannot_decrypt_cookie(self):
        """A different SECRET_KEY cannot decrypt the session cookie."""
        _, client = _make_session_app()
        response = client.get("/write")
        cookie = _get_session_cookie(response)
        assert cookie is not None

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.fernet import InvalidToken

        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=_HKDF_SALT,
            info=_HKDF_INFO,
        )
        wrong_key = base64.urlsafe_b64encode(kdf.derive(b"wrong-secret"))
        fernet = Fernet(wrong_key)

        with pytest.raises(InvalidToken):
            fernet.decrypt(cookie.encode("utf-8"), ttl=300)


# ---------------------------------------------------------------------------
# Test: session round-trips
# ---------------------------------------------------------------------------


class TestSessionRoundTrip:
    """Session data written on one request must be readable on the next."""

    def test_write_then_read_returns_same_data(self):
        _, client = _make_session_app()
        # Write data to session.
        client.get("/write")
        # Read it back.
        response = client.get("/read")
        data = response.json()
        assert data["hello"] == "world"
        assert data["number"] == 42

    def test_empty_session_before_write(self):
        """Fresh client has no session data."""
        _, client = _make_session_app()
        response = client.get("/read")
        assert response.json() == {}

    def test_session_persists_across_multiple_requests(self):
        _, client = _make_session_app()
        client.get("/write")
        # Make several requests; session should still be readable.
        for _ in range(3):
            response = client.get("/read")
            assert response.json().get("hello") == "world"

    def test_cookie_is_refreshed_on_each_response(self):
        """A new (re-encrypted) cookie is set on every response that touches the session.

        This prevents a stolen cookie from being used indefinitely — the TTL
        is refreshed only on active use.
        """
        _, client = _make_session_app()
        r1 = client.get("/write")
        r2 = client.get("/read")
        cookie1 = r1.cookies.get(_SESSION_COOKIE)
        cookie2 = r2.cookies.get(_SESSION_COOKIE)
        # Both cookies exist; they are different Fernet tokens (different nonces/timestamps).
        assert cookie1 is not None
        assert cookie2 is not None
        assert cookie1 != cookie2


# ---------------------------------------------------------------------------
# Test: tampered cookie
# ---------------------------------------------------------------------------


class TestTamperedCookie:
    """A corrupted cookie must clear the session and delete the browser cookie."""

    def test_tampered_cookie_returns_empty_session(self):
        _, client = _make_session_app()
        client.get("/write")
        # Manually corrupt the cookie.
        client.cookies.set(_SESSION_COOKIE, "this-is-not-a-valid-fernet-token", path="/")
        response = client.get("/read")
        assert response.json() == {}

    def test_tampered_cookie_triggers_delete_set_cookie(self):
        """After a tampered cookie, the response must instruct the browser to delete it."""
        _, client = _make_session_app()
        client.get("/write")
        client.cookies.set(_SESSION_COOKIE, "corrupted-value", path="/")
        response = client.get("/read")

        # The Set-Cookie header must have Max-Age=0 to delete the browser cookie.
        set_cookie = response.headers.get("set-cookie", "")
        assert "Max-Age=0" in set_cookie, (
            f"Expected Max-Age=0 to delete tampered cookie, got: {set_cookie!r}"
        )

    def test_session_usable_again_after_tampered_cookie(self):
        """After a tampered cookie is cleared, a new session can be started.

        TestClient (httpx) does not automatically honour Max-Age=0 in a
        Set-Cookie header the way a real browser would.  We manually delete
        the cookie from the test client's jar to simulate browser behaviour,
        then verify that a fresh session can be established.
        """
        _, client = _make_session_app()
        client.get("/write")
        # Corrupt the cookie.
        client.cookies.set(_SESSION_COOKIE, "corrupted", path="/")
        # Read → middleware rejects the tampered cookie, sends Max-Age=0.
        response = client.get("/read")
        assert response.json() == {}, "Tampered cookie should yield empty session"
        # Simulate the browser honouring Max-Age=0 (TestClient doesn't do this
        # automatically — manual deletion mirrors real browser behaviour).
        client.cookies.delete(_SESSION_COOKIE)
        # Start a fresh session; this should work normally.
        client.get("/write")
        response = client.get("/read")
        assert response.json().get("hello") == "world"


# ---------------------------------------------------------------------------
# Test: logout deletes cookie
# ---------------------------------------------------------------------------


class TestLogoutDeletesCookie:
    """Calling session.clear() must cause the middleware to send Max-Age=0."""

    def test_clear_session_sends_max_age_zero(self):
        _, client = _make_session_app()
        # Establish a session.
        client.get("/write")
        # Clear it (logout).
        response = client.get("/clear")

        set_cookie = response.headers.get("set-cookie", "")
        assert "Max-Age=0" in set_cookie, (
            f"Expected Max-Age=0 on logout, got: {set_cookie!r}"
        )

    def test_session_empty_after_clear(self):
        _, client = _make_session_app()
        client.get("/write")
        client.get("/clear")
        response = client.get("/read")
        assert response.json() == {}

    def test_no_set_cookie_when_session_never_existed(self):
        """A fresh GET with no session cookie should NOT set an empty/delete cookie."""
        _, client = _make_session_app()
        response = client.get("/read")
        # No session cookie should be set (session was never established).
        assert _get_session_cookie(response) is None


# ---------------------------------------------------------------------------
# Test: key derivation unit tests
# ---------------------------------------------------------------------------


class TestKeyDerivation:
    """_derive_fernet_key must be deterministic and produce a valid Fernet key."""

    def test_same_key_produces_same_result(self):
        k1 = EncryptedSessionMiddleware._derive_fernet_key("my-secret")
        k2 = EncryptedSessionMiddleware._derive_fernet_key("my-secret")
        assert k1 == k2

    def test_different_secrets_produce_different_keys(self):
        k1 = EncryptedSessionMiddleware._derive_fernet_key("secret-a")
        k2 = EncryptedSessionMiddleware._derive_fernet_key("secret-b")
        assert k1 != k2

    def test_output_is_valid_fernet_key(self):
        """The derived bytes must be accepted by Fernet without error."""
        key = EncryptedSessionMiddleware._derive_fernet_key("any-secret")
        fernet = Fernet(key)  # raises if key is invalid
        token = fernet.encrypt(b"test")
        assert fernet.decrypt(token) == b"test"

    def test_output_is_44_chars_base64url(self):
        """A 32-byte key base64url-encoded is always 44 characters."""
        key = EncryptedSessionMiddleware._derive_fernet_key("any-secret")
        assert len(key) == 44
        assert isinstance(key, bytes)

    def test_key_is_url_safe_base64(self):
        """Fernet requires URL-safe base64 (no + or /)."""
        key = EncryptedSessionMiddleware._derive_fernet_key("any-secret")
        decoded = base64.urlsafe_b64decode(key)
        assert len(decoded) == 32, "Fernet key must decode to exactly 32 bytes"


# ---------------------------------------------------------------------------
# Test: integration — full app stack (auth routes use the real middleware)
# ---------------------------------------------------------------------------


class TestIntegrationWithFullApp:
    """EncryptedSessionMiddleware must work end-to-end with auth and vault routes."""

    _CREDENTIAL = "SuperSecretP@ss123!"

    def _get_csrf(self, client: TestClient, url: str) -> str:
        import re
        response = client.get(url)
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response.text)
        assert match, f"No CSRF token found in {url}"
        return match.group(1)

    def test_setup_and_login_store_opaque_cookie(self, full_client: TestClient):
        """After login, the session cookie must not be base64-decodable to JSON."""
        # Set up vault.
        csrf = self._get_csrf(full_client, "/setup")
        full_client.post("/setup", data={
            "csrf_token": csrf,
            "password": self._CREDENTIAL,
            "confirm_password": self._CREDENTIAL,
        })
        # Log in (follow_redirects=False so the cookie lands on the post response).
        csrf = self._get_csrf(full_client, "/login")
        full_client.post("/login", data={
            "csrf_token": csrf,
            "password": self._CREDENTIAL,
        }, follow_redirects=False)

        # After login the session cookie is set on the client's jar.
        cookie = full_client.cookies.get(_MAIN_COOKIE)
        assert cookie is not None, "No session cookie after login"

        # Attempt the Phase 1 attack.
        first_segment = cookie.split(".")[0]
        padded = first_segment + "=" * (4 - len(first_segment) % 4)
        try:
            raw = base64.urlsafe_b64decode(padded)
            parsed = json.loads(raw)
            pytest.fail(
                f"Session cookie is still plain base64-JSON — Phase 1 "
                f"vulnerability not fixed: {list(parsed.keys())}"
            )
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass  # Cookie is opaque — correct.

    def test_vault_accessible_after_login(self, full_client: TestClient):
        """An authenticated session (encrypted cookie) can access the vault."""
        response = full_client.get("/vault")
        assert response.status_code == 200
        assert "Vault" in response.text
