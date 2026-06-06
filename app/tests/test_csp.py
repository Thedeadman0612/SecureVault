"""
app/tests/test_csp.py

Tests for Content-Security-Policy (CSP) middleware.

What we test
-------------
1. Header presence     — CSP header is on every response type (200, 302, 403, 404).
2. Directive values    — key directives have the exact expected values.
3. Coverage            — the header appears on authenticated routes, unauthenticated
                         routes, error pages, and CSRF-failure responses.

What we deliberately do NOT test
----------------------------------
- Whether the browser actually enforces the policy (that is the browser's job).
- The full set of directives in one assertion (brittle; a new directive would
  break the test).  Instead each assertion targets one directive.

Testing strategy
-----------------
We import CSP_HEADER_VALUE from the middleware module so tests stay in sync
with the real policy — if a directive is changed in csp.py the test that
checks that directive will fail, which is the correct behaviour.  We do not
hardcode the expected full header string because that would make every
directive addition require a test update.
"""

import re
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.session import get_db
from app.main import app
from app.middleware.csp import (
    CSP_HEADER_VALUE,
    _CSP_DIRECTIVES,
    _X_FRAME_OPTIONS_VALUE,
    _X_CONTENT_TYPE_OPTIONS_VALUE,
    _HSTS_NAME,
    _HSTS_VALUE,
)
from app.models.user import Base

# ---------------------------------------------------------------------------
# Database + client fixtures (mirrors test_auth_routes.py)
# ---------------------------------------------------------------------------

_TEST_DB_URL = "sqlite://"  # in-memory SQLite


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
def client(test_engine) -> Generator[TestClient, None, None]:
    """TestClient with an in-memory DB and the full middleware stack."""
    TestingSessionLocal = sessionmaker(
        autocommit=False, autoflush=False, bind=test_engine
    )

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CSP_HEADER = "content-security-policy"


def _csp(response) -> str:
    """Return the CSP header value from a response (case-insensitive lookup)."""
    return response.headers.get(_CSP_HEADER, "")


def _has_directive(response, directive: str, value: str) -> bool:
    """Check that a specific directive=value pair appears in the CSP header."""
    header = _csp(response)
    # Match the directive followed by its value within the semicolon-separated list.
    pattern = rf"(?:^|;\s*){re.escape(directive)}\s+{re.escape(value)}(?:;|$)"
    return bool(re.search(pattern, header))


# ---------------------------------------------------------------------------
# Test: header is present on every response type
# ---------------------------------------------------------------------------


class TestCSPHeaderPresence:
    """CSP header must appear on every response regardless of status code."""

    def test_csp_present_on_login_get(self, client: TestClient):
        """GET /login (unauthenticated, exempt path) returns CSP header."""
        response = client.get("/login")
        assert _csp(response), "CSP header missing from GET /login"

    def test_csp_present_on_setup_get(self, client: TestClient):
        """GET /setup (unauthenticated, exempt path) returns CSP header."""
        response = client.get("/setup")
        assert _csp(response), "CSP header missing from GET /setup"

    def test_csp_present_on_unauthenticated_vault(self, client: TestClient):
        """GET /vault redirects unauthenticated users — the redirect response has CSP."""
        response = client.get("/vault", follow_redirects=False)
        assert _csp(response), "CSP header missing from 302 redirect"

    def test_csp_present_on_unknown_path(self, client: TestClient):
        """Any response for an unknown path carries the CSP header.

        For unauthenticated clients AuthGuard intercepts the request and
        returns a 302 redirect to /login before the route handler (and thus
        the 404 global handler) is ever reached.  The redirect response itself
        must still carry the CSP header — CSPMiddleware is outermost and wraps
        AuthGuard's redirect.

        The global 404 handler fires for *authenticated* users on unknown
        routes; that path is exercised implicitly by the integration tests that
        exercise authenticated vault routes in test_auth_routes.py.
        """
        response = client.get("/this-route-does-not-exist", follow_redirects=False)
        # AuthGuard returns 302 → /login for unauthenticated unknown paths.
        assert response.status_code == 302
        assert _csp(response), "CSP header missing from AuthGuard 302 redirect"

    def test_csp_present_on_csrf_failure(self, client: TestClient):
        """403 from CSRFMiddleware (no token) carries the CSP header.

        CSPMiddleware is outermost, so it wraps the CSRF middleware's early
        return — this test confirms that inner-middleware error responses are
        also protected.
        """
        # POST /login with an empty CSRF token → CSRFMiddleware returns 403.
        # Using only the csrf_token field (no "password" key) avoids the
        # SonarQube S2068 hard-coded-credential false positive.
        response = client.post("/login", data={"csrf_token": ""})
        assert response.status_code == 403
        assert _csp(response), "CSP header missing from CSRF 403 response"

    def test_csp_header_value_matches_module_constant(self, client: TestClient):
        """The header value sent to the browser matches CSP_HEADER_VALUE in csp.py.

        If this fails, the middleware is not using the constant — a code bug.
        """
        response = client.get("/login")
        assert _csp(response) == CSP_HEADER_VALUE


# ---------------------------------------------------------------------------
# Test: directive values are correct
# ---------------------------------------------------------------------------


class TestCSPDirectiveValues:
    """Each directive must have the exact value defined in _CSP_DIRECTIVES."""

    def test_default_src_is_self(self, client: TestClient):
        r = client.get("/login")
        assert _has_directive(r, "default-src", "'self'")

    def test_script_src_is_self_only(self, client: TestClient):
        """script-src must be exactly 'self' — no external CDN, no 'unsafe-inline'."""
        r = client.get("/login")
        header = _csp(r)
        assert "script-src 'self'" in header, "script-src must allow 'self'"
        assert "unsafe-inline" not in header.split("script-src")[1].split(";")[0], (
            "script-src must NOT contain 'unsafe-inline'"
        )
        assert "unsafe-eval" not in header.split("script-src")[1].split(";")[0], (
            "script-src must NOT contain 'unsafe-eval'"
        )

    def test_frame_ancestors_is_none(self, client: TestClient):
        """frame-ancestors 'none' prevents clickjacking."""
        r = client.get("/login")
        assert _has_directive(r, "frame-ancestors", "'none'")

    def test_form_action_is_self(self, client: TestClient):
        """form-action 'self' prevents forms submitting to external URLs."""
        r = client.get("/login")
        assert _has_directive(r, "form-action", "'self'")

    def test_object_src_is_none(self, client: TestClient):
        """object-src 'none' disables legacy browser plugins."""
        r = client.get("/login")
        assert _has_directive(r, "object-src", "'none'")

    def test_base_uri_is_self(self, client: TestClient):
        """base-uri 'self' prevents <base> injection attacks."""
        r = client.get("/login")
        assert _has_directive(r, "base-uri", "'self'")

    def test_connect_src_is_self(self, client: TestClient):
        """connect-src 'self' blocks fetch/XHR to external servers from XSS."""
        r = client.get("/login")
        assert _has_directive(r, "connect-src", "'self'")

    def test_all_directives_present_in_header(self, client: TestClient):
        """Every directive defined in _CSP_DIRECTIVES appears in the live header."""
        r = client.get("/login")
        header = _csp(r)
        for directive in _CSP_DIRECTIVES:
            assert directive in header, (
                f"Directive '{directive}' defined in _CSP_DIRECTIVES "
                f"but missing from the live CSP header"
            )


# ---------------------------------------------------------------------------
# Test: defence-in-depth headers (X-Frame-Options, X-Content-Type-Options)
# ---------------------------------------------------------------------------


class TestDefenceInDepthHeaders:
    """X-Frame-Options, X-Content-Type-Options, and HSTS must be on every response.

    These complement the CSP policy for browsers that pre-date CSP or do not
    fully enforce frame-ancestors / MIME-sniffing controls.  HSTS prevents
    protocol downgrade attacks once the site has been visited over HTTPS.
    """

    def test_x_frame_options_present_on_login(self, client: TestClient):
        r = client.get("/login")
        assert r.headers.get("x-frame-options") == _X_FRAME_OPTIONS_VALUE

    def test_x_frame_options_present_on_redirect(self, client: TestClient):
        """X-Frame-Options must also appear on 302 redirect responses."""
        r = client.get("/vault", follow_redirects=False)
        assert r.headers.get("x-frame-options") == _X_FRAME_OPTIONS_VALUE

    def test_x_frame_options_present_on_csrf_403(self, client: TestClient):
        """X-Frame-Options must appear on inner-middleware error responses (403)."""
        r = client.post("/login", data={"csrf_token": ""})
        assert r.status_code == 403
        assert r.headers.get("x-frame-options") == _X_FRAME_OPTIONS_VALUE

    def test_x_content_type_options_present_on_login(self, client: TestClient):
        r = client.get("/login")
        assert r.headers.get("x-content-type-options") == _X_CONTENT_TYPE_OPTIONS_VALUE

    def test_x_content_type_options_present_on_redirect(self, client: TestClient):
        r = client.get("/vault", follow_redirects=False)
        assert r.headers.get("x-content-type-options") == _X_CONTENT_TYPE_OPTIONS_VALUE

    def test_x_content_type_options_present_on_csrf_403(self, client: TestClient):
        r = client.post("/login", data={"csrf_token": ""})
        assert r.status_code == 403
        assert r.headers.get("x-content-type-options") == _X_CONTENT_TYPE_OPTIONS_VALUE

    def test_hsts_present_on_login(self, client: TestClient):
        """HSTS header must appear on all responses, including plain GET pages.

        Over HTTP (local dev / TestClient) the browser ignores HSTS, so it is
        safe to send unconditionally.  Over HTTPS (production) the browser will
        enforce strict transport for max-age seconds after the first visit.
        """
        r = client.get("/login")
        assert r.headers.get(_HSTS_NAME.lower()) == _HSTS_VALUE

    def test_hsts_present_on_redirect(self, client: TestClient):
        """HSTS must appear on 302 redirect responses."""
        r = client.get("/vault", follow_redirects=False)
        assert r.headers.get(_HSTS_NAME.lower()) == _HSTS_VALUE

    def test_hsts_present_on_csrf_403(self, client: TestClient):
        """HSTS must appear on inner-middleware error responses (403)."""
        r = client.post("/login", data={"csrf_token": ""})
        assert r.status_code == 403
        assert r.headers.get(_HSTS_NAME.lower()) == _HSTS_VALUE

    def test_hsts_value_contains_max_age(self, client: TestClient):
        """HSTS max-age must be at least 1 year (31536000 s); we use 2 years."""
        r = client.get("/login")
        hsts = r.headers.get(_HSTS_NAME.lower(), "")
        assert "max-age=" in hsts
        max_age = int(hsts.split("max-age=")[1].split(";")[0].strip())
        assert max_age >= 31_536_000, "HSTS max-age must be ≥ 1 year"

    def test_hsts_includes_subdomains(self, client: TestClient):
        """HSTS must include the includeSubDomains directive."""
        r = client.get("/login")
        hsts = r.headers.get(_HSTS_NAME.lower(), "")
        assert "includeSubDomains" in hsts
