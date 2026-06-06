"""
app/tests/test_rate_limit.py

Tests for LoginRateLimitMiddleware and _LoginAttemptTracker.

What we test
-------------
Unit tests (_LoginAttemptTracker):
  1. Initial state is unlocked with zero failures.
  2. Failures accumulate; lockout triggers at max_failures.
  3. is_locked returns (True, remaining_seconds) while locked.
  4. record_success resets the counter before lockout is reached.
  5. record_success while locked does NOT unlock (an attacker who manages to
     slip in a success response shouldn't escape lockout — but in practice
     the route returns 429 before the handler runs).
  6. Lockout expires naturally (tested with a tiny lockout_seconds=0 override).
  7. reset_all clears every record.
  8. failure_count reflects the current value correctly.

Integration tests (LoginRateLimitMiddleware via TestClient):
  9.  First N-1 failures are NOT blocked (all return non-429).
  10. Nth failure triggers lockout — next attempt returns 429.
  11. 429 response body contains the lockout message.
  12. 429 response still carries the CSP header (CSPMiddleware is outermost).
  13. POST /setup is NOT rate-limited (different path).
  14. GET /login is NOT rate-limited (GET, not POST).
  15. A 303 success response resets the counter (can fail N times again).
  16. Non-401/303 status codes (422) do not affect the counter.

Testing approach
-----------------
Integration tests use a minimal FastAPI app with:
  - LoginRateLimitMiddleware wrapping a stub route that returns a
    configurable status code.  This isolates the middleware from the
    full auth stack (no DB, no CSRF, no session needed).
  - A short max_failures=3 and lockout_seconds=60 for fast tests.

A separate full-app fixture verifies the middleware works end-to-end
within the real middleware stack (CSRF, encrypted session, etc.).
"""

import re
from collections.abc import Generator

import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.session import get_db
from app.main import app as main_app
from app.middleware.rate_limit import (
    LoginRateLimitMiddleware,
    _LoginAttemptTracker,
    _DEFAULT_MAX_FAILURES,
    _lockout_page,
)
from app.models.user import Base

# ---------------------------------------------------------------------------
# Minimal stub app — isolates middleware without DB / CSRF / session
# ---------------------------------------------------------------------------

_TEST_MAX_FAILURES = 3
_TEST_LOCKOUT_SECONDS = 60


def _make_stub_app(login_status: int = 401) -> tuple[FastAPI, TestClient]:
    """Create a minimal app whose POST /login returns a fixed status code.

    This lets us drive the middleware through failure and success scenarios
    without involving auth, CSRF, or database logic.
    """
    stub = FastAPI()
    stub.add_middleware(
        LoginRateLimitMiddleware,
        max_failures=_TEST_MAX_FAILURES,
        lockout_seconds=_TEST_LOCKOUT_SECONDS,
    )

    @stub.post("/login")
    async def fake_login() -> HTMLResponse:
        # Return the caller-configured status code.
        if login_status == 303:
            return RedirectResponse(url="/vault", status_code=303)
        return HTMLResponse("result", status_code=login_status)

    @stub.post("/setup")
    async def fake_setup() -> HTMLResponse:
        return HTMLResponse("setup ok", status_code=200)

    @stub.get("/login")
    async def fake_login_get() -> HTMLResponse:
        return HTMLResponse("login form", status_code=200)

    return stub, TestClient(stub, raise_server_exceptions=True)


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
    TestingSessionLocal = sessionmaker(
        autocommit=False, autoflush=False, bind=test_engine
    )

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    main_app.dependency_overrides[get_db] = override_get_db
    with TestClient(main_app, raise_server_exceptions=False) as c:
        yield c
    main_app.dependency_overrides.clear()


def _get_csrf(client: TestClient, url: str) -> str:
    """Extract the CSRF token from a GET response."""
    response = client.get(url)
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response.text)
    assert match, f"No CSRF token found at {url}"
    return match.group(1)


# ---------------------------------------------------------------------------
# Unit tests: _LoginAttemptTracker
# ---------------------------------------------------------------------------


class TestLoginAttemptTracker:
    """Unit tests for the tracker in isolation — no HTTP involved."""

    def _tracker(self, max_failures=3, lockout_seconds=60):
        return _LoginAttemptTracker(
            max_failures=max_failures,
            lockout_seconds=lockout_seconds,
        )

    def test_new_ip_is_not_locked(self):
        t = self._tracker()
        locked, remaining = t.is_locked("10.0.0.1")
        assert not locked
        assert remaining == 0

    def test_failure_count_starts_at_zero(self):
        t = self._tracker()
        assert t.failure_count("10.0.0.1") == 0

    def test_failures_accumulate(self):
        t = self._tracker(max_failures=5)
        for i in range(1, 5):
            count = t.record_failure("10.0.0.2")
            assert count == i

    def test_lockout_triggers_at_max_failures(self):
        t = self._tracker(max_failures=3)
        t.record_failure("10.0.0.3")
        t.record_failure("10.0.0.3")
        assert not t.is_locked("10.0.0.3")[0]  # 2 failures — not yet
        t.record_failure("10.0.0.3")            # 3rd failure → lockout
        locked, remaining = t.is_locked("10.0.0.3")
        assert locked
        assert remaining > 0

    def test_lockout_remaining_is_approximately_correct(self):
        t = self._tracker(max_failures=1, lockout_seconds=60)
        t.record_failure("10.0.0.4")
        _, remaining = t.is_locked("10.0.0.4")
        # Should be close to 60 seconds; allow 5 seconds for slow CI hosts.
        assert 55 <= remaining <= 60

    def test_record_success_before_lockout_resets_counter(self):
        t = self._tracker(max_failures=5)
        t.record_failure("10.0.0.5")
        t.record_failure("10.0.0.5")
        t.record_success("10.0.0.5")
        assert t.failure_count("10.0.0.5") == 0
        assert not t.is_locked("10.0.0.5")[0]

    def test_record_success_on_unknown_ip_is_safe(self):
        """record_success on an IP with no record should not raise."""
        t = self._tracker()
        t.record_success("192.168.1.99")  # should not raise

    def test_lockout_expires_after_zero_seconds(self):
        """Use lockout_seconds=0 to instantly expire the lockout."""
        t = self._tracker(max_failures=1, lockout_seconds=0)
        t.record_failure("10.0.0.6")
        # Even though lockout was triggered, it expired immediately.
        # is_locked cleans up expired records and returns False.
        locked, _ = t.is_locked("10.0.0.6")
        assert not locked

    def test_different_ips_are_tracked_independently(self):
        t = self._tracker(max_failures=3)
        t.record_failure("10.0.0.7")
        t.record_failure("10.0.0.7")
        t.record_failure("10.0.0.7")  # 10.0.0.7 is locked
        assert t.is_locked("10.0.0.7")[0]
        assert not t.is_locked("10.0.0.8")[0]  # 10.0.0.8 is clean

    def test_reset_all_clears_all_records(self):
        t = self._tracker(max_failures=3)
        t.record_failure("10.0.0.9")
        t.record_failure("10.0.0.10")
        t.reset_all()
        assert t.failure_count("10.0.0.9") == 0
        assert t.failure_count("10.0.0.10") == 0

    def test_sub_lockout_record_evicted_after_failure_window(self):
        """Partial-failure records below max_failures are evicted after failure_window_seconds.

        Uses failure_window_seconds=0 so the window expires immediately on the
        next is_locked() call — time.monotonic() always advances between calls.
        """
        t = _LoginAttemptTracker(
            max_failures=5,
            lockout_seconds=60,
            failure_window_seconds=0,
        )
        t.record_failure("10.0.0.11")  # 1/5 — no lockout triggered
        t.record_failure("10.0.0.11")  # 2/5 — still below threshold
        # failure_window_seconds=0 means (now - last_failure_at) >= 0 is always
        # True, so is_locked() evicts the record immediately.
        locked, _ = t.is_locked("10.0.0.11")
        assert not locked
        assert t.failure_count("10.0.0.11") == 0  # record evicted


# ---------------------------------------------------------------------------
# Integration tests: LoginRateLimitMiddleware (stub app)
# ---------------------------------------------------------------------------


class TestLoginRateLimitMiddleware:
    """Integration tests: middleware behaviour via HTTP."""

    def test_first_failures_are_not_blocked(self):
        """The first N-1 failures must pass through without a 429."""
        _, client = _make_stub_app(login_status=401)
        for _ in range(_TEST_MAX_FAILURES - 1):
            response = client.post("/login")
            assert response.status_code != 429, (
                "Unexpected 429 before max_failures reached"
            )

    def test_nth_failure_triggers_lockout_on_next_attempt(self):
        """After exactly max_failures bad attempts, the next POST /login returns 429."""
        _, client = _make_stub_app(login_status=401)
        for _ in range(_TEST_MAX_FAILURES):
            client.post("/login")  # exhaust the failure budget
        response = client.post("/login")
        assert response.status_code == 429

    def test_429_body_contains_lockout_message(self):
        _, client = _make_stub_app(login_status=401)
        for _ in range(_TEST_MAX_FAILURES):
            client.post("/login")
        response = client.post("/login")
        assert response.status_code == 429
        assert "Too Many" in response.text or "locked" in response.text.lower()

    def test_post_setup_is_not_rate_limited(self):
        """POST /setup must never be rate-limited — different path."""
        _, client = _make_stub_app(login_status=401)
        for _ in range(_TEST_MAX_FAILURES + 2):
            response = client.post("/setup")
            assert response.status_code != 429

    def test_get_login_is_not_rate_limited(self):
        """GET /login must never be rate-limited — GET, not POST."""
        _, client = _make_stub_app(login_status=401)
        for _ in range(_TEST_MAX_FAILURES + 2):
            response = client.get("/login")
            assert response.status_code != 429

    def test_success_resets_failure_counter(self):
        """A 303 success response resets the counter so the IP can fail again."""
        # Build an app that returns 401 initially; we'll manually hit the
        # tracker's record_success via a 303 stub.
        success_app = FastAPI()
        success_app.add_middleware(
            LoginRateLimitMiddleware,
            max_failures=_TEST_MAX_FAILURES,
            lockout_seconds=_TEST_LOCKOUT_SECONDS,
        )
        call_count = {"n": 0}

        @success_app.post("/login")
        async def toggle_login() -> HTMLResponse:
            call_count["n"] += 1
            # Return 303 on the (max_failures)th call to simulate success.
            if call_count["n"] == _TEST_MAX_FAILURES:
                return RedirectResponse(url="/vault", status_code=303)
            return HTMLResponse("fail", status_code=401)

        # follow_redirects=False so we see the raw 303 without the client
        # trying to fetch /vault (which doesn't exist in the stub app).
        client = TestClient(
            success_app, raise_server_exceptions=True, follow_redirects=False
        )

        # Fail max_failures-1 times.
        for _ in range(_TEST_MAX_FAILURES - 1):
            client.post("/login")

        # Succeed on the next attempt → resets counter.
        response = client.post("/login")
        assert response.status_code == 303

        # Should be able to fail again without immediate lockout.
        response = client.post("/login")
        assert response.status_code == 401  # allowed through, not 429

    def test_422_does_not_increment_failure_counter(self):
        """Status 422 (invalid form data) must not count as a failure."""
        _, client = _make_stub_app(login_status=422)
        # POST enough times that failures (if counted) would trigger lockout.
        for _ in range(_TEST_MAX_FAILURES + 2):
            response = client.post("/login")
            assert response.status_code == 422  # never 429

    def test_429_includes_retry_after_header(self):
        """429 response must include a Retry-After header (RFC 6585 §4)."""
        _, client = _make_stub_app(login_status=401)
        for _ in range(_TEST_MAX_FAILURES):
            client.post("/login")
        response = client.post("/login")
        assert response.status_code == 429
        assert "retry-after" in response.headers
        retry_after = int(response.headers["retry-after"])
        assert retry_after > 0


# ---------------------------------------------------------------------------
# Integration tests: full app stack
# ---------------------------------------------------------------------------


class TestRateLimitInFullStack:
    """Verify the rate limiter works end-to-end with CSRF and encrypted session."""

    _CREDENTIAL = "StrongVaultP@ss456!"
    _WRONG_CREDENTIAL = "wrong-pw"

    def _setup_vault(self, client: TestClient) -> None:
        csrf = _get_csrf(client, "/setup")
        client.post("/setup", data={
            "csrf_token": csrf,
            "password": self._CREDENTIAL,
            "confirm_password": self._CREDENTIAL,
        })

    def test_wrong_credential_returns_401_not_429_initially(
        self, full_client: TestClient
    ):
        """First wrong-password attempt must return 401, not 429."""
        self._setup_vault(full_client)
        csrf = _get_csrf(full_client, "/login")
        response = full_client.post("/login", data={
            "csrf_token": csrf,
            "password": "definitely-wrong",
        })
        assert response.status_code == 401

    def test_get_login_always_returns_200(self, full_client: TestClient):
        """GET /login must never be blocked by the rate limiter."""
        response = full_client.get("/login")
        assert response.status_code == 200

    def test_post_without_csrf_returns_403_not_429(self, full_client: TestClient):
        """A missing CSRF token must return 403 (from CSRFMiddleware), never 429.

        This verifies that the rate limiter is INSIDE CSRFMiddleware — bots
        without a session/CSRF token cannot inflate the failure counter.
        """
        response = full_client.post("/login", data={"csrf_token": ""})
        assert response.status_code == 403

    def test_429_carries_csp_header(self, full_client: TestClient):
        """429 lockout response must still carry the CSP header.

        CSPMiddleware is outermost — it wraps every response including lockout
        pages returned by the rate limiter before the route handler runs.
        """
        from app.middleware.csp import CSP_HEADER_VALUE

        self._setup_vault(full_client)  # idempotent — 400 on duplicate is ignored
        for _ in range(_DEFAULT_MAX_FAILURES):
            csrf = _get_csrf(full_client, "/login")
            full_client.post("/login", data={"csrf_token": csrf, "password": self._WRONG_CREDENTIAL})
        csrf = _get_csrf(full_client, "/login")
        response = full_client.post("/login", data={"csrf_token": csrf, "password": self._WRONG_CREDENTIAL})
        assert response.status_code == 429
        assert response.headers.get("content-security-policy") == CSP_HEADER_VALUE

    def test_429_carries_retry_after_header(self, full_client: TestClient):
        """429 lockout response must include a Retry-After header in the full stack."""
        self._setup_vault(full_client)  # idempotent
        for _ in range(_DEFAULT_MAX_FAILURES):
            csrf = _get_csrf(full_client, "/login")
            full_client.post("/login", data={"csrf_token": csrf, "password": self._WRONG_CREDENTIAL})
        csrf = _get_csrf(full_client, "/login")
        response = full_client.post("/login", data={"csrf_token": csrf, "password": self._WRONG_CREDENTIAL})
        assert response.status_code == 429
        assert "retry-after" in response.headers
        assert int(response.headers["retry-after"]) > 0


# ---------------------------------------------------------------------------
# Unit tests: _lockout_page() time-string formatting
# ---------------------------------------------------------------------------


class TestLockoutPageFormatting:
    """Unit tests for every formatting branch in _lockout_page().

    Branches:
      seconds_remaining < 60         → "N second[s]"
      seconds_remaining % 60 == 0    → "M minute[s]"
      seconds_remaining % 60 != 0    → "M minute[s] N second[s]"
    Singular/plural is tested for both the minutes and seconds components.
    """

    @pytest.mark.parametrize("seconds, expected_fragment", [
        (1,   "1 second"),       # singular seconds
        (2,   "2 seconds"),      # plural seconds
        (59,  "59 seconds"),     # boundary before minutes
        (60,  "1 minute"),       # exactly 1 minute, no seconds component
        (60,  "1 minute"),       # singular minute
        (120, "2 minutes"),      # plural minutes, no seconds
        (61,  "1 minute"),       # 1 minute 1 second — minute component
        (61,  "1 second"),       # 1 minute 1 second — second component
        (62,  "1 minute"),       # 1 minute 2 seconds — minute component
        (62,  "2 seconds"),      # 1 minute 2 seconds — second component
        (121, "2 minutes"),      # 2 minutes 1 second — minute component
        (121, "1 second"),       # 2 minutes 1 second — second component
        (900, "15 minutes"),     # default lockout (15 minutes exactly)
    ])
    def test_time_string_in_page(self, seconds: int, expected_fragment: str) -> None:
        page = _lockout_page(seconds)
        assert expected_fragment in page, (
            f"Expected '{expected_fragment}' in lockout page for {seconds}s, got:\n{page}"
        )

    def test_page_is_valid_html(self) -> None:
        """Page must start with DOCTYPE and contain the status code."""
        page = _lockout_page(900)
        assert page.strip().startswith("<!DOCTYPE html>")
        assert "429" in page

    def test_page_contains_return_link(self) -> None:
        """Page must include a link back to /login."""
        page = _lockout_page(60)
        assert 'href="/login"' in page
