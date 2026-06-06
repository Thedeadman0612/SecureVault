"""
app/tests/conftest.py

Shared pytest fixtures that apply to the entire test suite.

login_tracker_reset (autouse)
------------------------------
Resets the main app's login-attempt tracker before every test function.

Without this, tests that make multiple wrong-password POST /login requests
(test_wrong_password_returns_401, test_failed_login_does_not_set_session, etc.)
would accumulate failures in the shared in-memory tracker and eventually
lock out the loopback IP used by TestClient — causing unrelated tests that
need a successful login to receive 429 instead of 303.

The tracker is stored on app.state.login_tracker in main.py specifically to
allow this reset without reaching into middleware internals.
"""

import pytest

from app.main import app


@pytest.fixture(autouse=True)
def login_tracker_reset() -> None:
    """Reset the login rate-limit tracker before every test."""
    app.state.login_tracker.reset_all()
