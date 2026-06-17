"""
app/middleware/auth_guard.py

Starlette middleware that enforces authentication on every request.

Every inbound request is checked for a valid session before it reaches a
route handler. If `encryption_key` is absent from the session the request
is redirected to /login — no route handler is invoked.

EXEMPT PATHS (allowed without a session):
  Exact matches:  /login, /setup, /health
  Prefix matches: /static/

These match both GET and POST on the same path since HTML forms can only
submit to the page they're on, and the auth routes self-redirect when the
session is already active (preventing authenticated users from seeing the
login/setup pages).

MIDDLEWARE ORDER IN main.py:
  EncryptedSessionMiddleware must run BEFORE AuthGuard so the session dict is
  populated before we inspect it. In FastAPI/Starlette, the last middleware
  added with add_middleware() is the outermost (runs first on the way in).
  Therefore:
    app.add_middleware(AuthGuard)                       # innermost — runs second
    app.add_middleware(EncryptedSessionMiddleware, ...) # outermost — runs first

  Reading session["encryption_key"] in AuthGuard is only safe because
  EncryptedSessionMiddleware has already decrypted the Fernet-encrypted cookie
  by the time AuthGuard.dispatch() is called.
"""

import logging
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

logger = logging.getLogger(__name__)

# Paths that do not require an active session.
# /2fa/verify and /2fa/recovery are mid-login: the user has passed the
# password check (pending_user_id in session) but encryption_key is not yet
# set. The route handlers themselves validate the pending session state.
_EXEMPT_EXACT: frozenset[str] = frozenset({
    "/login",
    "/setup",
    "/2fa/verify",
    "/2fa/recovery",
    "/auth/timeout-notify",  # JS inactivity-timer notification; read-only, no state change
    "/health",  # liveness/readiness probe — no session, no auth, just DB connectivity
})
_EXEMPT_PREFIXES: tuple[str, ...] = ("/static/",)

_LOGIN_URL = "/login"


class AuthGuard(BaseHTTPMiddleware):
    """Redirect unauthenticated requests to /login.

    Checks request.session["encryption_key"] on every non-exempt request.
    The encryption key is set by auth_service.login() and cleared by
    auth_service.logout() — its presence is the single source of truth for
    whether a user is authenticated.

    This middleware does NOT verify the key's validity or integrity — that
    is the responsibility of the vault service layer when the key is used
    to decrypt entries.
    """

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        path: str = request.url.path

        # Pass exempt paths straight through — no session check needed.
        if path in _EXEMPT_EXACT or any(path.startswith(p) for p in _EXEMPT_PREFIXES):
            return await call_next(request)

        # For all other paths, require an active session.
        if not request.session.get("encryption_key"):
            # Classify why the session is absent — aids debugging in logs.
            session_keys = set(request.session.keys())
            user_id = request.session.get("user_id")

            if not session_keys or session_keys <= {"csrf_token"}:
                # Cookie was absent or expired at the Fernet layer — fresh visit
                # or the inactivity TTL elapsed between requests.
                cause = "session_expired_or_no_cookie"
            elif request.session.get("pending_user_id"):
                # Mid-login TOTP state reached a non-exempt route — misconfigured
                # exempt list or direct URL navigation during 2FA step-up.
                cause = "pending_totp"
                user_id = request.session.get("pending_user_id")
            else:
                # Session exists with unexpected keys but no encryption_key.
                cause = "session_missing_key"

            logger.info(
                "Auth guard: access denied — method=%s path=%s cause=%s user_id=%s",
                request.method, path, cause, user_id,
            )
            return RedirectResponse(url=_LOGIN_URL, status_code=302)

        response = await call_next(request)
        # Prevent browsers from caching authenticated pages. Without this,
        # a cached /entry/{id} page could reveal decrypted passwords to
        # anyone who presses Back after the session has ended.
        response.headers["Cache-Control"] = "no-store"
        return response
