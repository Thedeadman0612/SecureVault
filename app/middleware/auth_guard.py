"""
app/middleware/auth_guard.py

Starlette middleware that enforces authentication on every request.

Every inbound request is checked for a valid session before it reaches a
route handler. If `encryption_key` is absent from the session the request
is redirected to /login — no route handler is invoked.

EXEMPT PATHS (allowed without a session):
  Exact matches:  /login, /setup
  Prefix matches: /static/

These match both GET and POST on the same path since HTML forms can only
submit to the page they're on, and the auth routes self-redirect when the
session is already active (preventing authenticated users from seeing the
login/setup pages).

MIDDLEWARE ORDER IN main.py:
  SessionMiddleware must run BEFORE AuthGuard so the session dict is
  populated before we inspect it. In FastAPI/Starlette, the last middleware
  added with add_middleware() is the outermost (runs first on the way in).
  Therefore:
    app.add_middleware(AuthGuard)              # innermost — runs second
    app.add_middleware(SessionMiddleware, ...) # outermost — runs first

  Reading session["encryption_key"] in AuthGuard is only safe because
  SessionMiddleware has already decoded the signed cookie by the time
  AuthGuard.dispatch() is called.
"""

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

logger = logging.getLogger(__name__)

# Paths that do not require an active session.
_EXEMPT_EXACT: frozenset[str] = frozenset({"/login", "/setup"})
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

    async def dispatch(self, request: Request, call_next) -> Response:
        path: str = request.url.path

        # Pass exempt paths straight through — no session check needed.
        if path in _EXEMPT_EXACT or any(path.startswith(p) for p in _EXEMPT_PREFIXES):
            return await call_next(request)

        # For all other paths, require an active session.
        if not request.session.get("encryption_key"):
            logger.debug(
                "Unauthenticated request to %s — redirecting to /login.", path
            )
            return RedirectResponse(url=_LOGIN_URL, status_code=302)

        response = await call_next(request)
        # Prevent browsers from caching authenticated pages. Without this,
        # a cached /entry/{id} page could reveal decrypted passwords to
        # anyone who presses Back after the session has ended.
        response.headers["Cache-Control"] = "no-store"
        return response
