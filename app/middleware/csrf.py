"""
app/middleware/csrf.py

CSRF protection — Synchronizer Token Pattern.

HOW IT WORKS
------------
On every request the middleware ensures a random CSRF token exists in the
server-side session.  The token is exposed via ``request.state.csrf_token``
so Jinja2 templates can embed it as a hidden form field without any per-route
boilerplate.

On every *mutating* request (POST / PUT / PATCH / DELETE) the middleware reads
the ``csrf_token`` field from the submitted form body and compares it to the
session value using a timing-safe comparison.  A missing or mismatched token
results in an immediate 403 response — the route handler is never called.

WHY SYNCHRONIZER TOKEN (not double-submit cookie)
-------------------------------------------------
The double-submit cookie pattern stores the token in *both* a cookie and a
form field.  Because our session cookie is HttpOnly, an attacker cannot read
it via JavaScript, but they *could* set a new cookie from a subdomain in some
configurations.  Storing the authoritative token in the *session* (server-side)
removes that risk entirely: the attacker cannot read or set the session value.

WHY TOKEN IN SESSION (not per-request rotation)
-----------------------------------------------
Rotating the token on every response breaks multi-tab usage — a token obtained
in tab A is invalidated the moment tab B loads a new page.  A session-scoped
token (cleared on logout via ``session.clear()``) provides the right balance
between security and usability for a single-user local app.

MIDDLEWARE POSITION IN STACK (main.py add_middleware call order)
----------------------------------------------------------------
  app.add_middleware(AuthGuard)       # innermost  — runs last on the way in
  app.add_middleware(CSRFMiddleware)  # middle     — needs session; before auth
  app.add_middleware(SessionMiddleware, ...)  # outermost — decodes cookie first

Runs *outside* AuthGuard so that the auth-exempt paths (/login, /setup) are
also CSRF-protected.  Runs *inside* SessionMiddleware so that
``request.session`` is already populated when this middleware inspects it.
"""

import logging
import secrets
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response

logger = logging.getLogger(__name__)

# Name of the hidden form field and session key used to carry the token.
CSRF_FIELD = "csrf_token"

# Token entropy: 32 bytes = 256 bits → represented as 64 lowercase hex chars.
_TOKEN_BYTES = 32

# HTTP methods that do not mutate server state (per RFC 7231 §4.2).
# These pass through without CSRF validation.
_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})


class CSRFMiddleware(BaseHTTPMiddleware):
    """Reject mutating requests that do not carry a valid CSRF token.

    Safe to use with Starlette's SessionMiddleware — the session dict is
    populated by the outer SessionMiddleware before this middleware runs.

    Note on body caching: ``await request.form()`` is called here for POST
    requests.  Starlette caches the body bytes on the request object after the
    first read, so the route handler's ``Form(...)`` parameters still receive
    the full form data unchanged.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # ------------------------------------------------------------------
        # Step 1 — Ensure a session token exists.
        # ------------------------------------------------------------------
        token: str = request.session.get(CSRF_FIELD, "")
        if not token:
            token = secrets.token_hex(_TOKEN_BYTES)
            request.session[CSRF_FIELD] = token

        # Expose via request.state so templates can embed it without needing
        # an explicit context variable in every route handler.
        request.state.csrf_token = token

        # ------------------------------------------------------------------
        # Step 2 — Validate on mutating methods.
        # ------------------------------------------------------------------
        if request.method not in _SAFE_METHODS:
            try:
                # Call body() BEFORE form() so that Starlette's _CachedRequest
                # sets self._body on the cached-request object.  wrapped_receive()
                # (used by call_next to replay the body to downstream route
                # handlers) only replays when _body is set — if form() is called
                # directly it reads via stream(), which sets _stream_consumed but
                # NOT _body, causing wrapped_receive() to return b"" and the
                # route handler to see an empty form (→ 422 on all POSTs).
                await request.body()
                form = await request.form()
                submitted: str = str(form.get(CSRF_FIELD, ""))
            except Exception:
                submitted = ""

            if not submitted or not secrets.compare_digest(token, submitted):
                logger.warning(
                    "CSRF validation failed — method=%s path=%s "
                    "(token present: %s)",
                    request.method,
                    request.url.path,
                    bool(submitted),
                )
                return HTMLResponse(
                    content=_forbidden_page(),
                    status_code=403,
                )

        return await call_next(request)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _forbidden_page() -> str:
    """Minimal inline 403 HTML page returned on CSRF failure.

    Intentionally avoids Jinja2 — template loading could itself fail, and
    a CSRF failure page must always render.  Phase 4 can upgrade this to a
    proper template once one exists for error pages.
    """
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureVault — 403 Forbidden</title>
</head>
<body>
  <h1>403 — Forbidden</h1>
  <p>Request validation failed. Please reload the page and try again.</p>
  <a href="/">Return to vault</a>
</body>
</html>"""
