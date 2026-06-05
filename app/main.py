"""
app/main.py

FastAPI application factory: middleware stack, routers, static files, and
global error handlers.

MIDDLEWARE ORDER (outermost → innermost, i.e. request processing order):
  1. CSPMiddleware               — stamps Content-Security-Policy on every response.
                                    Outermost so it covers error pages from inner layers.
  2. EncryptedSessionMiddleware  — decrypts the session cookie (Fernet AES) into
                                    scope["session"] = request.session.  Replaced the
                                    Phase 1 signed-only SessionMiddleware in Phase 2.
  3. CSRFMiddleware              — generates/validates the CSRF token stored in session;
                                    exposes it via request.state.csrf_token for templates.
  4. AuthGuard                   — inspects request.session["encryption_key"]; redirects
                                    unauthenticated requests to /login.

  In FastAPI/Starlette, add_middleware() stacks in reverse — the LAST call
  produces the OUTERMOST layer.  Add order:

    app.add_middleware(AuthGuard)                          # added first  → innermost
    app.add_middleware(CSRFMiddleware)                     # added second → middle-inner
    app.add_middleware(EncryptedSessionMiddleware, ...)    # added third  → middle-outer
    app.add_middleware(CSPMiddleware)                      # added last   → outermost

  EncryptedSessionMiddleware sits outside CSRFMiddleware because CSRFMiddleware
  reads/writes request.session (the decrypted dict) — the session must be
  populated before CSRF inspection runs.

  CSPMiddleware is outermost because it adds a response header that must appear
  on ALL responses, including CSRF 403s and session-layer error responses.

GLOBAL ERROR HANDLERS:
  404 Not Found         — generic HTML page; no internal path or DB detail.
  500 Internal Server Error — generic HTML page; never exposes stack traces.
  These fire for any unhandled exception that escapes a route handler.

STATIC FILES:
  Mounted at /static → app/static/. Exempt from AuthGuard (prefix /static/).

ROUTERS:
  /          → app/routes/auth.py  (setup, login, logout)
  /          → app/routes/vault.py (vault dashboard, entry CRUD)
"""

import logging

from fastapi import FastAPI, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from app.config.settings import settings
from app.middleware.auth_guard import AuthGuard
from app.middleware.csrf import CSRFMiddleware
from app.middleware.csp import CSPMiddleware
from app.middleware.encrypted_session import EncryptedSessionMiddleware
from app.routes import auth, vault

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application instance
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SecureVault",
    description="Local-first encrypted credential manager.",
    # Disable the interactive docs in production to avoid exposing the API
    # surface. Re-enable during development by removing these two lines.
    docs_url=None,
    redoc_url=None,
)

# ---------------------------------------------------------------------------
# Static files
# ---------------------------------------------------------------------------

# Mounted BEFORE middleware registration so /static/* is served by the ASGI
# app's static file handler, not passed through the middleware stack.
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# ---------------------------------------------------------------------------
# Middleware stack
# (Last added = outermost = runs first on incoming requests.)
# ---------------------------------------------------------------------------

# AuthGuard — innermost; reads the session set up by SessionMiddleware.
app.add_middleware(AuthGuard)

# CSRFMiddleware — middle; needs session (set by outer SessionMiddleware);
# sits outside AuthGuard so that /login and /setup are also CSRF-protected.
app.add_middleware(CSRFMiddleware)

# EncryptedSessionMiddleware — middle-outer; ENCRYPTS (not just signs) the
# session cookie so that the vault encryption key stored in the session is
# opaque to anyone who can read the raw cookie value.
#
# Uses Fernet (AES-128-CBC + HMAC-SHA256) with a key derived from SECRET_KEY
# via HKDF-SHA256.  Replaces the Phase 1 SessionMiddleware which only signed
# the cookie with itsdangerous (payload was base64-readable without the key).
#
# Parameter meanings are identical to the old SessionMiddleware:
#   https_only: True in production; False only with ENVIRONMENT=development.
#   same_site:  "strict" — cookie never sent on any cross-site request.
app.add_middleware(
    EncryptedSessionMiddleware,
    secret_key=settings.SECRET_KEY,
    max_age=settings.SESSION_TIMEOUT_MINUTES * 60,
    session_cookie="sv_session",                           # non-default name avoids collisions
    https_only=settings.ENVIRONMENT != "development",      # False only in local dev
    same_site="strict",                                    # hardened from "lax" in Phase 2
)

# CSPMiddleware — outermost; added last so it wraps every other layer.
# Stamps Content-Security-Policy on ALL responses including CSRF/session errors.
# Needs no session data, so placement relative to SessionMiddleware is flexible.
app.add_middleware(CSPMiddleware)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(auth.router)
app.include_router(vault.router)


@app.get("/")
async def root() -> RedirectResponse:
    """Redirect the bare root URL to the vault dashboard.

    AuthGuard runs before this handler — unauthenticated requests are already
    redirected to /login before reaching here. This route only fires for
    authenticated users, sending them straight to /vault.
    """
    return RedirectResponse(url="/vault", status_code=status.HTTP_302_FOUND)

# ---------------------------------------------------------------------------
# Global error handlers
# ---------------------------------------------------------------------------

@app.exception_handler(404)
async def not_found_handler(_request: Request, _exc: Exception) -> HTMLResponse:
    """Return a generic 404 page.

    Never includes the requested path or any internal state in the response
    body — a 404 should not confirm or deny that a resource exists.
    """
    return HTMLResponse(
        content=_error_page("404 — Page Not Found", "The page you requested could not be found."),
        status_code=status.HTTP_404_NOT_FOUND,
    )


@app.exception_handler(500)
async def server_error_handler(request: Request, _exc: Exception) -> HTMLResponse:
    """Return a generic 500 page.

    Logs the exception with a full traceback for diagnostics; returns only a
    generic message to the browser — never a stack trace or internal detail.
    """
    logger.exception("Unhandled server error for request %s %s", request.method, request.url.path)
    return HTMLResponse(
        content=_error_page("500 — Server Error", "Something went wrong. Please try again later."),
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _error_page(title: str, message: str) -> str:
    """Minimal inline HTML error page.

    Phase 4 can replace this with a proper Jinja2 error template once one
    is added to app/templates/. Kept inline here to avoid a template
    dependency in the error handler itself (template loading can fail).
    """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureVault — {title}</title>
</head>
<body>
  <h1>{title}</h1>
  <p>{message}</p>
  <a href="/">Return to vault</a>
</body>
</html>"""
