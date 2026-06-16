"""
app/main.py

FastAPI application factory: middleware stack, routers, static files, and
global error handlers.

MIDDLEWARE ORDER (outermost → innermost, i.e. request processing order):
  1. CSPMiddleware               — stamps Content-Security-Policy on every response.
                                    Outermost so it covers error pages from all inner layers.
  2. EncryptedSessionMiddleware  — decrypts the Fernet-encrypted session cookie into
                                    scope["session"] = request.session.
  3. CSRFMiddleware              — validates the CSRF token stored in the session;
                                    exposes request.state.csrf_token for templates.
  4. LoginRateLimitMiddleware    — enforces a failed-attempt lockout on POST /login.
                                    Sits INSIDE CSRFMiddleware so only CSRF-validated
                                    requests count as genuine password attempts.
  5. AuthGuard                   — checks request.session["encryption_key"]; redirects
                                    unauthenticated requests to /login.

  In FastAPI/Starlette, add_middleware() stacks in reverse — the LAST call
  produces the OUTERMOST layer.  Add order:

    app.add_middleware(AuthGuard)                          # added first  → innermost
    app.add_middleware(LoginRateLimitMiddleware)           # added second → inside CSRF
    app.add_middleware(CSRFMiddleware)                     # added third  → outside LRL
    app.add_middleware(EncryptedSessionMiddleware, ...)    # added fourth → middle-outer
    app.add_middleware(CSPMiddleware)                      # added last   → outermost

  LoginRateLimitMiddleware inside CSRFMiddleware ensures bots without valid
  CSRF tokens get a 403 and never inflate the failure counter.  429 lockout
  responses still receive the CSP header (CSPMiddleware wraps everything).

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

import html
import logging
import logging.handlers
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from app.config.settings import settings
from app.middleware.auth_guard import AuthGuard
from app.middleware.csrf import CSRFMiddleware
from app.middleware.csp import CSPMiddleware
from app.middleware.encrypted_session import EncryptedSessionMiddleware
from app.middleware.rate_limit import LoginRateLimitMiddleware, _LoginAttemptTracker
from app.routes import auth, vault


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
# Configures the root logger once at import time.
#
# Two handlers:
#   stderr  — always active; uvicorn shows this in the terminal during dev.
#   file    — rotating log at logs/app.log (10 MB × 5 backups ≈ 50 MB cap).
#             Created here so all app loggers (rate_limit, csrf, vault, etc.)
#             write to the same file automatically via the root logger.
#
# Format includes timestamp, level, logger name, and message so log lines are
# self-contained when tailing the file:
#   2024-06-06 14:32:01,123 WARNING  app.middleware.rate_limit — Login lockout triggered …
#
# Phase 5.4 adds a dedicated security-audit stream (securevault.audit logger)
# writing structured JSON to logs/audit.log, separate from debug output.

_LOG_DIR = Path(__file__).parent.parent / "logs"
_LOG_DIR.mkdir(exist_ok=True)

_LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s — %(message)s"
_LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"

# Root-logger level: DEBUG in development, INFO in production.
_root_level = logging.DEBUG if settings.ENVIRONMENT == "development" else logging.INFO

logging.basicConfig(
    level=_root_level,
    format=_LOG_FORMAT,
    datefmt=_LOG_DATEFMT,
    handlers=[
        # Terminal output (uvicorn / stdout).
        logging.StreamHandler(),
        # Rotating file: 10 MB per file, keep last 5 rotations.
        logging.handlers.RotatingFileHandler(
            _LOG_DIR / "app.log",
            maxBytes=10 * 1024 * 1024,   # 10 MB
            backupCount=5,
            encoding="utf-8",
        ),
    ],
)

# Suppress noisy third-party loggers that flood the file with irrelevant lines.
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("watchfiles").setLevel(logging.WARNING)
# python-multipart fires DEBUG lines for every byte-range of every form field
# (e.g. "on_field_data with data[176:193]") — useless for app debugging and
# mildly sensitive (annotates byte positions of form fields including passwords).
logging.getLogger("python_multipart").setLevel(logging.WARNING)

# Security audit logger — writes structured JSON to logs/audit.log, separate
# from app.log. propagate=False keeps audit records out of app.log (no double-
# logging). The %(message)s-only formatter yields pure JSON lines, one per event.
_audit_handler = logging.handlers.RotatingFileHandler(
    _LOG_DIR / "audit.log",
    maxBytes=10 * 1024 * 1024,   # 10 MB
    backupCount=10,
    encoding="utf-8",
)
_audit_handler.setFormatter(logging.Formatter("%(message)s"))
_audit_logger = logging.getLogger("securevault.audit")
_audit_logger.addHandler(_audit_handler)
_audit_logger.setLevel(logging.INFO)
_audit_logger.propagate = False

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

# AuthGuard — innermost; reads the session populated by EncryptedSessionMiddleware.
app.add_middleware(AuthGuard)

# LoginRateLimitMiddleware — inside CSRFMiddleware so only CSRF-validated
# requests (i.e. genuine password attempts) count toward the failure limit.
# Returns 429 when the IP is locked; records failure on 401, resets on 303.
#
# The tracker is created explicitly and stored on app.state so test fixtures
# can call app.state.login_tracker.reset_all() to prevent cross-test
# contamination (multiple wrong-password tests would otherwise exhaust the
# limit and lock out the shared test IP).
_login_tracker = _LoginAttemptTracker()
app.state.login_tracker = _login_tracker
app.add_middleware(LoginRateLimitMiddleware, _tracker_override=_login_tracker)

# CSRFMiddleware — outside LoginRateLimitMiddleware; bots without a valid
# CSRF token are blocked here (403) before the rate limiter ever sees them.
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
# Development-only utilities
# ---------------------------------------------------------------------------

if settings.ENVIRONMENT == "development":
    from fastapi.responses import JSONResponse

    @app.post("/dev/reset-lockout")
    async def dev_reset_lockout() -> JSONResponse:
        """Clear all in-memory login-lockout counters (development only).

        This endpoint is ONLY registered when ENVIRONMENT=development.
        It does not exist in production — the route is never mounted.

        Use this during local testing to unblock a locked-out IP without
        restarting the server.  The lockout tracker is purely in-memory so
        a server restart has the same effect; this endpoint is purely for
        convenience.

        Example:
            curl -X POST http://localhost:8000/dev/reset-lockout
        """
        app.state.login_tracker.reset_all()
        logger.info("dev/reset-lockout: all login-lockout counters cleared")
        return JSONResponse({"detail": "All login-lockout counters have been reset."})

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
    safe_title = html.escape(title)
    safe_message = html.escape(message)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureVault — {safe_title}</title>
</head>
<body>
  <h1>{safe_title}</h1>
  <p>{safe_message}</p>
  <a href="/">Return to vault</a>
</body>
</html>"""
