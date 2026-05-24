"""
app/routes/auth.py

Route handlers for the authentication flow: setup, login, and logout.

Routes:
  GET  /setup   — Render the first-time setup form. Redirects to /login if
                  the vault is already initialised.
  POST /setup   — Validate input, create the vault user, redirect to /login.
  GET  /login   — Render the login form. Redirects to /vault if already
                  logged in (encryption_key present in session).
  POST /login   — Verify password, derive key, redirect to /vault.
  POST /logout  — Clear session, redirect to /login.

ERROR HANDLING CONVENTION:
  Validation errors (Pydantic) and expected service errors (HTTPException) are
  caught here and re-rendered into the originating template with an `error`
  context variable. Unexpected exceptions propagate to FastAPI's global handler
  in main.py, which returns a generic 500 page — never a raw stack trace.

SECURITY NOTES:
  - POST handlers use status 303 See Other for redirects after a successful
    form submission, preventing duplicate submissions on browser back/refresh.
  - GET /login and GET /setup redirect away if the session already contains
    the expected key, so authenticated users cannot accidentally land on these
    pages and re-initialise or re-derive the key.
"""

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.user import User
from app.schemas.auth import LoginRequest, SetupRequest
from app.services import auth_service
from app.utils.helpers import first_validation_error

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

# Template name constants — avoids repeated string literals and makes
# renames a one-line change.
_SETUP_TEMPLATE = "setup.html"
_LOGIN_TEMPLATE = "login.html"

# Redirect URL constants.
_LOGIN_URL = "/login"
_VAULT_URL = "/vault"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# Setup routes
# ---------------------------------------------------------------------------

@router.get("/setup", response_class=HTMLResponse)
async def get_setup(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    """Render the first-time vault setup form.

    Redirects to /login if the vault has already been initialised (a User row
    exists), so this page cannot be used to overwrite an existing vault.
    """
    if db.query(User).first():
        return RedirectResponse(url=_LOGIN_URL, status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(_SETUP_TEMPLATE, {"request": request})


@router.post("/setup")
async def post_setup(
    request: Request,
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """Create the vault user and redirect to /login on success.

    Validates the form data with SetupRequest, then delegates to
    auth_service.setup_vault(). On any error the setup page is re-rendered
    with a user-facing message — no internal detail is ever exposed.

    On success: redirects to /login (303 See Other) so the user can
    derive the encryption key and begin their session.
    """
    # --- Schema validation ---
    try:
        SetupRequest(password=password, confirm_password=confirm_password)
    except ValidationError as exc:
        return templates.TemplateResponse(
            _SETUP_TEMPLATE,
            {"request": request, "error": first_validation_error(exc)},
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    # --- Service call ---
    try:
        auth_service.setup_vault(password, db)
    except HTTPException as exc:
        # Expected service errors (e.g. HTTP 400 "Vault is already set up.").
        # Pass the detail through so the user sees the real reason.
        return templates.TemplateResponse(
            _SETUP_TEMPLATE,
            {"request": request, "error": exc.detail},
            status_code=exc.status_code,
        )
    except Exception:
        # Truly unexpected errors (e.g. DB unavailable). Log with full
        # traceback; return a generic message — no internals to the browser.
        logger.exception("Unexpected error during vault setup.")
        return templates.TemplateResponse(
            _SETUP_TEMPLATE,
            {"request": request, "error": "Setup failed. Please try again."},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Redirect to /login so the user derives their encryption key immediately.
    # 303 See Other converts the POST to a GET, preventing re-submission.
    logger.info("Vault setup complete — redirecting to /login.")
    return RedirectResponse(url=_LOGIN_URL, status_code=status.HTTP_303_SEE_OTHER)


# ---------------------------------------------------------------------------
# Login routes
# ---------------------------------------------------------------------------

@router.get("/login", response_class=HTMLResponse)
async def get_login(request: Request) -> HTMLResponse:
    """Render the login form.

    Redirects to /vault if the user is already authenticated (encryption_key
    present in session), so pressing Back after login does not re-show the
    login page with a filled password field.
    """
    if request.session.get("encryption_key"):
        return RedirectResponse(url=_VAULT_URL, status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(_LOGIN_TEMPLATE, {"request": request})


@router.post("/login")
async def post_login(
    request: Request,
    password: str = Form(...),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """Verify the master password, derive the encryption key, redirect to /vault.

    Delegates to auth_service.login(), which writes encryption_key and user_id
    into the session. On failure the login page is re-rendered with a generic
    error — the specific reason (no user vs wrong password) is never disclosed.
    """
    # --- Schema validation (non-empty password) ---
    try:
        LoginRequest(password=password)
    except ValidationError as exc:
        return templates.TemplateResponse(
            _LOGIN_TEMPLATE,
            {"request": request, "error": first_validation_error(exc)},
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    # --- Service call ---
    try:
        auth_service.login(password, db, request.session)
    except Exception:
        # auth_service raises HTTPException 401 (wrong password) or 500
        # (corrupt kdf_salt). Render a generic error for both.
        logger.warning("Login attempt failed.")
        return templates.TemplateResponse(
            _LOGIN_TEMPLATE,
            {"request": request, "error": "Invalid password."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    return RedirectResponse(url=_VAULT_URL, status_code=status.HTTP_303_SEE_OTHER)


# ---------------------------------------------------------------------------
# Logout route
# ---------------------------------------------------------------------------

@router.post("/logout")
async def post_logout(request: Request) -> RedirectResponse:
    """Clear the session and redirect to /login.

    Calls auth_service.logout() which wipes the session dict entirely,
    including the in-memory encryption key. After this point the vault
    entries cannot be decrypted until the user logs in again.
    """
    auth_service.logout(request.session)
    return RedirectResponse(url=_LOGIN_URL, status_code=status.HTTP_303_SEE_OTHER)
