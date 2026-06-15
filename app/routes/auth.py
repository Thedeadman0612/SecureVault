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

import base64
import io
import logging

import qrcode  # type: ignore[import-untyped]
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.recovery_code import RecoveryCode
from app.models.user import User
from app.schemas.auth import LoginRequest, SetupRequest
from app.security.encryption import InvalidToken, decrypt_field_gcm
from app.security.totp import generate_secret, get_provisioning_uri, verify_recovery_code, verify_totp
from app.services import auth_service
from app.templates_config import templates
from app.utils.helpers import first_validation_error, utcnow

logger = logging.getLogger(__name__)

router = APIRouter()

# Template name constants — avoids repeated string literals and makes
# renames a one-line change.
_SETUP_TEMPLATE = "setup.html"
_LOGIN_TEMPLATE = "login.html"
_2FA_SETUP_TEMPLATE = "2fa_setup.html"
_2FA_VERIFY_TEMPLATE = "2fa_verify.html"
_2FA_RECOVERY_TEMPLATE = "2fa_recovery.html"

# Redirect URL constants.
_LOGIN_URL = "/login"
_VAULT_URL = "/vault"
_2FA_VERIFY_URL = "/2fa/verify"
_2FA_SETUP_URL = "/2fa/setup"

# Maximum failed TOTP attempts before the pending session is wiped and the
# user must re-enter their password from /login.
_MAX_TOTP_ATTEMPTS: int = 5
_MAX_RECOVERY_ATTEMPTS: int = 5


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_qr_b64(uri: str) -> str:
    """Generate a QR code image for *uri* and return it as a base64 PNG string.

    The returned string is safe to embed directly in an <img> src attribute:
        <img src="data:image/png;base64,{{ qr_image }}">
    """
    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def _raw_key_from_session(session: dict) -> bytes:
    """Decode the base64 encryption key stored in session["encryption_key"]."""
    return base64.urlsafe_b64decode(session["encryption_key"].encode())


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
    return templates.TemplateResponse(request, _SETUP_TEMPLATE)


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
            request, _SETUP_TEMPLATE,
            {"error": first_validation_error(exc)},
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    # --- Service call ---
    try:
        auth_service.setup_vault(password, db)
    except HTTPException as exc:
        # Expected service errors (e.g. HTTP 400 "Vault is already set up.").
        # Pass the detail through so the user sees the real reason.
        return templates.TemplateResponse(
            request, _SETUP_TEMPLATE,
            {"error": exc.detail},
            status_code=exc.status_code,
        )
    except Exception:
        # Truly unexpected errors (e.g. DB unavailable). Log with full
        # traceback; return a generic message — no internals to the browser.
        logger.exception("Unexpected error during vault setup.")
        return templates.TemplateResponse(
            request, _SETUP_TEMPLATE,
            {"error": "Setup failed. Please try again."},
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
    error: str | None = request.session.pop("flash_error", None)
    return templates.TemplateResponse(request, _LOGIN_TEMPLATE, {"error": error} if error else {})


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
            request, _LOGIN_TEMPLATE,
            {"error": first_validation_error(exc)},
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    # --- Service call ---
    try:
        requires_totp: bool = auth_service.login(password, db, request.session)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            # Wrong password or no vault — return identical generic message
            # so the response does not reveal whether a vault exists.
            logger.warning("Login attempt failed — invalid password.")
            return templates.TemplateResponse(
                request, _LOGIN_TEMPLATE,
                {"error": "Invalid password."},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        # HTTP 500 from derive_key() means kdf_salt is corrupt — a server
        # error, not a credentials error. Returning 401 here would mask
        # DB corruption and make it indistinguishable from a wrong password.
        logger.exception("Login failed due to server error: %s", exc.detail)
        return templates.TemplateResponse(
            request, _LOGIN_TEMPLATE,
            {"error": "Login failed due to a server error. Please contact support."},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    except Exception:
        # Truly unexpected errors (e.g. DB unavailable).
        logger.exception("Unexpected error during login.")
        return templates.TemplateResponse(
            request, _LOGIN_TEMPLATE,
            {"error": "Login failed. Please try again."},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    if requires_totp:
        return RedirectResponse(url=_2FA_VERIFY_URL, status_code=status.HTTP_303_SEE_OTHER)
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


# ---------------------------------------------------------------------------
# 2FA setup routes  (require full authentication — encryption_key in session)
# ---------------------------------------------------------------------------


@router.get("/2fa/setup", response_class=HTMLResponse)
async def get_2fa_setup(
    request: Request,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Render the TOTP setup page with a fresh QR code.

    Generates a new TOTP secret on every visit and stores it in the session
    as pending_totp_secret. The secret is NOT persisted to the DB here — it
    is only written after the user confirms their first TOTP code (POST /2fa/setup).

    AuthGuard already requires encryption_key for this path, so the user is
    guaranteed to be authenticated before reaching this handler.
    """
    user_id: int = request.session["user_id"]
    user = db.query(User).filter(User.id == user_id).first()

    secret: str = request.session.get("pending_totp_secret") or generate_secret()
    request.session["pending_totp_secret"] = secret
    uri = get_provisioning_uri(secret)

    return templates.TemplateResponse(
        request,
        _2FA_SETUP_TEMPLATE,
        {
            "qr_image": _make_qr_b64(uri),
            "secret": secret,
            "totp_enabled": user.totp_enabled if user else False,
        },
    )


@router.post("/2fa/setup")
async def post_2fa_setup(
    request: Request,
    token: str = Form(...),
    db: Session = Depends(get_db),
) -> Response:
    """Confirm the first TOTP code and activate 2FA.

    Reads the pending TOTP secret from the session, verifies the submitted
    6-digit code, then delegates to auth_service.enable_2fa() which encrypts
    the secret, persists it, and generates 8 recovery codes.

    On success: renders the setup template showing the recovery codes once.
    On failure: re-renders the setup page with the same QR code so the user
                can try again without re-scanning.
    """
    user_id: int | None = request.session.get("user_id")
    secret: str | None = request.session.get("pending_totp_secret")

    if not user_id or not secret:
        return RedirectResponse(url=_LOGIN_URL, status_code=status.HTTP_302_FOUND)

    raw_key = _raw_key_from_session(request.session)

    try:
        codes = auth_service.enable_2fa(user_id, secret, token, raw_key, db)
    except HTTPException as exc:
        uri = get_provisioning_uri(secret)
        return templates.TemplateResponse(
            request,
            _2FA_SETUP_TEMPLATE,
            {
                "qr_image": _make_qr_b64(uri),
                "secret": secret,
                "error": exc.detail,
                "totp_enabled": False,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    request.session.pop("pending_totp_secret", None)
    return templates.TemplateResponse(
        request,
        _2FA_SETUP_TEMPLATE,
        {
            "recovery_codes": codes,
            "setup_complete": True,
            "totp_enabled": True,
        },
    )


@router.post("/2fa/disable")
async def post_2fa_disable(
    request: Request,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """Deactivate TOTP 2FA and delete all recovery codes for the current user.

    AuthGuard already requires encryption_key for this path.
    Redirects to /vault on success.
    """
    user_id: int | None = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url=_LOGIN_URL, status_code=status.HTTP_302_FOUND)

    auth_service.disable_2fa(user_id, db)
    return RedirectResponse(url=_VAULT_URL, status_code=status.HTTP_303_SEE_OTHER)


# ---------------------------------------------------------------------------
# 2FA verify routes  (mid-login — pending_user_id in session, no encryption_key)
# ---------------------------------------------------------------------------


@router.get("/2fa/verify", response_class=HTMLResponse)
async def get_2fa_verify(request: Request) -> Response:
    """Render the TOTP verification form for a mid-login user.

    Only valid when session["pending_user_id"] is set (i.e. the user has
    passed the password check but not the TOTP check). If the pending key
    is absent the user is redirected to /login to start over.
    """
    if not request.session.get("pending_user_id"):
        return RedirectResponse(url=_LOGIN_URL, status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request, _2FA_VERIFY_TEMPLATE)


@router.post("/2fa/verify")
async def post_2fa_verify(
    request: Request,
    token: str = Form(...),
    db: Session = Depends(get_db),
) -> Response:
    """Validate the TOTP code and promote the session to fully authenticated.

    Reads the pending session state, decrypts the stored TOTP secret,
    and verifies the submitted token. On success the pending keys are
    replaced with the live encryption_key so AuthGuard grants vault access.

    Tracks failed attempts in session["totp_attempts"]. After
    _MAX_TOTP_ATTEMPTS failures the pending session is wiped and the user
    must restart from /login (they may use a recovery code instead).
    """
    pending_user_id: int | None = request.session.get("pending_user_id")
    pending_key_b64: str | None = request.session.get("pending_encryption_key")

    if not pending_user_id or not pending_key_b64:
        return RedirectResponse(url=_LOGIN_URL, status_code=status.HTTP_302_FOUND)

    if len(token) != 6 or not token.isdigit():
        return templates.TemplateResponse(
            request,
            _2FA_VERIFY_TEMPLATE,
            {"error": "Please enter a valid 6-digit code."},
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    user = db.query(User).filter(User.id == pending_user_id).first()
    if not user or not user.totp_enabled or not user.totp_secret:
        request.session.clear()
        return RedirectResponse(url=_LOGIN_URL, status_code=status.HTTP_302_FOUND)

    raw_key = base64.urlsafe_b64decode(pending_key_b64.encode())
    try:
        plaintext_secret = decrypt_field_gcm(user.totp_secret, raw_key)
    except (InvalidToken, ValueError):
        logger.error("Failed to decrypt TOTP secret for user id=%d.", pending_user_id)
        request.session.clear()
        return RedirectResponse(url=_LOGIN_URL, status_code=status.HTTP_302_FOUND)

    if not verify_totp(plaintext_secret, token):
        attempts: int = request.session.get("totp_attempts", 0) + 1
        if attempts >= _MAX_TOTP_ATTEMPTS:
            logger.warning(
                "TOTP attempt limit reached for pending user id=%d — wiping session.",
                pending_user_id,
            )
            request.session.clear()
            request.session["flash_error"] = "Too many incorrect codes. Please log in again."
            return RedirectResponse(url=_LOGIN_URL, status_code=status.HTTP_302_FOUND)
        logger.warning(
            "Failed TOTP attempt %d/%d for pending user id=%d.",
            attempts,
            _MAX_TOTP_ATTEMPTS,
            pending_user_id,
        )
        request.session["totp_attempts"] = attempts
        return templates.TemplateResponse(
            request,
            _2FA_VERIFY_TEMPLATE,
            {"error": "Invalid code. Please try again."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    # Promote to a fully authenticated session.
    request.session.clear()
    request.session["encryption_key"] = pending_key_b64
    request.session["user_id"] = pending_user_id
    logger.info("User id=%d completed TOTP verification — session promoted.", pending_user_id)
    return RedirectResponse(url=_VAULT_URL, status_code=status.HTTP_303_SEE_OTHER)


# ---------------------------------------------------------------------------
# Recovery code routes  (mid-login, same session state as /2fa/verify)
# ---------------------------------------------------------------------------


@router.get("/2fa/recovery", response_class=HTMLResponse)
async def get_2fa_recovery(request: Request) -> Response:
    """Render the recovery code input form.

    Only valid during the mid-login TOTP step (pending_user_id in session).
    """
    if not request.session.get("pending_user_id"):
        return RedirectResponse(url=_LOGIN_URL, status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request, _2FA_RECOVERY_TEMPLATE)


@router.post("/2fa/recovery")
async def post_2fa_recovery(
    request: Request,
    recovery_code: str = Form(...),
    db: Session = Depends(get_db),
) -> Response:
    """Verify a recovery code and promote the session to fully authenticated.

    Iterates over the user's unused recovery codes and runs Argon2id
    verification on each. The first match is marked used (used_at timestamp
    set) and the session is promoted. An already-used or invalid code returns
    a 401 and re-renders the form.

    Recovery codes are single-use — once used_at is set the code is
    permanently consumed.
    """
    pending_user_id: int | None = request.session.get("pending_user_id")
    pending_key_b64: str | None = request.session.get("pending_encryption_key")

    if not pending_user_id or not pending_key_b64:
        return RedirectResponse(url=_LOGIN_URL, status_code=status.HTTP_302_FOUND)

    stripped_code = recovery_code.strip()
    if not stripped_code or len(stripped_code) > 32:
        return templates.TemplateResponse(
            request,
            _2FA_RECOVERY_TEMPLATE,
            {"error": "Invalid or already-used recovery code."},
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    recovery_attempts: int = request.session.get("recovery_attempts", 0) + 1
    if recovery_attempts > _MAX_RECOVERY_ATTEMPTS:
        logger.warning(
            "Recovery code attempt limit reached for pending user id=%d — wiping session.",
            pending_user_id,
        )
        request.session.clear()
        request.session["flash_error"] = "Too many incorrect codes. Please log in again."
        return RedirectResponse(url=_LOGIN_URL, status_code=status.HTTP_302_FOUND)

    unused_codes = (
        db.query(RecoveryCode)
        .filter(
            RecoveryCode.user_id == pending_user_id,
            RecoveryCode.used_at.is_(None),
        )
        .all()
    )

    matched: RecoveryCode | None = None
    for row in unused_codes:
        if verify_recovery_code(stripped_code, row.code_hash):
            matched = row
            break

    if matched is None:
        logger.warning(
            "Invalid recovery code attempt %d/%d for pending user id=%d.",
            recovery_attempts,
            _MAX_RECOVERY_ATTEMPTS,
            pending_user_id,
        )
        request.session["recovery_attempts"] = recovery_attempts
        return templates.TemplateResponse(
            request,
            _2FA_RECOVERY_TEMPLATE,
            {"error": "Invalid or already-used recovery code."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    try:
        matched.used_at = utcnow()
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Failed to mark recovery code used for user id=%d.", pending_user_id)
        return templates.TemplateResponse(
            request,
            _2FA_RECOVERY_TEMPLATE,
            {"error": "An error occurred. Please try again."},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    request.session.clear()
    request.session["encryption_key"] = pending_key_b64
    request.session["user_id"] = pending_user_id
    logger.info(
        "User id=%d authenticated via recovery code — session promoted.", pending_user_id
    )
    return RedirectResponse(url=_VAULT_URL, status_code=status.HTTP_303_SEE_OTHER)


# ---------------------------------------------------------------------------
# Session diagnostic endpoints
# ---------------------------------------------------------------------------

@router.get("/auth/timeout-notify", response_class=Response)
async def get_timeout_notify(request: Request) -> Response:
    """Log a client-side inactivity timeout event and return 204.

    Called by session_timeout.js (with keepalive: true) just before it
    redirects the browser to /login. Because the JS timer fires while the
    session is still momentarily valid, we can read user_id here and emit
    a structured log entry that ties the redirect to a specific user — which
    is otherwise invisible in the server logs.

    This route is exempt from AuthGuard (see auth_guard.py _EXEMPT_EXACT)
    so the notification still arrives even if the Fernet TTL expired at the
    same moment the JS timer fired.
    """
    user_id: int | None = request.session.get("user_id")
    logger.info(
        "Client-side inactivity timeout fired — user_id=%s will be redirected to /login.",
        user_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
