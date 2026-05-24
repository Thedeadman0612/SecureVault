"""
app/routes/vault.py

Route handlers for vault entry CRUD: dashboard, create, detail, edit, delete.

Routes:
  GET  /vault              — Dashboard: list all decrypted entries.
  GET  /entry/new          — Render blank create form.
  POST /entry/new          — Validate + create entry, redirect to /vault.
  GET  /entry/{id}         — Detail view for a single decrypted entry.
  GET  /entry/{id}/edit    — Render edit form pre-filled with existing values.
  POST /entry/{id}/edit    — Validate + update entry, redirect to /entry/{id}.
  POST /entry/{id}/delete  — Delete entry, redirect to /vault.

SESSION CONTRACT (written by auth_service.login):
  session["encryption_key"]  str   — URL-safe base64 of the raw 32-byte key.
  session["user_id"]          int   — primary key of the authenticated user.

  _session_context() decodes both into (raw_key: bytes, user_id: int).
  If either key is missing, the helper redirects to /login. Once auth_guard
  middleware is wired up in main.py, it will intercept unauthenticated
  requests before they reach these routes — the fallback in _session_context
  becomes a secondary safety net.

EMPTY-STRING CONVENTION (HTML forms always submit all fields):
  HTML forms submit optional fields as empty strings, not None.
  none_if_empty() converts "" → None so VaultEntryUpdate treats unedited
  fields as "no change" rather than "clear to empty string".

ERROR HANDLING:
  HTTPException 404 (entry not found) → redirect to /vault.
  HTTPException 500 (decryption failure) → redirect to /vault with error.
  ValidationError → re-render the originating form with the error message.
  Unexpected exceptions → propagate to main.py's global 500 handler.
"""

import base64
import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.schemas.vault import VaultEntryCreate, VaultEntryUpdate
from app.services import vault_service
from app.utils.helpers import first_validation_error, none_if_empty

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

# Template name constants.
_VAULT_TEMPLATE        = "vault.html"
_ENTRY_FORM_TEMPLATE   = "entry_form.html"
_ENTRY_DETAIL_TEMPLATE = "entry_detail.html"

# Redirect URL constants.
_VAULT_URL = "/vault"
_LOGIN_URL = "/login"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _session_context(request: Request) -> tuple[bytes, int] | RedirectResponse:
    """Decode the encryption key and user_id from the session.

    Returns a (raw_key, user_id) tuple on success, or a RedirectResponse to
    /login if either session key is absent (unauthenticated request).

    Once auth_guard middleware is active this path will never be reached via
    normal browser navigation — it acts as a secondary safety net.
    """
    key_b64: str | None = request.session.get("encryption_key")
    user_id: int | None = request.session.get("user_id")
    if not key_b64 or not user_id:
        return RedirectResponse(url=_LOGIN_URL, status_code=status.HTTP_302_FOUND)
    return base64.urlsafe_b64decode(key_b64), int(user_id)



# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@router.get(_VAULT_URL, response_class=HTMLResponse)
async def get_vault(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    """Render the vault dashboard with all decrypted entries.

    Passes a (possibly empty) list of VaultEntryResponse objects to the
    template under the key `entries`.
    """
    ctx = _session_context(request)
    if isinstance(ctx, RedirectResponse):
        return ctx
    raw_key, user_id = ctx

    error: str | None = None
    try:
        entries = vault_service.get_entries(user_id, raw_key, db)
    except HTTPException as exc:
        # A 500 here means decryption failed for one or more entries —
        # wrong key in session or tampered ciphertext. Show the error
        # prominently so the user knows their data is not simply gone.
        # Any other unexpected HTTPException is also surfaced rather than
        # silently swallowed.
        entries = []
        error = exc.detail
        # logger.exception() captures the full traceback automatically —
        # useful for pinpointing which entry/field caused the decryption
        # failure even though the HTTPException itself is expected.
        logger.exception(
            "Failed to load vault entries for user id=%d: %s",
            user_id, exc.detail,
        )

    return templates.TemplateResponse(
        _VAULT_TEMPLATE,
        {"request": request, "entries": entries, "error": error},
    )


# ---------------------------------------------------------------------------
# Create entry
# ---------------------------------------------------------------------------

@router.get("/entry/new", response_class=HTMLResponse)
async def get_new_entry(request: Request) -> HTMLResponse:
    """Render the blank entry creation form.

    Passes `entry=None` and `action="/entry/new"` so the shared
    entry_form.html template can distinguish create from edit mode.
    """
    ctx = _session_context(request)
    if isinstance(ctx, RedirectResponse):
        return ctx

    return templates.TemplateResponse(
        _ENTRY_FORM_TEMPLATE,
        {"request": request, "entry": None, "action": "/entry/new"},
    )


@router.post("/entry/new")
async def post_new_entry(
    request: Request,
    title: str = Form(...),
    website: str = Form(""),
    category: str = Form(""),
    username: str = Form(""),
    password: str = Form(...),
    notes: str = Form(""),
    db: Session = Depends(get_db),
) -> RedirectResponse | HTMLResponse:
    """Validate form data, create the vault entry, redirect to /vault.

    Re-renders the create form with an error message on validation failure.
    On success, redirects with 303 See Other to prevent duplicate submissions.
    """
    ctx = _session_context(request)
    if isinstance(ctx, RedirectResponse):
        return ctx
    raw_key, user_id = ctx

    # --- Schema validation ---
    try:
        data = VaultEntryCreate(
            title=title,
            website=none_if_empty(website),
            category=none_if_empty(category),
            username=username,
            password=password,
            notes=none_if_empty(notes),
        )
    except ValidationError as exc:
        return templates.TemplateResponse(
            _ENTRY_FORM_TEMPLATE,
            {
                "request": request,
                "entry": None,
                "action": "/entry/new",
                "error": first_validation_error(exc),
            },
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    # --- Service call ---
    vault_service.create_entry(data, user_id, raw_key, db)
    return RedirectResponse(url=_VAULT_URL, status_code=status.HTTP_303_SEE_OTHER)


# ---------------------------------------------------------------------------
# Entry detail
# ---------------------------------------------------------------------------

@router.get("/entry/{entry_id}", response_class=HTMLResponse)
async def get_entry(
    request: Request,
    entry_id: int,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Render the detail view for a single vault entry.

    Passes the decrypted VaultEntryResponse to the template under `entry`.
    Redirects to /vault if the entry does not exist or belongs to another user.
    """
    ctx = _session_context(request)
    if isinstance(ctx, RedirectResponse):
        return ctx
    raw_key, user_id = ctx

    try:
        entry = vault_service.get_entry(entry_id, user_id, raw_key, db)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            return RedirectResponse(url=_VAULT_URL, status_code=status.HTTP_302_FOUND)
        raise

    return templates.TemplateResponse(
        _ENTRY_DETAIL_TEMPLATE,
        {"request": request, "entry": entry},
    )


# ---------------------------------------------------------------------------
# Edit entry
# ---------------------------------------------------------------------------

@router.get("/entry/{entry_id}/edit", response_class=HTMLResponse)
async def get_edit_entry(
    request: Request,
    entry_id: int,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Render the edit form pre-filled with the existing entry's values.

    Passes the decrypted entry and `action="/entry/{id}/edit"` so the shared
    entry_form.html template renders in edit mode.
    Redirects to /vault if the entry does not exist.
    """
    ctx = _session_context(request)
    if isinstance(ctx, RedirectResponse):
        return ctx
    raw_key, user_id = ctx

    try:
        entry = vault_service.get_entry(entry_id, user_id, raw_key, db)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            return RedirectResponse(url=_VAULT_URL, status_code=status.HTTP_302_FOUND)
        raise

    return templates.TemplateResponse(
        _ENTRY_FORM_TEMPLATE,
        {
            "request": request,
            "entry": entry,
            "action": f"/entry/{entry_id}/edit",
        },
    )


@router.post("/entry/{entry_id}/edit")
async def post_edit_entry(
    request: Request,
    entry_id: int,
    title: str = Form(""),
    website: str = Form(""),
    category: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    notes: str = Form(""),
    db: Session = Depends(get_db),
) -> RedirectResponse | HTMLResponse:
    """Validate and apply a partial update to an existing vault entry.

    Only non-empty fields are written — empty submissions are treated as
    "no change" via none_if_empty(). On success, redirects to the entry's
    detail page with 303 See Other.
    """
    ctx = _session_context(request)
    if isinstance(ctx, RedirectResponse):
        return ctx
    raw_key, user_id = ctx

    # --- Schema validation ---
    try:
        data = VaultEntryUpdate(
            title=none_if_empty(title),
            website=none_if_empty(website),
            category=none_if_empty(category),
            username=none_if_empty(username),
            password=none_if_empty(password),
            notes=none_if_empty(notes),
        )
    except ValidationError as exc:
        return templates.TemplateResponse(
            _ENTRY_FORM_TEMPLATE,
            {
                "request": request,
                "entry": None,
                "action": f"/entry/{entry_id}/edit",
                "error": first_validation_error(exc),
            },
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    # --- Service call ---
    try:
        vault_service.update_entry(entry_id, data, user_id, raw_key, db)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            return RedirectResponse(url=_VAULT_URL, status_code=status.HTTP_302_FOUND)
        raise

    return RedirectResponse(
        url=f"/entry/{entry_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# ---------------------------------------------------------------------------
# Delete entry
# ---------------------------------------------------------------------------

@router.post("/entry/{entry_id}/delete")
async def post_delete_entry(
    request: Request,
    entry_id: int,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """Permanently delete a vault entry and redirect to /vault.

    No encryption key is needed — the Fernet tokens are deleted with the row.
    Redirects to /vault regardless of outcome (404 is silently swallowed since
    the desired state — entry gone — is already achieved).
    """
    ctx = _session_context(request)
    if isinstance(ctx, RedirectResponse):
        return ctx
    _, user_id = ctx  # raw_key not needed for deletion

    try:
        vault_service.delete_entry(entry_id, user_id, db)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            # Entry already gone — desired state achieved; redirect silently.
            logger.warning(
                "Delete request for non-existent entry id=%d by user id=%d.",
                entry_id, user_id,
            )
        else:
            raise

    return RedirectResponse(url=_VAULT_URL, status_code=status.HTTP_303_SEE_OTHER)
