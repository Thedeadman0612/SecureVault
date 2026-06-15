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

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.schemas.vault import VaultEntryCreate, VaultEntryUpdate
from app.services import import_export as import_export_svc
from app.services import vault_service
from app.templates_config import templates
from app.utils.helpers import first_validation_error, none_if_empty

logger = logging.getLogger(__name__)

router = APIRouter()

# Template name constants.
_VAULT_TEMPLATE        = "vault.html"
_ENTRY_FORM_TEMPLATE   = "entry_form.html"
_ENTRY_DETAIL_TEMPLATE = "entry_detail.html"

# Redirect URL constants.
_VAULT_URL = "/vault"
_LOGIN_URL = "/login"
_NEW_ENTRY_PATH = "/entry/new"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _session_context(request: Request) -> tuple[bytes, int] | RedirectResponse:
    """Decode the encryption key and user_id from the session.

    Returns a (raw_key, user_id) tuple on success, or a RedirectResponse to
    /login if either session key is absent or cannot be decoded.

    Failure modes handled:
      - Missing key_b64 or user_id → unauthenticated; redirect to /login.
      - Corrupt base64 in key_b64 → session tampered; clear + redirect to /login.

    Once auth_guard middleware is active this path will never be reached via
    normal browser navigation — it acts as a secondary safety net.
    """
    key_b64: str | None = request.session.get("encryption_key")
    user_id: int | None = request.session.get("user_id")
    # Use `not key_b64` for the key (rejects None AND empty string — both invalid)
    # but `user_id is None` for the id. `not user_id` would be falsy for user_id=0,
    # incorrectly blocking a valid user. Phase 1 has id=1 so this is a safety net
    # that matters most once multi-user (Phase 6) is added.
    if not key_b64 or user_id is None:
        return RedirectResponse(url=_LOGIN_URL, status_code=status.HTTP_302_FOUND)
    try:
        raw_key = base64.urlsafe_b64decode(key_b64)
    except ValueError:
        # Session contains invalid base64 — possible tampering or corruption.
        # Clear the session so the browser doesn't loop on every request.
        logger.warning("Corrupt encryption_key in session — clearing and redirecting to /login.")
        request.session.clear()
        return RedirectResponse(url=_LOGIN_URL, status_code=status.HTTP_302_FOUND)
    return raw_key, int(user_id)



# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@router.get(_VAULT_URL, response_class=HTMLResponse)
async def get_vault(
    request: Request,
    q: str | None = Query(default=None),
    category: str | None = Query(default=None),
    imported: int | None = Query(default=None),
    import_error: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Render the vault dashboard with filtered, decrypted entries.

    Accepts optional `q` (title/website text search) and `category` (exact
    match) query parameters. Both filters operate on plaintext columns only.
    `imported` and `import_error` carry one-shot flash state from POST /vault/import.
    """
    ctx = _session_context(request)
    if isinstance(ctx, RedirectResponse):
        return ctx
    raw_key, user_id = ctx

    error: str | None = None
    categories: list[str] = []
    try:
        # Always fetch all entries — client-side JS in vault_search.js does
        # the live filtering. q and active_category are passed to the template
        # only to pre-fill the search inputs on page load.
        entries = vault_service.get_entries(user_id, raw_key, db)
        categories = vault_service.get_categories(user_id, db)
    except HTTPException as exc:
        entries = []
        error = exc.detail
        logger.exception(
            "Failed to load vault entries for user id=%d: %s",
            user_id, exc.detail,
        )

    return templates.TemplateResponse(
        request, _VAULT_TEMPLATE,
        {
            "entries": entries,
            "error": error,
            "q": q or "",
            "active_category": category or "",
            "categories": categories,
            "imported": imported,
            "import_error": import_error,
        },
    )


# ---------------------------------------------------------------------------
# Import / Export
# ---------------------------------------------------------------------------

@router.post("/vault/import", response_model=None)
async def post_import_vault(
    request: Request,
    import_file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """Parse an uploaded KeePass XML or LastPass CSV file and create vault entries.

    File format is inferred from the filename extension (.xml → KeePass, .csv → LastPass).
    All imported entries are encrypted with the user's current vault key before storage.
    Entries that fail validation (e.g. empty title) are skipped; the rest are imported.
    Redirects to /vault with a success count or an error message as a query parameter.

    Security:
      - Max 5 MB upload to limit memory pressure from malformed XML.
      - No sensitive field values are logged.
      - CSRF token validated by CSRFMiddleware before this handler runs.
    """
    ctx = _session_context(request)
    if isinstance(ctx, RedirectResponse):
        return ctx
    raw_key, user_id = ctx

    content = await import_file.read()
    if len(content) > import_export_svc.MAX_IMPORT_BYTES:
        return RedirectResponse(
            f"{_VAULT_URL}?import_error=File+too+large+(5+MB+max)",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    filename = (import_file.filename or "").lower()
    try:
        if filename.endswith(".xml"):
            parsed = import_export_svc.parse_keepass_xml(content)
        elif filename.endswith(".csv"):
            parsed = import_export_svc.parse_lastpass_csv(content)
        else:
            return RedirectResponse(
                f"{_VAULT_URL}?import_error=Unsupported+format+(use+.xml+or+.csv)",
                status_code=status.HTTP_303_SEE_OTHER,
            )
    except import_export_svc.ImportError:
        logger.warning("Import parse failed for user id=%d.", user_id)
        return RedirectResponse(
            f"{_VAULT_URL}?import_error=Could+not+parse+file",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    count = 0
    for ie in parsed:
        try:
            data = VaultEntryCreate(
                title=ie.title,
                website=ie.website,
                category=ie.category,
                username=ie.username or "",
                password=ie.password or "",
                notes=ie.notes,
            )
            vault_service.create_entry(data, user_id, raw_key, db)
            count += 1
        except Exception:
            logger.warning("Skipped one entry during import for user id=%d.", user_id)

    logger.info("Import complete: %d entries created for user id=%d.", count, user_id)
    return RedirectResponse(
        f"{_VAULT_URL}?imported={count}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/vault/export")
async def get_export_vault(
    request: Request,
    format: str = Query(default="keepass"),
    db: Session = Depends(get_db),
) -> Response:
    """Download all vault entries as a KeePass XML or LastPass CSV file.

    Query parameter:
      format=keepass  (default) → KeePass 2.x XML, filename securevault_export.xml
      format=lastpass           → LastPass CSV,     filename securevault_export.csv

    All sensitive fields are decrypted in memory and written into the export
    file. The file is sent as an attachment; it is never stored server-side.
    """
    ctx = _session_context(request)
    if isinstance(ctx, RedirectResponse):
        return ctx
    raw_key, user_id = ctx

    try:
        entries = vault_service.get_entries(user_id, raw_key, db)
    except HTTPException:
        return RedirectResponse(url=_VAULT_URL, status_code=status.HTTP_302_FOUND)

    if format == "lastpass":
        content = import_export_svc.build_lastpass_csv(entries)
        filename = "securevault_export.csv"
        media_type = "text/csv; charset=utf-8"
    else:
        content = import_export_svc.build_keepass_xml(entries)
        filename = "securevault_export.xml"
        media_type = "application/xml; charset=utf-8"

    logger.info(
        "Export: %d entries for user id=%d (format=%s).",
        len(entries), user_id, format,
    )
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
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
        request, _ENTRY_FORM_TEMPLATE,
        {"entry": None, "action": _NEW_ENTRY_PATH},
    )


@router.post("/entry/new", response_model=None)
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
            request, _ENTRY_FORM_TEMPLATE,
            {
                "entry": None,
                "action": _NEW_ENTRY_PATH,
                "error": first_validation_error(exc),
            },
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    # --- Service call ---
    try:
        vault_service.create_entry(data, user_id, raw_key, db)
    except Exception:
        # Covers HTTPException 500 (decrypt-after-write failure) and any
        # unexpected DB error (e.g. IntegrityError from db.commit()).
        # Never propagate raw exceptions to the browser — show a safe message.
        logger.exception("Failed to create vault entry for user id=%d.", user_id)
        return templates.TemplateResponse(
            request, _ENTRY_FORM_TEMPLATE,
            {
                "entry": None,
                "action": _NEW_ENTRY_PATH,
                "error": "Could not save entry. Please try again.",
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

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
        request, _ENTRY_DETAIL_TEMPLATE,
        {"entry": entry},
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
        request, _ENTRY_FORM_TEMPLATE,
        {
            "entry": entry,
            "action": f"/entry/{entry_id}/edit",
        },
    )


@router.post("/entry/{entry_id}/edit", response_model=None)
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
    # Clearable nullable fields (website, category, notes) are passed as-is:
    #   "" means "user cleared the field → set to NULL in DB"
    #   any non-empty string means "user changed the value → update"
    # Non-nullable / required fields (title, username, password) still use
    # none_if_empty() so an unedited blank submission means "no change".
    try:
        data = VaultEntryUpdate(
            title=none_if_empty(title),
            website=website,          # "" → clear; non-empty → update; None impossible from form
            category=category,        # "" → clear; non-empty → update; None impossible from form
            username=none_if_empty(username),
            password=none_if_empty(password),
            notes=notes,              # "" → clear; non-empty → update; None impossible from form
        )
    except ValidationError as exc:
        # Re-fetch the existing entry so the edit form is pre-filled on
        # validation error — passing entry=None would wipe all field values.
        try:
            existing = vault_service.get_entry(entry_id, user_id, raw_key, db)
        except HTTPException:
            # Entry vanished between GET and POST; redirect cleanly.
            return RedirectResponse(url=_VAULT_URL, status_code=status.HTTP_302_FOUND)
        return templates.TemplateResponse(
            request, _ENTRY_FORM_TEMPLATE,
            {
                "entry": existing,
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
