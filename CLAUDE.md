# CLAUDE.md

We are building an app described in @spec.md. Read that file for general architectural tasks or to double-check the exact tech
stack or application architecture.

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## Project

SecureVault — a local-first encrypted credential manager. Educational/portfolio project. Full spec is in `spec.md`.

---

## Commands

Once the project is scaffolded, use these commands:

```bash
# Install dependencies
uv pip install -r requirements.txt
# or
pip install -r requirements.txt

# Run the application
uvicorn app.main:app --reload

# Run all tests
pytest

# Run a single test file
pytest app/tests/test_encryption.py

# Run a single test by name
pytest app/tests/test_encryption.py::test_encrypt_decrypt_roundtrip

# Run database migrations
alembic upgrade head

# Create a new migration
alembic revision --autogenerate -m "description"

# Lint
ruff check app/
```

---

## Architecture

### Request Lifecycle

```
Browser → FastAPI route handler → Auth middleware check
       → Service layer (business logic)
       → Encryption service (encrypt/decrypt sensitive fields)
       → SQLAlchemy ORM
       → SQLite (securevault.db)
```

### Key Design Decisions

**Two separate cryptographic operations — never conflate them:**
- `argon2-cffi` hashes the master password for login verification. This hash is stored in `users.password_hash`. It is one-way and never used for encryption.
- `PBKDF2HMAC` (Phase 1) or `Argon2id` (Phase 2) derives the vault encryption key from the master password at login time. The salt for this is stored in `users.kdf_salt`. The derived key is held in-memory in the session only — never written to disk.

**What is encrypted vs. plaintext in `vault_entries`:**
- Encrypted (Fernet token, stored as base64): `username`, `password`, `notes`
- Plaintext (safe to store, used for search): `title`, `website`, `category`

**Session:** Starlette `SessionMiddleware` with `itsdangerous` signed cookies. The derived encryption key is stored in the session dict and cleared on logout or timeout. Never log it.

### Module Responsibilities

| Module | Purpose |
|---|---|
| `app/main.py` | FastAPI app init, middleware registration, router inclusion |
| `app/config/` | Settings via Pydantic `BaseSettings` (secret key, DB URL, session timeout) |
| `app/routes/` | Thin route handlers — validate input, call services, return responses |
| `app/services/` | Business logic: auth service, vault CRUD service |
| `app/security/` | Encryption service (Fernet wrap/unwrap), key derivation, password hashing |
| `app/models/` | SQLAlchemy ORM models (`User`, `VaultEntry`) |
| `app/schemas/` | Pydantic request/response schemas |
| `app/database/` | SQLAlchemy engine, session factory, `get_db` dependency |
| `app/middleware/` | Auth guard (redirect unauthenticated requests to `/login`) |
| `app/templates/` | Jinja2 HTML templates |
| `app/static/` | CSS, JS assets |
| `app/migrations/` | Alembic migration scripts |
| `app/tests/` | pytest unit and integration tests |

---

## Security Rules

These are hard constraints — do not compromise them even for debugging or convenience:

- **Never log:** passwords, decrypted values, encryption keys, session tokens.
- **Never store:** plaintext `username`, `password`, or `notes` in the database.
- **Never expose:** stack traces or internal errors to the browser — return generic user-facing messages only.
- **Never hardcode:** secret keys, salts, or passwords in source files.
- The derived encryption key lives **in session memory only** — it must be cleared on logout and must never touch disk.
- All DB queries go through SQLAlchemy ORM (parameterized) — no raw SQL string interpolation.

---

## Development Phases

Work is phased — do not implement Phase 2+ features during Phase 1:

1. **Phase 1 (MVP):** Setup/login flow, Fernet encryption, CRUD vault, plain HTML + Tailwind frontend, Alembic migrations.
2. **Phase 2:** CSRF protection, rate limiting, AES-256-GCM, secure cookie hardening, Argon2id key derivation.
3. **Phase 3:** Search, category filter, password generator, clipboard auto-clear, dark mode.
4. **Phase 4:** pytest coverage, ruff linting, type hints, structured logging, architecture docs.
5. **Phase 5:** Docker, GitHub Actions, `pip-audit`, container hardening.
6. **Phase 6 (Multi-User):** Add `username`/`email` to `User` model, registration route, login by username, strict `user_id` filtering on all vault queries, per-user encryption key derivation, updated frontend, user isolation tests.
7. **Phase 7 (Mobile):** Two-part mobile rollout — 7A: PWA (manifest, service worker, responsive polish, installable on Android); 7B: Native Android client via Flutter + JSON REST API layer (`/api/v1/`) + JWT auth alongside existing session cookies.

---

## Progress Tracker

### Phase 7 — Status: 🔴 Not Started

#### Phase 7A — PWA

| File | What's needed |
|---|---|
| `app/static/manifest.json` | Web app manifest — name, icons, theme colour, `display: standalone` |
| `app/static/sw.js` | Service worker — cache static assets for offline access |
| `app/templates/base.html` | Link `manifest.json`; add `<meta>` tags for mobile web app capability |
| `app/static/icons/` | App icon set (192×192, 512×512 PNG) for Android home screen |
| Responsive layout audit | Review all templates on small screens; fix any overflow/layout issues |

#### Phase 7B — Native Android Client

| File / Area | What's needed |
|---|---|
| `app/routes/api.py` | New router: `/api/v1/` JSON endpoints mirroring HTML routes (vault CRUD + auth) |
| `app/schemas/api.py` | JSON request/response schemas for the REST API |
| `app/security/tokens.py` | JWT access + refresh token generation and verification (`python-jose`) |
| `app/routes/auth.py` | Add `POST /api/v1/login` → returns JWT; `POST /api/v1/logout` → blacklist/expire token |
| `android/` | Flutter (recommended) or Kotlin Android project consuming `/api/v1/` |
| `app/middleware/auth_guard.py` | Extend to accept `Authorization: Bearer <token>` on `/api/v1/*` routes |

---

### Phase 1 — Status: ✅ Complete (including code-review hardening)

#### ✅ Completed

| File | What was done |
|---|---|
| `app/models/user.py` | `User` ORM model — `id`, `password_hash`, `kdf_salt` (unique), `created_at`, `updated_at`; typed `Mapped[list[VaultEntry]]` relationship with `cascade="all, delete-orphan"` and `passive_deletes=True` |
| `app/models/vault_entry.py` | `VaultEntry` ORM model — `user_id` FK with `ondelete="CASCADE"` and `index=True`; plaintext fields (`title`, `website`, `category`); encrypted fields (`username_encrypted`, `password_encrypted`, `notes_encrypted`); typed `Mapped[User]` relationship |
| `app/database/session.py` | SQLAlchemy engine, `SessionLocal`, `get_db` dependency; rollback on exception before close to prevent dirty connections returning to pool |
| `app/config/settings.py` | Pydantic `BaseSettings` loading `SECRET_KEY`, `DATABASE_URL`, `SESSION_TIMEOUT_MINUTES` from `.env` |
| `app/migrations/versions/9680c40ab116_initial_tables.py` | Alembic initial migration — creates `users` and `vault_entries` tables |
| `app/migrations/versions/61c78f942f62_add_cascade_delete_user_id_index_kdf_.py` | Alembic migration — adds `ON DELETE CASCADE` to `vault_entries.user_id` FK, index on `vault_entries.user_id`, and `UNIQUE` constraint on `users.kdf_salt` |
| `app/security/hashing.py` | `hash_password(plain) -> str` (Argon2id PHC string) · `verify_password(plain, hash) -> bool` · `needs_rehash(hash) -> bool` — checks if stored hash parameters are outdated so login can silently upgrade them |
| `app/security/encryption.py` | `generate_kdf_salt()` · `derive_key()` · `encrypt_field()` · `decrypt_field()` — uses `utf-8` (not `ascii`) encoding in `decrypt_field` so corrupt non-ASCII tokens raise `InvalidToken` rather than `UnicodeEncodeError`; `InvalidToken` re-exported |
| `app/templates/` | All 6 HTML templates fully implemented with Tailwind CSS: `base.html` (layout, UTC→local JS converter) · `login.html` + `setup.html` · `vault.html` · `entry_form.html` · `entry_detail.html` |
| `app/templates_config.py` | Centralised `Jinja2Templates` instance with absolute path (`Path(__file__).parent / "templates"`); registers `format_datetime` global and `truncate_str` filter; imported by both route modules so env mutations apply everywhere |
| `app/static/` | CSS and JS asset directories created |
| `app/schemas/auth.py` | `SetupRequest` (password + confirm_password, min-length ≥12, match validator) · `LoginRequest` (password) · `MessageResponse` |
| `app/schemas/vault.py` | `VaultEntryCreate` · `VaultEntryUpdate` (documents `""` = clear-to-NULL / `None` = no-change convention for nullable fields) · `VaultEntryResponse` |
| `app/services/auth_service.py` | `setup_vault()` — Argon2id hash + KDF salt; IntegrityError catch for TOCTOU safety · `login()` — timing-safe dummy hash when no user exists (prevents vault-existence detection); `session.clear()` before writing keys (session fixation); `needs_rehash` check with silent re-hash; explicit `HTTPException` branching (401 vs 500) · `logout()` — session.clear() |
| `app/services/vault_service.py` | Full vault CRUD filtering by `user_id`; encrypt on write, decrypt on read; `_decrypt_entry` catches `(InvalidToken, ValueError)`; `db.rollback()` on commit failure in create/update/delete; nullable-field clearing (`""` → NULL) in `update_entry` |
| `app/routes/auth.py` | All auth routes; uses shared `templates_config.templates`; `POST /login` catches `HTTPException` explicitly — HTTP 500 from corrupt kdf_salt is no longer masked as 401; server-error branch uses `logger.exception()` to capture full exception chain (SonarQube S8572) |
| `app/routes/vault.py` | Full vault CRUD routes; uses shared `templates_config.templates`; `_session_context()` — `user_id is None` check (not falsy), corrupt base64 clears session and redirects; edit `ValidationError` re-fetches entry so form stays pre-filled; `create_entry` wrapped in exception handler; nullable-field clearing passed through; `except (binascii.Error, ValueError)` simplified to `except ValueError` since `binascii.Error` is a subclass (SonarQube S5713); `_NEW_ENTRY_PATH` constant eliminates duplicate `"/entry/new"` literals (SonarQube S1192) |
| `app/middleware/auth_guard.py` | `AuthGuard(BaseHTTPMiddleware)` — exempts `/login`, `/setup`, `/static/*`; checks `session["encryption_key"]`; redirects unauthenticated requests to `/login` with 302 |
| `app/main.py` | FastAPI app; `StaticFiles` at `/static`; middleware stack (`AuthGuard` inner, `SessionMiddleware` outer); includes `auth` + `vault` routers; global 404 + 500 handlers; docs disabled |
| `app/utils/helpers.py` | `first_validation_error` · `none_if_empty` · `utcnow` · `format_datetime` · `truncate` |
| `app/tests/test_hashing.py` | Unit tests for `hash_password` and `verify_password`; `test_verify_does_not_raise_on_mismatch` fixed to assert return value directly (was fragile try/except) |
| `app/tests/test_encryption.py` | Unit tests for all four encryption functions + `InvalidToken` re-export |
| `app/tests/test_vault_service.py` | Integration tests for vault CRUD with in-memory SQLite; `db` fixture now uses `poolclass=StaticPool` so `create_all()` tables are visible to all test sessions |
| `app/tests/test_auth_routes.py` | Full-stack integration tests via `TestClient` (in-memory DB, full middleware stack) — all auth routes, session state, redirect behaviour, user-enumeration resistance |

#### ❌ Still To Implement (remaining Phase 1 stubs)

_None — all Phase 1 files are implemented and hardened._ 🎉

#### 🔑 Key Implementation Notes for Remaining Work

**Session key storage convention** (auth_service → vault_service contract):
```python
# auth_service stores key as base64 string (JSON-serialisable):
import base64
request.session["encryption_key"] = base64.urlsafe_b64encode(raw_key).decode()

# vault_service reads it back as raw bytes:
raw_key = base64.urlsafe_b64decode(request.session["encryption_key"])
```

**`InvalidToken` handling in vault_service** — always catch at the service layer.
Import `InvalidToken` from this module (not from `cryptography.fernet` directly — it is re-exported to keep callers decoupled from the underlying library):
```python
from app.security.encryption import decrypt_field, InvalidToken

try:
    username = decrypt_field(entry.username_encrypted, raw_key)
except InvalidToken:
    # log non-sensitive: "decryption failed for entry {id}"
    raise HTTPException(status_code=500, detail="Unable to decrypt entry.")
```

**`ValueError` from `derive_key()` in auth_service** — catch at the service layer.
`derive_key()` raises `ValueError` if the stored `kdf_salt` decodes to the wrong byte length (indicates DB corruption). Never let this propagate to the browser:
```python
from app.security.encryption import derive_key

try:
    raw_key = derive_key(master_password, user.kdf_salt)
except ValueError:
    # log non-sensitive: "kdf_salt length invalid for user {id}"
    raise HTTPException(status_code=500, detail="Login failed. Please contact support.")
```

**Auth guard exempt paths** — do not redirect these to `/login`:
- `GET /login`, `POST /login`
- `GET /setup`, `POST /setup`
- `GET /static/*`
