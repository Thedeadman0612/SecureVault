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

---

## Progress Tracker

### Phase 1 — Status: 🟡 In Progress

#### ✅ Completed

| File | What was done |
|---|---|
| `app/models/user.py` | `User` ORM model — `id`, `password_hash`, `kdf_salt`, `created_at`, `updated_at`, relationship to `VaultEntry` |
| `app/models/vault_entry.py` | `VaultEntry` ORM model — `user_id` FK, plaintext fields (`title`, `website`, `category`), encrypted fields (`username_encrypted`, `password_encrypted`, `notes_encrypted`) |
| `app/database/session.py` | SQLAlchemy engine, `SessionLocal`, `get_db` dependency |
| `app/config/settings.py` | Pydantic `BaseSettings` loading `SECRET_KEY`, `DATABASE_URL`, `SESSION_TIMEOUT_MINUTES` from `.env` |
| `app/migrations/versions/9680c40ab116_initial_tables.py` | Alembic initial migration — creates `users` and `vault_entries` tables. Run: `alembic upgrade head` |
| `app/security/hashing.py` | `hash_password(plain) -> str` (Argon2id PHC string) · `verify_password(plain, hash) -> bool` (catches `VerifyMismatchError`, propagates all others) |
| `app/security/encryption.py` | `generate_kdf_salt() -> str` (32-byte CSPRNG, base64) · `derive_key(password, salt_b64) -> bytes` (PBKDF2HMAC SHA-256, 600k iters, salt-length guard) · `encrypt_field(value, raw_key) -> str` (Fernet token) · `decrypt_field(token, raw_key) -> str` (raises `InvalidToken` — re-exported for callers) |
| `app/templates/` | All 6 HTML templates created: `base.html`, `login.html`, `setup.html`, `vault.html`, `entry_form.html`, `entry_detail.html` |
| `app/static/` | CSS and JS asset directories created |
| `app/schemas/auth.py` | `SetupRequest` (password + confirm_password, min-length ≥12, match validator) · `LoginRequest` (password) · `MessageResponse` (message + success: bool = True) |
| `app/schemas/vault.py` | `VaultEntryCreate` (title + password required, sensitive fields documented) · `VaultEntryUpdate` (all fields optional) · `VaultEntryResponse` (decrypted field names: `username`, `password`, `notes`; includes `id`, timestamps) |
| `app/services/auth_service.py` | `setup_vault(password, db)` — Argon2id hash + KDF salt + create User row (rejects if user exists) · `login(password, db, session)` — verify hash, derive key, store base64 key + user_id in session · `logout(session)` — session.clear() |
| `app/services/vault_service.py` | `create_entry`, `get_entries`, `get_entry`, `update_entry`, `delete_entry` — all filter by user_id; encrypt on write, decrypt on read via `_decrypt_entry()`; `InvalidToken` → HTTP 500 |
| `app/routes/auth.py` | `GET /setup` (redirect to /login if vault exists) · `POST /setup` (validate → setup_vault → **redirect to /login** 303) · `GET /login` (redirect to /vault if session active) · `POST /login` (login → redirect to /vault 303) · `POST /logout` (logout → redirect to /login 303) |

#### ❌ Still To Implement (remaining Phase 1 stubs)

Implement in this order (each layer depends on the one below):

| File | What's needed |
|---|---|
| `app/middleware/auth_guard.py` | Starlette middleware — checks session for `encryption_key`, redirects to `/login` if missing; allows `/login`, `/setup`, `/static` through unauthenticated |
| `app/routes/auth.py` | `GET/POST /setup`, `GET/POST /login`, `POST /logout` |
| `app/routes/vault.py` | `GET /vault`, `GET/POST /entry/new`, `GET /entry/{id}`, `POST /entry/{id}/edit`, `POST /entry/{id}/delete` |
| `app/main.py` | FastAPI app init, `SessionMiddleware`, `AuthGuard` middleware, Jinja2 templates, include routers |
| `app/tests/test_hashing.py` | Unit tests for `hash_password` and `verify_password` |
| `app/tests/test_encryption.py` | Unit tests for all four encryption functions + edge cases |
| `app/tests/test_vault_service.py` | Integration tests for vault CRUD with encryption roundtrip |
| `app/tests/test_auth_routes.py` | Integration tests for setup/login/logout flow |

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
