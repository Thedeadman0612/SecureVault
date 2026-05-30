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

# Lint with auto-fix
ruff check app/ --fix

# Run tests with coverage report
pytest --cov=app --cov-report=term-missing

# Dependency vulnerability scan
pip-audit
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

> ⚠️ **Known limitation (Phase 1):** Default Starlette sessions are **signed but not encrypted** — session data (including the encryption key) is base64-readable from the raw cookie value. Phase 2 must switch to an encrypted session backend (e.g. `starlette-session` with `cryptography`-backed encryption) so the cookie is opaque even if intercepted. Redis is NOT required — an encrypted cookie store is sufficient for this local-first app.

**Middleware stack order — `AuthGuard` inner, `SessionMiddleware` outer:**
Starlette applies middleware in reverse-add order. `SessionMiddleware` must be added last (outermost) so it decodes the cookie and populates `request.session` **before** `AuthGuard` (inner) attempts to read `request.session["encryption_key"]`. Reversing the order means `AuthGuard` always sees an empty session and redirects every request to `/login`.

**Known architecture limitation — server-side decryption:**
This app decrypts vault entries on the server and renders plaintext HTML to the browser. It is "encrypted at rest" — NOT zero-knowledge. A compromised server runtime can observe decrypted secrets during active requests. This is an accepted trade-off for simplicity and educational clarity. A future client-side crypto architecture (WebCrypto + React SPA) would eliminate this, but is out of scope for current phases.

### Module Responsibilities

| Module | Purpose |
|---|---|
| `app/main.py` | FastAPI app init, middleware registration, router inclusion |
| `app/config/` | Settings via Pydantic `BaseSettings` (secret key, DB URL, session timeout) |
| `app/routes/` | Thin route handlers — validate input, call services, return responses |
| `app/routes/ai.py` | Thin route handlers for all GenAI features (Phase 6), delegating to `ai_service` |
| `app/routes/api.py` | `/api/v1/` JSON REST API endpoints for the native mobile client (Phase 9) |
| `app/services/` | Business logic: auth service, vault CRUD service |
| `app/services/ai_service.py` | Anthropic Claude API client; metadata-only AI features; metadata extraction helpers — never accepts raw password/username as a parameter (Phase 6) |
| `app/security/` | Encryption service (Fernet wrap/unwrap), key derivation, password hashing |
| `app/security/tokens.py` | JWT access + refresh token generation and verification via `PyJWT` (Phase 9) |
| `app/models/` | SQLAlchemy ORM models (`User`, `VaultEntry`) |
| `app/schemas/` | Pydantic request/response schemas |
| `app/database/` | SQLAlchemy engine, session factory, `get_db` dependency |
| `app/middleware/` | Auth guard (redirect unauthenticated requests to `/login`) |
| `app/templates/` | Jinja2 HTML templates |
| `app/templates_config.py` | Centralised `Jinja2Templates` instance; registers `format_datetime` global and `truncate_str` filter; imported by all route modules |
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
- **Never send to external AI APIs:** decrypted passwords, usernames, or notes — see [GenAI Security Rules](#genai-security-rules-applies-to-all-phases).

---

## Development Phases

Work is phased — do not implement features from a later phase during an earlier one:

1. **Phase 1 (MVP):** Setup/login flow, Fernet encryption, CRUD vault, plain HTML + Tailwind frontend, Alembic migrations.
2. **Phase 2 (Security Hardening):** CSRF protection, rate limiting + lockout, AES-256-GCM encryption upgrade, secure cookie hardening, Argon2id key derivation.
3. **Phase 3 (UX Improvements):** Search and category filtering, password generator, dark mode, responsive layout improvements, password visibility toggle, copy-to-clipboard with auto-clear, password strength indicator.
4. **Phase 4 (Engineering Quality):** pytest coverage (unit + integration), Ruff linting, full type hints, structured logging, README with screenshots, architecture documentation, threat model document.
5. **Phase 5 (DevSecOps):** Dockerfile, docker-compose, GitHub Actions CI pipeline, `pip-audit` dependency scanning, trufflehog secret scanning, container hardening (non-root user, minimal base image).
6. **Phase 6 (GenAI Integration):** AI-powered security intelligence using Claude API — password strength analyzer, security audit assistant, smart entry assistant, auto-categorization, natural language vault search, breach detection via HaveIBeenPwned. **Critical security rule:** only plaintext metadata (`title`, `website`, `category`, complexity metrics, timestamps) is ever sent to an external API — passwords, usernames, and notes are never transmitted.
7. **Phase 7 (Multi-User Support):** Registration system, username-based login, user isolation hardening, admin dashboard, per-user settings, email verification and password reset.
8. **Phase 8 (Mobile PWA):** Mobile-first responsive UI overhaul, Progressive Web App (manifest + service worker), installable on Android home screen, pagination, offline static-asset caching.
9. **Phase 9 (Native Mobile App):** Flutter Android/iOS app consuming `/api/v1/` REST API with JWT auth, biometric authentication (Keystore/Keychain), secure storage, auto-lock on background, push notifications for breach alerts.

---

## Progress Tracker

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

---

### Phase 2 — Security Hardening — Status: 🟡 In Progress

#### ✅ Completed

| File | What was done |
|---|---|
| `app/security/encryption.py` | Replaced PBKDF2HMAC key derivation with Argon2id (`hash_secret_raw`, `Type.ID`); OWASP-recommended parameters: `time_cost=3`, `memory_cost=65536` (64 MiB), `parallelism=4`; function signature unchanged so no callers required updating; module docstring updated with upgrade rationale and breaking-change warning |
| `app/security/encryption.py` | Added `encrypt_field_gcm()` / `decrypt_field_gcm()` — AES-256-GCM with random 12-byte nonce; storage format `base64url(nonce‖ciphertext‖tag)`; `InvalidTag` caught internally and re-raised as `InvalidToken` for caller consistency; Fernet functions kept permanently for legacy-entry decryption; `_GCM_NONCE_BYTES` constant; `AESGCM` + `InvalidTag` imports; updated `__all__` and module docstring |
| `app/tests/test_encryption.py` | Added `TestDeriveKeyArgon2id` (3 tests): proves Argon2id output differs from PBKDF2HMAC, confirms `Type.ID` variant is used, confirms `Type.I` produces a different result — regression guards for the algorithm upgrade; fixed SonarQube S2068 — renamed local variable `password` → `kdf_input` in two tests to avoid hardcoded-credential false positives |
| `app/tests/test_encryption.py` | Added `TestEncryptFieldGcm` (11 tests) and `TestDecryptFieldGcm` (14 tests): round-trips, tamper detection (ciphertext, tag, nonce), cross-algorithm isolation guards (Fernet token rejected by GCM and vice versa), full derive→encrypt→decrypt integration |

#### ❌ Still To Implement

| File / Area | What's needed |
|---|---|
| `app/security/encryption.py` | Add `get_cipher(version, key)` factory function that returns the right algorithm — keeps `if/else` version-routing out of the service layer |
| `app/models/vault_entry.py` | Add `encryption_version` column (default `"fernet"`; set to `"aesgcm"` after re-encryption) — lets the service layer choose the right algorithm per entry |
| `app/migrations/` | New Alembic migration for `encryption_version` column (schema only — no data touched) |
| `app/services/vault_service.py` | Lazy re-encryption on read: if `entry.encryption_version == "fernet"` → decrypt with Fernet → re-encrypt with AES-GCM → save → set `encryption_version = "aesgcm"`; happens transparently while the key is already in session |
| `app/middleware/csrf.py` | CSRF protection middleware (`starlette-csrf` or double-submit cookie pattern) |
| `app/middleware/` or `app/main.py` | Content Security Policy (CSP) response header — `script-src 'self'`, no inline scripts; critical for a password manager where XSS = vault compromise since decrypted secrets are rendered in the browser |
| `app/main.py` | Switch to an encrypted session backend (e.g. `starlette-session` with `cryptography`) — Phase 1 sessions are signed-only (base64-readable); Phase 2 must make them opaque to the browser |
| `app/middleware/rate_limit.py` | Login rate limiting + lockout (`slowapi` with `InMemoryLimiter` — no Redis dependency; or manual SQLite-backed attempt counter) |
| `app/main.py` | Set `https_only=True` and `same_site='strict'` on `SessionMiddleware` for production; add environment check to allow `https_only=False` in local dev only; reduce `SESSION_TIMEOUT_MINUTES` default to 10 |
| `app/main.py` | Wire CSRF middleware into middleware stack |

> ⚠️ **Re-encryption cannot run in Alembic** — the encryption key only exists in session memory after login and must never touch disk. Alembic adds the `encryption_version` column only. The actual re-encryption is a lazy per-entry operation in `vault_service` at first read after upgrade. All read/write paths must check `encryption_version` and call the correct algorithm.

---

### Phase 3 — UX Improvements — Status: 🔴 Not Started

| File / Area | What's needed |
|---|---|
| `app/routes/vault.py` | Title/website text search and category filtering as query params on `GET /vault` (e.g. `?q=github&category=Work`) — no separate search route; keeps the dashboard URL canonical and avoids conflict with Phase 6's AI search endpoint |
| `app/services/vault_service.py` | `search_entries()` — filter on plaintext fields only (`title`, `website`, `category`); never decrypt to search |
| `app/templates/vault.html` | Search bar; category filter dropdown; dark mode toggle |
| `app/templates/entry_form.html` | Password generator button; password strength indicator |
| `app/static/js/` | Clipboard auto-clear after configurable timeout; dark mode persistence (localStorage); password generator logic |

---

### Phase 4 — Engineering Quality — Status: 🔴 Not Started

| File / Area | What's needed |
|---|---|
| `app/tests/` | Expand coverage to ≥80%; add integration tests for Phase 2 + 3 features |
| All `app/` modules | Full type hints on all public functions and classes |
| All `app/` files | `ruff check app/` zero violations |
| All `app/` files | Structured logging — verify no secrets appear in any log output |
| `README.md` | Project overview, architecture diagram, setup instructions, screenshots, security design notes, roadmap |
| `docs/architecture.md` | Architecture documentation — include the server-side decryption limitation, middleware order reasoning, and session cookie encryption decision |
| `docs/threat_model.md` | Threat model document — must cover: XSS (catastrophic for a password manager; mitigated by CSP + Jinja2 auto-escape), session cookie exposure (mitigated by encrypted sessions), server-side decryption (accepted trade-off), Python memory zeroing limitation (GC does not zero memory; `bytearray` helps but strings are immutable — document as known limitation) |
| `docs/security_audit_log.md` | Security audit logging strategy — login success/failure, admin actions, suspicious activity; logged to a dedicated stream separate from app debug logs; must never contain passwords, keys, or decrypted values |

---

### Phase 5 — DevSecOps — Status: 🔴 Not Started

| File / Area | What's needed |
|---|---|
| `Dockerfile` | Multi-stage build; non-root user; minimal base image |
| `docker-compose.yml` | Full stack up from cold machine; volume mount for `securevault.db` |
| `.github/workflows/ci.yml` | GitHub Actions CI — runs `pytest`, `ruff check`, `pip-audit` on every push; fails on violations |
| `pip-audit` | Dependency vulnerability scan — zero known critical CVEs required |
| Trufflehog / GitHub secret scanning | Secret scanning enabled; no secrets committed to the repository |
| `.dockerignore` | Exclude `.env`, `*.db`, `__pycache__`, `venv/`, `.git/` from Docker build context — prevents secrets and vault data entering the image |

---

### Phase 6 — GenAI Integration — Status: 🔴 Not Started

> **Goal:** Add AI-powered security intelligence while keeping all sensitive data strictly local.
> **Critical:** Never send decrypted passwords, usernames, or notes to any external AI API.
> Only metadata is safe to transmit (see [GenAI Security Rules](#genai-security-rules-applies-to-all-phases)).

| File / Area | What's needed |
|---|---|
| `app/schemas/ai_metadata.py` | `VaultMetadataForAI` dataclass — fields: `title`, `website`, `category`, `password_length`, `has_uppercase`, `has_numbers`, `has_symbols`, `created_at`, `updated_at` only; no `password`, `username`, `notes` fields exist on this type, making it structurally impossible to pass sensitive data to AI functions |
| `app/services/ai_service.py` | Anthropic Claude API client; all AI feature functions accept `list[VaultMetadataForAI]` — never `list[VaultEntry]`; metadata extraction helper converts `VaultEntry` → `VaultMetadataForAI` (strips all encrypted fields) before any API call |
| `app/routes/ai.py` | Thin route handlers for all AI features, delegating to `ai_service` |
| `app/config/settings.py` | Add `ANTHROPIC_API_KEY` and `HIBP_API_KEY` settings |
| `.env` | Add `ANTHROPIC_API_KEY` and `HIBP_API_KEY` variables |
| **6.1 Password Strength Analyzer** | `GET /vault/analyze` — extract metadata only, send to Claude API, return prioritised recommendations (potential reuse indicators flagged by same length + complexity metrics — approximation only, actual reuse detection requires comparing passwords which is forbidden; stale passwords ≥6 months; weak by metrics; incomplete entries); "Analyze Vault" button on dashboard; results in security report modal |
| **6.2 Security Audit Assistant** | `GET /vault/audit` page — full vault security score 0–100; score breakdown (strength, age, reuse, coverage); prioritised action list |
| **6.3 Smart Entry Assistant** | `POST /entry/smart-fill` — user pastes any text; Claude extracts title, website, username, category; pre-fills add-entry form; user reviews before saving; "Smart Fill" button on `entry_form.html` |
| **6.4 Auto-categorization** | Real-time category suggestion when user types title + website; shown as clickable chip below category field; accepted or ignored by user; common categories: Work, Personal, Banking, Social, Entertainment, Shopping, Development |
| **6.5 Natural Language Vault Search** | `GET /vault/ai-search?q=` — deliberately separate from Phase 3's text search on `GET /vault?q=`; Claude interprets free-text query and maps to entry filters (e.g. "streaming services" → Netflix/Spotify; "old passwords" → entries not updated in 1 year); cache responses keyed on the query string for 5 minutes in-memory to avoid duplicate API calls on repeated searches |
| **6.6 Breach Detection Assistant** | `GET /vault/breach-check` — checks website domain names (never passwords) against HaveIBeenPwned API; breach warning badges on dashboard; results cached in a `breach_cache(domain, is_breached, checked_at)` SQLite table for 24 hours — survives server restarts unlike in-memory cache |
| `app/models/breach_cache.py` | `BreachCache` ORM model — `domain`, `is_breached`, `checked_at`; TTL check in `ai_service` (re-fetch if `checked_at` > 24 h ago) |
| `app/migrations/` | New Alembic migration for `breach_cache` table |

---

### Phase 7 — Multi-User Support — Status: 🔴 Not Started

> **Goal:** Support multiple independent users on the same instance.
> Foundation already exists: `user_id` FK on all vault entries ✅, all queries filter by `user_id` ✅, `kdf_salt` unique=True ✅.

| File / Area | What's needed |
|---|---|
| `app/models/user.py` | Add `username` (unique, not null) and `email` (unique, not null) columns; add `is_admin` boolean (first registered user becomes admin) |
| `app/migrations/` | New Alembic migration for `username`, `email`, `is_admin` columns |
| `app/schemas/auth.py` | Add `RegisterRequest` schema — username, email, password, confirm_password |
| `app/routes/auth.py` | Add `GET /register` + `POST /register`; update `POST /login` to authenticate by username |
| `app/templates/register.html` | Registration form template |
| `app/templates/login.html` | Add username field |
| `app/services/auth_service.py` | `register_user()` function; update `login()` to look up user by username |
| `app/routes/admin.py` | Admin dashboard at `/admin` — user list (never vault contents), deactivate/reactivate users; admin-only guard |
| `app/templates/admin.html` | Admin dashboard template |
| `app/models/user_settings.py` | `UserSettings` ORM model — session timeout preference, category preferences per user |
| `app/migrations/` | New Alembic migration for `user_settings` table |
| `app/config/settings.py` | Add `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `ADMIN_EMAIL` settings |
| `app/tests/test_user_isolation.py` | Integration tests specifically verifying cross-user data isolation |

> ⚠️ **SMTP credentials** (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`) must only be set via environment variables — never committed to the repository. Add them to `.env` (gitignored) and document them in `.env.example` with placeholder values only.

> 📝 **SQLite is intentional.** SQLite in WAL mode handles moderate read concurrency well but has real write-contention limits under high multi-user load. This is a deliberate trade-off for local-first simplicity and educational clarity — not a production multi-tenant choice. Document this explicitly in `docs/architecture.md`.

---

### Phase 8 — Mobile PWA — Status: 🔴 Not Started

> **Goal:** Make the vault fully usable on mobile and installable as a Progressive Web App. No backend changes needed.

| File / Area | What's needed |
|---|---|
| All templates | Mobile-first Tailwind CSS breakpoints; touch-friendly targets ≥44×44 px; responsive table → card layout on small screens; collapsible navigation |
| `app/static/manifest.json` | Web app manifest — name, icons, theme colour, `display: standalone` |
| `app/static/sw.js` | Service worker — cache static assets for offline access |
| `app/templates/base.html` | Link `manifest.json`; add mobile `<meta>` tags; bottom navigation bar on mobile |
| `app/static/icons/` | App icon set (192×192 and 512×512 PNG) for Android home screen |
| `app/routes/vault.py` | Paginate vault entries (10 per page) |

---

### Phase 9 — Native Mobile App — Status: 🔴 Not Started

> **Prerequisites:** Phase 5 (Docker/deployment) complete · Phase 7 (Multi-user) complete · HTTPS certificate in place.
> **Dual-auth trade-off:** This phase runs session-cookie auth (web) and JWT auth (mobile API) in parallel. This is intentional — browsers use sessions, native clients use tokens — but it creates two auth code paths in `auth_guard.py` and doubles auth test surface. Document this explicitly; don't try to unify them.

| File / Area | What's needed |
|---|---|
| `app/routes/api.py` | New router: `/api/v1/` JSON endpoints mirroring all HTML routes (vault CRUD + auth) |
| `app/schemas/api.py` | JSON request/response schemas for the REST API |
| `app/security/tokens.py` | JWT access + refresh token generation and verification (`PyJWT` — prefer over `python-jose` which has had CVEs and is less actively maintained) |
| `app/routes/auth.py` | Add `POST /api/v1/login` → returns `{access_token, refresh_token}`; `POST /api/v1/logout` → revoke refresh token (mark JTI as revoked in `revoked_tokens` table); access tokens expire naturally after short TTL (15 min) — do not blacklist access tokens per-request |
| `app/models/revoked_token.py` | `RevokedToken` ORM model — stores revoked refresh token JTIs with expiry timestamp; checked only on token refresh, not on every API request |
| `app/migrations/` | New Alembic migration for `revoked_tokens` table |
| `app/middleware/auth_guard.py` | Extend to accept `Authorization: Bearer <token>` on `/api/v1/*` routes |
| `app/main.py` | CORS configuration — required for browser-based clients (PWA or future React SPA served from a different origin); native Flutter HTTP calls do not need CORS but including it is harmless and future-proofs the API |
| `mobile/` | Flutter project — consumes `/api/v1/`; native biometric auth (flutter_local_auth); secure storage (iOS Keychain / Android Keystore via flutter_secure_storage); auto-lock when app backgrounds; push notifications for breach alerts |

---

## GenAI Security Rules (Applies to All Phases)

These rules apply to **all AI features across all phases**. Never violate them regardless of convenience or performance pressure.

### ❌ NEVER send to any external AI API

- Decrypted passwords
- Decrypted usernames
- Decrypted notes
- Encryption keys or KDF salts
- Session tokens or cookies

### ✅ SAFE to send to any external AI API

- `title`, `website`, `category` — plaintext fields stored unencrypted
- Password metadata (complexity metrics only, never the password itself):
  - `password_length`
  - `has_uppercase`, `has_numbers`, `has_symbols`
- `created_at`, `updated_at` timestamps
- Entry counts and category distribution statistics
- Website domain names (for breach detection — never paired with credentials)

### Enforcement in code

- `ai_service.py` functions must **never** accept `password`, `username`, or `notes` as parameters.
- A metadata extraction helper must strip all encrypted fields before constructing any API payload.
- Any AI feature that requires access to sensitive data must be implemented **entirely locally** without external API calls.
