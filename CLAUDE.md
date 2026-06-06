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
| `app/routes/ai.py` | Thin route handlers for all GenAI features (Phase 7), delegating to `ai_service` |
| `app/routes/api.py` | `/api/v1/` JSON REST API endpoints for the browser extension (Phase 10) |
| `app/services/` | Business logic: auth service, vault CRUD service |
| `app/services/ai_service.py` | Anthropic Claude API client; metadata-only AI features; metadata extraction helpers — never accepts raw password/username as a parameter (Phase 7) |
| `app/security/` | Encryption service (Fernet wrap/unwrap), key derivation, password hashing |
| `app/security/tokens.py` | JWT access + refresh token generation and verification via `PyJWT` (Phase 10) |
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
3. **Phase 3 (TOTP 2FA):** Time-based One-Time Password two-factor authentication using `pyotp`; QR code setup flow; recovery codes; 2FA enforce/disable per user; session step-up after password check.
4. **Phase 4 (UX Improvements):** Search and category filtering, password generator, dark mode, responsive layout improvements, password visibility toggle, copy-to-clipboard with auto-clear, password strength indicator, password import/export (KeePass XML / LastPass CSV).
5. **Phase 5 (Engineering Quality):** pytest coverage (unit + integration), Ruff linting, full type hints, structured logging, README with screenshots, architecture documentation, threat model document.
6. **Phase 6 (DevSecOps):** Dockerfile, docker-compose, GitHub Actions CI pipeline, `pip-audit` dependency scanning, trufflehog secret scanning, container hardening (non-root user, minimal base image), cloud deployment on **AWS EC2 t3.micro** (nginx reverse proxy + TLS via certbot + systemd service).
7. **Phase 7 (GenAI Integration):** AI-powered security intelligence using Claude API — password strength analyzer, smart entry assistant, breach detection via HaveIBeenPwned. **Critical security rule:** only plaintext metadata (`title`, `website`, `category`, complexity metrics, timestamps) is ever sent to an external API — passwords, usernames, and notes are never transmitted.
8. **Phase 8 (Multi-User Support):** Registration system, username-based login, user isolation hardening, admin dashboard, per-user settings, email verification and password reset.
9. **Phase 9 (Mobile PWA):** Mobile-first responsive UI overhaul, Progressive Web App (manifest + service worker), installable on Android home screen, pagination, offline static-asset caching.
10. **Phase 10 (Browser Extension):** Chrome/Firefox extension with auto-fill, quick-search popup, and `/api/v1/` REST API backend with JWT auth — replaces the Flutter native app plan.

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
| `app/tests/test_auth_routes.py` | Full-stack integration tests via `TestClient` (in-memory DB, full middleware stack) — all auth routes, session state, redirect behaviour, user-enumeration resistance; SonarQube S2068 fix — renamed `_VALID_PASSWORD` / `_SHORT_PASSWORD` / `_WRONG_PASSWORD` constants to `_VALID_CREDENTIAL` / `_SHORT_CREDENTIAL` / `_WRONG_CREDENTIAL` to avoid hardcoded-credential false positives |

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

### Phase 2 — Security Hardening — Status: ✅ Complete

#### ✅ Completed

| File | What was done |
|---|---|
| `app/security/encryption.py` | Replaced PBKDF2HMAC key derivation with Argon2id (`hash_secret_raw`, `Type.ID`); OWASP-recommended parameters: `time_cost=3`, `memory_cost=65536` (64 MiB), `parallelism=4`; function signature unchanged so no callers required updating; module docstring updated with upgrade rationale and breaking-change warning |
| `app/security/encryption.py` | Added `encrypt_field_gcm()` / `decrypt_field_gcm()` — AES-256-GCM with random 12-byte nonce; storage format `base64url(nonce‖ciphertext‖tag)`; `InvalidTag` caught internally and re-raised as `InvalidToken` for caller consistency; Fernet functions kept permanently for legacy-entry decryption; `_GCM_NONCE_BYTES` constant; `AESGCM` + `InvalidTag` imports; updated `__all__` and module docstring |
| `app/tests/test_encryption.py` | Added `TestDeriveKeyArgon2id` (3 tests): proves Argon2id output differs from PBKDF2HMAC, confirms `Type.ID` variant is used, confirms `Type.I` produces a different result — regression guards for the algorithm upgrade; fixed SonarQube S2068 — renamed local variable `password` → `kdf_input` in two tests to avoid hardcoded-credential false positives |
| `app/tests/test_encryption.py` | Added `TestEncryptFieldGcm` (11 tests) and `TestDecryptFieldGcm` (14 tests): round-trips, tamper detection (ciphertext, tag, nonce), cross-algorithm isolation guards (Fernet token rejected by GCM and vice versa), full derive→encrypt→decrypt integration |
| `app/security/encryption.py` | Added `get_cipher(version, key)` factory — returns `(encrypt_fn, decrypt_fn)` closures pre-bound to `key`; routes `"fernet"` → Fernet pair, `"aesgcm"` → GCM pair; raises `ValueError` on unknown version; `Callable` import from `collections.abc`; updated `__all__` |
| `app/tests/test_encryption.py` | Added `TestGetCipher` (15 tests): round-trips for both versions, token format checks, key-binding verification, wrong-key raises `InvalidToken`, cross-algorithm isolation guards, unknown/empty/wrong-case version raises `ValueError` |
| `app/models/vault_entry.py` | Added `encryption_version: Mapped[str]` column — `server_default="fernet"` (stamps existing rows on migration), `default="fernet"` (ORM fallback); sits above the encrypted field columns with inline comment explaining "fernet" / "aesgcm" values |
| `app/migrations/versions/a9cefaea1f22_add_encryption_version_to_vault_entries.py` | Alembic migration — schema-only `ADD COLUMN encryption_version VARCHAR NOT NULL DEFAULT 'fernet'`; spurious `_alembic_tmp_users` drop/create removed from autogenerate output; upgrade/downgrade comments explain why data is not touched here |
| `app/services/vault_service.py` | Rewrote to use `get_cipher()` factory throughout — removed direct `encrypt_field`/`decrypt_field` imports; `_decrypt_entry()` now accepts optional `db` parameter and performs lazy re-encryption (Fernet → AES-GCM, all three fields atomically) on first read; `create_entry()` always writes `encryption_version="aesgcm"`; `update_entry()` re-encrypts using the entry's current algorithm so ciphertext stays consistent, then passes `db` to `_decrypt_entry()` which handles the GCM upgrade atomically; lazy re-encryption failure is non-fatal (logs exception, resets in-memory version to "fernet", retries on next read) |
| `app/tests/test_vault_service.py` | Added `decrypt_field_gcm` import; fixed two existing assertions that checked for Fernet `"gAAAAA"` prefix (now verify `encryption_version=="aesgcm"` + GCM round-trip); added `TestEncryptionVersioning` (7 tests): new entries store `"aesgcm"`, `get_entry` / `get_entries` upgrade legacy Fernet rows, version stays `"fernet"` on wrong-key failure, update of sensitive field stamps `"aesgcm"`, plaintext-only update still triggers lazy re-encryption via `_decrypt_entry(db=db)` |
| `app/config/settings.py` | Added `ENVIRONMENT: str = "production"` field — fail-secure default; drives `https_only` on `SessionMiddleware` in `main.py`; set to `"development"` in `.env` to allow `http://` during local dev; changed `SESSION_TIMEOUT_MINUTES` default from 30 → 10 per OWASP Session Management Cheat Sheet §Session Expiration |
| `app/main.py` | `https_only` now driven by `settings.ENVIRONMENT != "development"` (True in production, False only in local dev); `same_site` hardened from `"lax"` → `"strict"` (strongest SameSite policy — cookie never sent on any cross-site request); inline comments explain both decisions; `.env` and `.env.example` updated with `ENVIRONMENT` variable documentation |
| `app/middleware/csrf.py` | New — Synchronizer Token Pattern CSRF protection via `BaseHTTPMiddleware`; token generated with `secrets.token_hex(32)` (256 bits) and stored in `session["csrf_token"]`; exposed via `request.state.csrf_token` for templates; mutating methods (POST/PUT/PATCH/DELETE) validated with `secrets.compare_digest`; 403 on missing or mismatched token; `await request.body()` called before `await request.form()` to pre-set `_body` on Starlette's `_CachedRequest` so downstream route handlers receive the full body via `wrapped_receive()` (avoids empty-body 422 bug) |
| `app/middleware/csrf.py` | **Bug fix** — added `token_was_fresh` flag to distinguish session-expiry races from genuine CSRF attacks; when the session had no CSRF token on arrival (expired session replaced by background request e.g. Chrome DevTools probe), CSRF mismatch now returns 303 redirect to `/login` instead of a confusing 403; active-session CSRF failures (token_was_fresh=False) still return 403; module docstring updated with "SESSION EXPIRY AND CSRF FAILURES" section explaining the Chrome DevTools race scenario |
| `app/main.py` | `CSRFMiddleware` imported and wired between `AuthGuard` (inner) and `SessionMiddleware` (outer) — has session access, protects auth-exempt paths `/login` and `/setup`; module docstring updated to document three-layer middleware order |
| `app/templates/` (5 files) | Added `<input type="hidden" name="csrf_token" value="{{ request.state.csrf_token }}">` to all 8 POST forms across `login.html`, `setup.html`, `vault.html` (logout nav), `entry_form.html` (logout nav + entry form), `entry_detail.html` (logout nav + delete form) |
| `app/tests/test_auth_routes.py` | Added `_get_csrf_token(client, url)` helper (GET + regex parse); updated both fixtures (`client_with_vault`, `authenticated_client`) and all POST test calls to include CSRF token; added `TestCSRFProtection` class (8 tests — 7 original + `test_stale_csrf_token_on_fresh_session_redirects_to_login` covering the token_was_fresh=True→303 redirect path); updated `test_post_without_csrf_token_returns_403` to do prior GET so it tests active-session scenario correctly |
| `app/middleware/csp.py` | New — `Content-Security-Policy` response header via `BaseHTTPMiddleware`; directives: `script-src 'self'` (no inline scripts, no external CDNs, no `unsafe-eval`), `style-src 'self' 'unsafe-inline'` (Tailwind runtime style injection), `form-action 'self'` (blocks form hijacking), `frame-ancestors 'none'` (clickjacking prevention), `base-uri 'self'` (blocks `<base>` injection), `object-src 'none'` (disables plugins), `connect-src 'self'` (blocks XSS data exfiltration via fetch); policy pre-built as a module-level constant; `_SELF` constant eliminates repeated `'self'` literals (SonarQube S1192); wired as outermost middleware so header appears on ALL responses including CSRF 403s and session errors; **security-review hardening**: added `X-Frame-Options: DENY` (`_X_FRAME_OPTIONS_NAME/VALUE` constants) for legacy-browser clickjacking protection and `X-Content-Type-Options: nosniff` (`_X_CONTENT_TYPE_OPTIONS_NAME/VALUE`) to block MIME-sniffing attacks — both stamped on every response alongside CSP |
| `app/main.py` | `CSPMiddleware` imported and added last (`app.add_middleware(CSPMiddleware)` — outermost layer); middleware order docstring updated to document the four-layer stack and explain why CSP must be outermost |
| `app/static/js/tailwind.min.js` | Tailwind Play CDN script (398 KB) self-hosted at `/static/js/` — eliminates the `https://cdn.tailwindcss.com` external CDN dependency so `script-src 'self'` needs no external domain; confirmed script contains no `eval` or `new Function` calls so `unsafe-eval` is not needed |
| `app/static/js/datetime.js` | UTC→local time converter extracted from `base.html` inline `<script>` block; CSP-compliant external file |
| `app/static/js/entry_detail.js` | Password toggle, clipboard copy, and delete confirm functions extracted from `entry_detail.html` inline `<script>` block; reads password from `<input type="hidden" id="sv-password-value">` (Jinja2 auto-escapes value in attribute context); username copy button reads value from `data-copy` attribute; all event listeners use `addEventListener` — zero `onclick`/`onsubmit` attributes remain |
| `app/static/js/entry_form.js` | Password field visibility toggle extracted from `entry_form.html` inline `<script>` block; event listener replaces the `onclick` attribute |
| `app/templates/base.html`, `entry_detail.html`, `entry_form.html` | Removed all 3 inline `<script>` blocks and 7 inline `onclick`/`onsubmit` event handler attributes; replaced with `<script src="/static/js/...">` external file references; `entry.password` server-rendered value moved from a JS string literal to `<input type="hidden" id="sv-password-value" value="{{ entry.password }}">` (CSP-safe and equivalent security — password is in HTML either way) |
| `app/tests/test_csp.py` | New — 20 tests in three classes: `TestCSPHeaderPresence` (6 tests — header present on GET, unauthenticated redirect, CSRF 403, unknown-path redirect; value matches `CSP_HEADER_VALUE` constant), `TestCSPDirectiveValues` (8 tests — `script-src` has no `unsafe-inline`/`unsafe-eval`, `frame-ancestors 'none'`, `form-action 'self'`, `object-src 'none'`, `base-uri 'self'`, `connect-src 'self'`; all `_CSP_DIRECTIVES` keys present in live header), `TestDefenceInDepthHeaders` (6 tests — `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff` verified on GET, 302 redirect, and CSRF 403; imports `_X_FRAME_OPTIONS_VALUE` / `_X_CONTENT_TYPE_OPTIONS_VALUE` constants so the tests stay in sync with the middleware) |

| `app/middleware/encrypted_session.py` | New — replaces `SessionMiddleware`; Fernet (AES-128-CBC + HMAC-SHA256) encrypts the full cookie payload so the session is opaque; `_derive_fernet_key()` uses HKDF-SHA256 on `SECRET_KEY` (no new env variable); `ttl=max_age` enforces session expiry at the crypto layer; tampered/expired cookies log a warning and return `{}`; logout triggers `Max-Age=0` delete-cookie; raw ASGI `__call__` pattern (same as Starlette's own `SessionMiddleware`) |
| `app/main.py` | Removed `SessionMiddleware` import; added `EncryptedSessionMiddleware` with identical parameters and stack position; module docstring updated to reflect four-layer middleware stack with encrypted sessions |
| `app/tests/test_encrypted_session.py` | New — 20 tests: `TestCookieIsOpaque` (Phase 1 base64-decode attack fails; Fernet decrypt succeeds with correct key; wrong key raises `InvalidToken`), `TestSessionRoundTrip` (write→read, empty before write, persists across requests, cookie refreshed each response), `TestTamperedCookie` (empty session, `Max-Age=0` delete header, fresh session after clear), `TestLogoutDeletesCookie` (`Max-Age=0` on `session.clear()`, empty after clear, no spurious header when session never existed), `TestKeyDerivation` (deterministic, different secrets differ, valid Fernet key, 44-char base64url), plus integration test confirming vault cookie is opaque end-to-end |
| `app/middleware/rate_limit.py` | New — `_AttemptRecord` dataclass (`failures`, `locked_until`, `last_failure_at`); `_LoginAttemptTracker` (thread-safe in-memory per-IP failure counter with `threading.Lock`; `is_locked()` evicts expired lockout records AND sub-lockout records past `failure_window_seconds` to prevent unbounded memory growth; `record_failure()` sets `last_failure_at`; `record_success()`, `failure_count()`, `reset_all()` API; `failure_window_seconds=3600` default); `LoginRateLimitMiddleware` (intercepts POST /login only; pre-flight 429 with `Retry-After` header (RFC 6585 §4); records failure on 401, resets on 303, ignores 422/500; `call_next` typed as `Callable[[Request], Awaitable[Response]]`); `_lockout_page()` inline HTML helper; `_DEFAULT_FAILURE_WINDOW_SECONDS` constant; `_STATUS_FAILURE: int` / `_STATUS_SUCCESS: int` annotated; string forward reference on `_tracker_override` removed; `field` unused import removed; "epoch time" docstring corrected to "monotonic clock value" |
| `app/main.py` | `LoginRateLimitMiddleware` imported and wired between `AuthGuard` (inner) and `CSRFMiddleware` (outer); tracker created explicitly as `_login_tracker` and stored on `app.state.login_tracker` so test fixtures can call `reset_all()` without reaching into middleware internals; middleware order docstring updated to document the five-layer stack |
| `app/tests/conftest.py` | New — `login_tracker_reset` autouse fixture calls `app.state.login_tracker.reset_all()` before every test; prevents cross-test contamination where accumulated wrong-password failures in shared TestClient would lock out the loopback IP and cause unrelated login tests to receive 429 instead of 303/401 |
| `app/tests/test_rate_limit.py` | New — 252 total suite tests; rate-limit module contributes 39 tests across four classes: `TestLoginAttemptTracker` (11 unit tests — adds `test_sub_lockout_record_evicted_after_failure_window`); `TestLoginRateLimitMiddleware` (8 tests — adds `test_429_includes_retry_after_header`); `TestRateLimitInFullStack` (5 tests — adds `test_429_carries_csp_header` and `test_429_carries_retry_after_header`); `TestLockoutPageFormatting` (15 parametrized tests — all seconds/minutes singular/plural branches, HTML structure, `/login` return link); CI-tolerance widened to `55 <= remaining <= 60`; S2068 SonarQube false-positives avoided with `_WRONG_CREDENTIAL` constant |
| `pytest.ini` | New — `filterwarnings` suppresses FastAPI's internal `HTTP_422_UNPROCESSABLE_ENTITY` deprecation noise (FastAPI internals issue, not our code); remove once FastAPI ships the renamed-constant fix |
| `app/main.py` | Added `POST /dev/reset-lockout` endpoint (registered only when `ENVIRONMENT=development`); calls `app.state.login_tracker.reset_all()` to clear all in-memory lockout counters without a server restart; guarded by an `if settings.ENVIRONMENT == "development":` block so the route is never mounted in production; documented with a curl example |
| `app/main.py` | Added rotating file logger — `logs/app.log` (10 MB × 5 backups); configured at import time via `logging.basicConfig` with `RotatingFileHandler`; `logs/` added to `.gitignore`; DEBUG level in development, INFO in production; noisy third-party loggers (`uvicorn.access`, `watchfiles`, `python_multipart`) suppressed to WARNING — `python_multipart` in particular fires byte-range DEBUG lines for every form field on every POST, annotating positions of sensitive fields; Phase 5 will replace with structured JSON logging and a dedicated security-audit stream |

#### ❌ Still To Implement

_None — all Phase 2 files are implemented and hardened._ 🎉

> ⚠️ **Re-encryption cannot run in Alembic** — the encryption key only exists in session memory after login and must never touch disk. Alembic adds the `encryption_version` column only. The actual re-encryption is a lazy per-entry operation in `vault_service` at first read after upgrade. All read/write paths must check `encryption_version` and call the correct algorithm.

---

### Phase 3 — TOTP Two-Factor Authentication — Status: 🔴 Not Started

> **Goal:** Add a second authentication factor so a stolen master password alone cannot unlock the vault.
> TOTP (RFC 6238) is the industry standard — supported by Google Authenticator, Authy, 1Password, Bitwarden, etc.
> 2FA is optional per-user: users who skip setup continue using password-only login.

| File / Area | What's needed |
|---|---|
| `app/models/user.py` | Add `totp_secret: Mapped[str \| None]` (NULL = 2FA disabled; stored AES-GCM encrypted — same key as vault), `totp_enabled: Mapped[bool]` (default False) |
| `app/models/recovery_code.py` | `RecoveryCode` ORM model — `user_id` FK, `code_hash` (Argon2id hash of 8-char alphanumeric code), `used_at` timestamp (NULL = unused); 8 codes generated at 2FA setup, each usable exactly once |
| `app/migrations/` | New Alembic migration for `totp_secret`, `totp_enabled` columns on `users` and new `recovery_codes` table |
| `app/security/totp.py` | New module — `generate_secret() -> str` (`pyotp.random_base32()`); `get_provisioning_uri(secret, issuer) -> str` (for QR code); `verify_totp(secret, token, valid_window=1) -> bool`; `generate_recovery_codes() -> list[str]` (8 × 8-char codes, `secrets.token_urlsafe`); `hash_recovery_code(code) -> str` (Argon2id); `verify_recovery_code(code, hash) -> bool` |
| `app/services/auth_service.py` | `enable_2fa(user_id, secret, confirmation_token, db) -> list[str]` — verifies the first TOTP code before activating, returns recovery codes; `disable_2fa(user_id, db)`; extend `login()` to return a `requires_totp=True` flag when 2FA is enabled (so the route redirects to the TOTP prompt instead of directly to /vault) |
| `app/routes/auth.py` | Add `GET /2fa/setup` + `POST /2fa/setup` (render QR code, accept confirmation code, return recovery codes); `GET /2fa/verify` + `POST /2fa/verify` (TOTP prompt mid-login); `POST /2fa/disable`; update `POST /login` flow to redirect to `/2fa/verify` when `requires_totp=True`; use `session["pending_user_id"]` for the mid-login state so AuthGuard still blocks /vault until 2FA is passed |
| `app/templates/2fa_setup.html` | QR code image (`<img src="data:image/png;base64,...">` — generated server-side with `qrcode[pil]`); manual secret entry fallback; recovery codes display (shown once — "save these now" warning); confirm-first-code form |
| `app/templates/2fa_verify.html` | 6-digit TOTP code input; "Use recovery code" link |
| `app/templates/2fa_recovery.html` | Recovery code text input; redirects back to TOTP verify on wrong code |
| `app/middleware/auth_guard.py` | Exempt `/2fa/verify` and `/2fa/recovery` from the encryption-key check (user is mid-login: password passed, TOTP not yet); add `/2fa/*` to setup exempt paths |
| `requirements.txt` | Add `pyotp>=2.9` and `qrcode[pil]>=7.4` |
| `app/tests/test_totp.py` | Unit tests: secret generation format, URI format, TOTP verification (valid/invalid/expired), recovery code generation (length, uniqueness), recovery code hashing round-trip |
| `app/tests/test_auth_routes.py` | Integration tests: 2FA setup flow, TOTP verify blocks vault before code, recovery code invalidated after use, disable 2FA, login without 2FA still works |

> ⚠️ **TOTP secret storage:** The secret must be encrypted at rest — treat it like a vault credential. Use `encrypt_field_gcm(secret, encryption_key)` and store the ciphertext in `users.totp_secret`. Decrypt at login time the same way vault fields are decrypted. Never log the plaintext secret.
>
> ⚠️ **Mid-login session state:** Use `session["pending_user_id"]` to track a user who has passed the password check but not yet the TOTP check. Clear this key on: TOTP success (replace with full session), TOTP failure after N attempts (lock), or any navigation away from `/2fa/verify`. `AuthGuard` must NOT grant access to the vault based on `pending_user_id` — only a fully established `encryption_key` in session grants access.

---

### Phase 4 — UX Improvements — Status: 🔴 Not Started

| File / Area | What's needed |
|---|---|
| `app/routes/vault.py` | Title/website text search and category filtering as query params on `GET /vault` (e.g. `?q=github&category=Work`) — no separate search route; keeps the dashboard URL canonical and avoids conflict with Phase 7's AI search endpoint |
| `app/services/vault_service.py` | `search_entries()` — filter on plaintext fields only (`title`, `website`, `category`); never decrypt to search |
| `app/templates/vault.html` | Search bar; category filter dropdown; dark mode toggle |
| `app/templates/entry_form.html` | Password generator button; password strength indicator |
| `app/static/js/` | Clipboard auto-clear after configurable timeout; dark mode persistence (localStorage); password generator logic |
| `app/routes/vault.py` | `GET /vault/export` → KeePass XML / LastPass CSV download (decrypted — warn user); `POST /vault/import` → parse and bulk-insert entries; import preview before commit |
| `app/services/vault_service.py` | `export_entries_csv()`, `export_entries_xml()`, `import_entries_csv()`, `import_entries_xml()` — import always re-encrypts with current key |
| `app/templates/import_export.html` | Import/export UI with format selector and security warning ("exported file contains plaintext passwords — store securely") |

---

### Phase 5 — Engineering Quality — Status: 🔴 Not Started

| File / Area | What's needed |
|---|---|
| `app/tests/` | Expand coverage to ≥80%; add integration tests for Phase 2 + 3 + 4 features |
| All `app/` modules | Full type hints on all public functions and classes |
| All `app/` files | `ruff check app/` zero violations |
| All `app/` files | Structured logging — verify no secrets appear in any log output |
| `README.md` | Project overview, architecture diagram, setup instructions, screenshots, security design notes, roadmap |
| `docs/architecture.md` | Architecture documentation — include the server-side decryption limitation, middleware order reasoning, session cookie encryption decision, and 2FA mid-login session design |
| `docs/threat_model.md` | Threat model document — must cover: XSS (catastrophic for a password manager; mitigated by CSP + Jinja2 auto-escape), session cookie exposure (mitigated by encrypted sessions), server-side decryption (accepted trade-off), Python memory zeroing limitation (GC does not zero memory; `bytearray` helps but strings are immutable — document as known limitation), TOTP secret exposure |
| `docs/security_audit_log.md` | Security audit logging strategy — login success/failure, 2FA events, admin actions, suspicious activity; logged to a dedicated stream separate from app debug logs; must never contain passwords, keys, or decrypted values |

---

### Phase 6 — DevSecOps + Cloud Deployment — Status: 🔴 Not Started

| File / Area | What's needed |
|---|---|
| `Dockerfile` | Multi-stage build; non-root user; minimal base image (`python:3.13-slim`) |
| `docker-compose.yml` | Full stack up from cold machine; volume mount for `securevault.db` and `logs/` |
| `.github/workflows/ci.yml` | GitHub Actions CI — runs `pytest`, `ruff check`, `pip-audit` on every push; fails on violations |
| `pip-audit` | Dependency vulnerability scan — zero known critical CVEs required |
| Trufflehog / GitHub secret scanning | Secret scanning enabled; no secrets committed to the repository |
| `.dockerignore` | Exclude `.env`, `*.db`, `__pycache__`, `venv/`, `.git/`, `logs/` from Docker build context — prevents secrets and vault data entering the image |
| Cloud deployment | **AWS EC2 t3.micro** (free tier 12 months, then ~$8/month); Ubuntu 24.04 LTS; stack: Route 53 (DNS) → EC2 → nginx (443/TLS) → uvicorn (8000, loopback) → FastAPI; SQLite on a separate EBS volume so the DB survives instance replacement; Elastic IP for a stable public address |
| `nginx/securevault.conf` | nginx config — HTTP→HTTPS redirect, TLS via certbot (Let's Encrypt), TLS 1.2+ with strong cipher suite, `proxy_pass http://127.0.0.1:8000`, `X-Forwarded-For` forwarding for correct rate-limiter IP tracking |
| `systemd/securevault.service` | systemd unit file — runs uvicorn as a non-root user, `Restart=always`, `EnvironmentFile=/etc/securevault/env` (secrets never in the unit file itself) |
| `docs/deployment.md` | Step-by-step AWS EC2 deployment guide: launch t3.micro (Ubuntu 24.04), security group (ports 22/80/443 only), Elastic IP, nginx + certbot install, systemd unit, EBS volume for DB, GitHub Actions SSH deploy workflow, server hardening (UFW, fail2ban, non-root app user) |

> 💡 **Why AWS EC2 over Azure App Service:** EC2 gives you full OS access — you configure nginx, TLS, and systemd yourself. This teaches infrastructure skills that transfer everywhere. Azure App Service abstracts all of this away, which is faster to deploy but teaches less. Use EC2 for learning depth; App Service if you just need it live quickly.
>
> ⚠️ **Rate limiter and reverse proxy:** When nginx is in front, `request.client.host` is the proxy's IP, not the user's. Update `LoginRateLimitMiddleware` to read `X-Forwarded-For` (only when `ENVIRONMENT=production` — never trust this header in dev). Document this in `docs/deployment.md`.

---

### Phase 7 — GenAI Integration — Status: 🔴 Not Started

> **Goal:** Add AI-powered security intelligence while keeping all sensitive data strictly local.
> **Scope (3 features):** Strength Analyzer, Smart Entry Assistant, Breach Detection. Auto-categorization and natural language search were descoped — their value/effort ratio is too low for a personal vault.
> **Critical:** Never send decrypted passwords, usernames, or notes to any external AI API.
> Only metadata is safe to transmit (see [GenAI Security Rules](#genai-security-rules-applies-to-all-phases)).

| File / Area | What's needed |
|---|---|
| `app/schemas/ai_metadata.py` | `VaultMetadataForAI` dataclass — fields: `title`, `website`, `category`, `password_length`, `has_uppercase`, `has_numbers`, `has_symbols`, `created_at`, `updated_at` only; no `password`, `username`, `notes` fields exist on this type, making it structurally impossible to pass sensitive data to AI functions |
| `app/services/ai_service.py` | Anthropic Claude API client; all AI feature functions accept `list[VaultMetadataForAI]` — never `list[VaultEntry]`; metadata extraction helper converts `VaultEntry` → `VaultMetadataForAI` (strips all encrypted fields) before any API call |
| `app/routes/ai.py` | Thin route handlers for all AI features, delegating to `ai_service` |
| `app/config/settings.py` | Add `ANTHROPIC_API_KEY` and `HIBP_API_KEY` settings |
| `.env` | Add `ANTHROPIC_API_KEY` and `HIBP_API_KEY` variables |
| **7.1 Password Strength Analyzer** | `GET /vault/analyze` — extract metadata only, send to Claude API, return prioritised recommendations (potential reuse indicators flagged by same length + complexity metrics; stale passwords ≥6 months; weak by metrics; incomplete entries); "Analyze Vault" button on dashboard; results in security report modal |
| **7.2 Smart Entry Assistant** | `POST /entry/smart-fill` — user pastes any text (email, URL, app name); Claude extracts title, website, username, category; pre-fills add-entry form; user reviews before saving; "Smart Fill" button on `entry_form.html` |
| **7.3 Breach Detection** | `GET /vault/breach-check` — checks website domain names (never passwords) against HaveIBeenPwned API; breach warning badges on dashboard; results cached in a `breach_cache(domain, is_breached, checked_at)` SQLite table for 24 hours — survives server restarts unlike in-memory cache |
| `app/models/breach_cache.py` | `BreachCache` ORM model — `domain`, `is_breached`, `checked_at`; TTL check in `ai_service` (re-fetch if `checked_at` > 24 h ago) |
| `app/migrations/` | New Alembic migration for `breach_cache` table |

---

### Phase 8 — Multi-User Support — Status: 🔴 Not Started

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

### Phase 9 — Mobile PWA — Status: 🔴 Not Started

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

### Phase 10 — Browser Extension — Status: 🔴 Not Started

> **Goal:** Chrome/Firefox extension that auto-fills credentials and provides quick vault search — far more useful day-to-day than a native mobile app.
> **Prerequisites:** Phase 6 (cloud deployment + HTTPS) · Phase 8 (Multi-User, for username-based auth).
> **Replaces:** the original Flutter native app plan (Phase 9 in old numbering).

| File / Area | What's needed |
|---|---|
| **Backend — REST API** | |
| `app/routes/api.py` | New router: `/api/v1/` JSON endpoints for vault CRUD + auth; consumed by extension |
| `app/schemas/api.py` | JSON request/response schemas for the REST API |
| `app/security/tokens.py` | JWT access + refresh token generation and verification (`PyJWT`); access token TTL 15 min; refresh token TTL 7 days |
| `app/routes/auth.py` | Add `POST /api/v1/login` → `{access_token, refresh_token}`; `POST /api/v1/refresh`; `POST /api/v1/logout` → revoke JTI |
| `app/models/revoked_token.py` | `RevokedToken` ORM model — revoked refresh token JTIs with expiry; checked only on refresh, not every request |
| `app/migrations/` | New Alembic migration for `revoked_tokens` table |
| `app/middleware/auth_guard.py` | Extend to accept `Authorization: Bearer <token>` on `/api/v1/*` routes |
| `app/main.py` | CORS configuration for extension origin (add extension ID to allowed origins in production) |
| **Extension frontend** | |
| `extension/manifest.json` | Manifest V3; permissions: `storage`, `activeTab`, `scripting`; host_permissions: `https://your-server/*` |
| `extension/popup/` | HTML + JS popup — login form (first time), vault search, click-to-fill button |
| `extension/content/autofill.js` | Content script — detect `<input type="password">` and associated username fields; inject fill buttons; never store passwords in extension storage beyond the current tab session |
| `extension/background/` | Service worker — token refresh logic; message bridge between popup and content script |
| `extension/` | `package.json` with build tooling (esbuild or webpack) to bundle the extension |
| `docs/extension.md` | Load unpacked extension guide; how to connect to local dev server vs. cloud server |

> ⚠️ **Extension security:** Credentials must NEVER be written to `chrome.storage` — only held in the service worker's in-memory state for the duration of the session. Tokens should be stored in `chrome.storage.session` (cleared on browser close) not `chrome.storage.local` (persists). The content script must not inject passwords directly into the DOM as attribute values — use the browser's native autofill APIs where possible, or post to the input value via `dispatchEvent` to avoid leaking via `data-*` attributes.

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
