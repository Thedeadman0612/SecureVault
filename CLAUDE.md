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
- `Argon2id` (Phase 2) derives the vault encryption key from the master password at login time. The salt for this is stored in `users.kdf_salt`. The derived key is held in-memory in the session only — never written to disk.

**What is encrypted vs. plaintext in `vault_entries`:**
- Encrypted (AES-256-GCM, stored as base64): `username`, `password`, `notes`. Legacy Fernet entries are re-encrypted lazily on first read.
- Plaintext (safe to store, used for search): `title`, `website`, `category`

**Session:** `EncryptedSessionMiddleware` (Phase 2) — Fernet-encrypted cookie using HKDF-derived key from `SECRET_KEY`. Session payload is fully opaque to the client. The derived vault encryption key is stored in the session dict and cleared on logout or timeout. Never log it.

**Middleware stack order (five layers, outer → inner):**
Starlette applies middleware in reverse-add order. Current stack:
1. `CSPMiddleware` — outermost; stamps security headers on every response
2. `EncryptedSessionMiddleware` — decrypts the cookie and populates `request.session`
3. `LoginRateLimitMiddleware` — intercepts POST /login; enforces per-IP failure lockout
4. `CSRFMiddleware` — validates CSRF token on mutating requests; has session access
5. `AuthGuard` — innermost; checks `session["encryption_key"]`; redirects unauthenticated requests to `/login`

**Known architecture limitation — server-side decryption:**
This app decrypts vault entries on the server and renders plaintext HTML to the browser. It is "encrypted at rest" — NOT zero-knowledge. A compromised server runtime can observe decrypted secrets during active requests. This is an accepted trade-off for simplicity and educational clarity. A future client-side crypto architecture (WebCrypto + React SPA) would eliminate this, but is out of scope for current phases.

### Module Responsibilities

| Module | Purpose |
|---|---|
| `app/main.py` | FastAPI app init, middleware registration, router inclusion |
| `app/config/` | Settings via Pydantic `BaseSettings` (secret key, DB URL, session timeout, environment) |
| `app/routes/` | Thin route handlers — validate input, call services, return responses |
| `app/routes/ai.py` | Thin route handlers for all GenAI features (Phase 7), delegating to `ai_service` |
| `app/routes/api.py` | `/api/v1/` JSON REST API endpoints for the browser extension (Phase 10) |
| `app/services/` | Business logic: auth service, vault CRUD service |
| `app/services/ai_service.py` | Anthropic Claude API client; metadata-only AI features; metadata extraction helpers — never accepts raw password/username as a parameter (Phase 7) |
| `app/security/` | Encryption service (Fernet + AES-256-GCM), key derivation, password hashing |
| `app/security/totp.py` | TOTP secret generation, provisioning URI, token verification, recovery code generation/hashing (Phase 3) |
| `app/security/tokens.py` | JWT access + refresh token generation and verification via `PyJWT` (Phase 10) |
| `app/models/` | SQLAlchemy ORM models (`User`, `VaultEntry`, `RecoveryCode`) |
| `app/schemas/` | Pydantic request/response schemas |
| `app/database/` | SQLAlchemy engine, session factory, `get_db` dependency; WAL mode pragma hook |
| `app/middleware/auth_guard.py` | Redirect unauthenticated requests to `/login`; exempt `/login`, `/setup`, `/static/*`, `/2fa/*` |
| `app/middleware/csrf.py` | Synchronizer Token Pattern CSRF protection; 403 on mismatch, 303 on session-expiry race |
| `app/middleware/csp.py` | Content-Security-Policy + X-Frame-Options + X-Content-Type-Options + HSTS headers |
| `app/middleware/rate_limit.py` | Per-IP login failure counter with lockout; 429 + Retry-After on breach |
| `app/middleware/encrypted_session.py` | Fernet-encrypted cookie session; replaces Starlette's signed-only SessionMiddleware |
| `app/templates/` | Jinja2 HTML templates |
| `app/templates_config.py` | Centralised `Jinja2Templates` instance; registers `format_datetime` global and `truncate_str` filter |
| `app/static/` | CSS, JS assets (self-hosted Tailwind, datetime.js, entry_detail.js, entry_form.js) |
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

### Phase 1 — Status: ✅ Complete

All MVP files implemented and hardened through code review. See `spec.md §Phase 1` and git history for full details.

---

### Phase 2 — Security Hardening — Status: ✅ Complete

All security hardening files implemented and hardened through code review. See `spec.md §Phase 2` and git history for full details.

> ⚠️ **Re-encryption cannot run in Alembic** — the encryption key only exists in session memory after login and must never touch disk. Alembic adds the `encryption_version` column only. The actual re-encryption is a lazy per-entry operation in `vault_service` at first read after upgrade. All read/write paths must check `encryption_version` and call the correct algorithm via `get_cipher(version, key)`.

---

### Phase 3 — TOTP Two-Factor Authentication — Status: ✅ Complete

> **Goal:** Add a second authentication factor so a stolen master password alone cannot unlock the vault.
> TOTP (RFC 6238) is the industry standard — supported by Google Authenticator, Authy, 1Password, Bitwarden, etc.
> 2FA is optional per-user: users who skip setup continue using password-only login.

#### ✅ Completed

| File / Area | What was implemented |
|---|---|
| `requirements.txt` | Added `pyotp>=2.9` and `qrcode[pil]>=7.4` |
| `app/models/user.py` | Added `totp_secret: Mapped[str \| None]` (NULL = 2FA disabled; AES-GCM encrypted) and `totp_enabled: Mapped[bool]` (default False); added `recovery_codes` relationship |
| `app/models/recovery_code.py` | New `RecoveryCode` ORM model — `user_id` FK (CASCADE), `code_hash` (Argon2id), `used_at` (NULL = unused) |
| `app/migrations/versions/d4e5f6a7b8c9_add_totp_2fa.py` | Alembic migration adding `totp_secret`, `totp_enabled` to `users` and creating `recovery_codes` table with index |
| `app/security/totp.py` | New module: `generate_secret()`, `get_provisioning_uri()`, `verify_totp()`, `generate_recovery_codes()` (8 × 8-char codes via `secrets.token_urlsafe`), `hash_recovery_code()` (Argon2id), `verify_recovery_code()` |
| `app/services/auth_service.py` | Added `enable_2fa()` (verifies first code, encrypts secret AES-GCM, stores 8 hashed recovery codes); `disable_2fa()` (clears secret, deletes codes); extended `login()` to return `True` when TOTP step required (sets `pending_user_id` + `pending_encryption_key`) |
| `app/routes/auth.py` | Added `GET/POST /2fa/setup`, `GET/POST /2fa/verify`, `GET/POST /2fa/recovery`, `POST /2fa/disable`; updated `POST /login` to redirect to `/2fa/verify` when `requires_totp=True`; QR code generated server-side via `qrcode[pil]` |
| `app/middleware/auth_guard.py` | Exempted `/2fa/verify` and `/2fa/recovery` from encryption-key check so mid-login users can reach the TOTP prompt |
| `app/tests/test_totp.py` | 18 unit tests covering `generate_secret` format/randomness, `get_provisioning_uri` structure, `verify_totp` valid/invalid/wrong-secret, `generate_recovery_codes` count/length/uniqueness, `hash_recovery_code` Argon2id format, `verify_recovery_code` correct/wrong |
| `app/templates/2fa_setup.html` | Three-state template: setup form with QR code + manual secret fallback + confirmation input; recovery codes display (shown once with save-now warning); optional disable button when 2FA already active |
| `app/templates/2fa_verify.html` | 6-digit TOTP input form; "Use recovery code" link to `/2fa/recovery` |
| `app/templates/2fa_recovery.html` | Recovery code text input form; "Use authenticator app" link back to `/2fa/verify` |
| `app/tests/test_auth_routes.py` | 25 new 2FA integration tests across `TestLogin2FA`, `TestTotpVerify`, `TestRecoveryCodes`, `TestDisable2FA`; `_enable_2fa` helper with `generate_secret` mock; `client_2fa_enabled` and `client_2fa_pending` fixtures |

> ⚠️ **TOTP secret storage:** The secret must be encrypted at rest — treat it like a vault credential. Use `encrypt_field_gcm(secret, encryption_key)` and store the ciphertext in `users.totp_secret`. Decrypt at login time the same way vault fields are decrypted. Never log the plaintext secret.
>
> ⚠️ **Mid-login session state:** Use `session["pending_user_id"]` to track a user who has passed the password check but not yet the TOTP check. Clear this key on: TOTP success (replace with full session), TOTP failure after N attempts (lock), or any navigation away from `/2fa/verify`. `AuthGuard` must NOT grant access to the vault based on `pending_user_id` — only a fully established `encryption_key` in session grants access.

---

### Phase 4 — UX Improvements — Status: 🟡 In Progress (Sub-tasks 1 & 2 complete)

> **Goal:** Improve usability and add practical data management features.

#### ✅ Completed (Sub-task 1 — search, password generator, strength indicator)

| File / Area | What was implemented |
|---|---|
| `app/routes/vault.py` | `get_vault()` accepts `q` and `category` query params for form pre-fill; always fetches all entries (client-side JS handles filtering); passes `q`, `active_category`, `categories` to template |
| `app/services/vault_service.py` | `get_entries()` extended with optional `q` (title/website `ilike` OR) and `category` (exact match) filters (used by tests/future callers); new `get_categories()` returns sorted distinct categories for the dropdown |
| `app/templates/vault.html` | Search input (`id="vault-search-q"`) + category `<select>` (`id="vault-search-category"`); `data-vault-entry`/`data-title`/`data-website`/`data-category` on each `<tr>` for JS filtering; "No entries found" block (`id="vault-empty-filtered"`, hidden by default); "vault is empty" state; dynamic count label |
| `app/templates/entry_form.html` | "Generate password" button below the password field; strength indicator bar + label (`hidden` until input); password generator modal (`id="password-generator-modal"`) with length slider (8–64, default 16), uppercase/numbers/symbols checkboxes, Regenerate + Use Password buttons |
| `app/static/js/vault_search.js` | New file: live client-side filtering as user types (debounced 150 ms); category select filters instantly; form submit intercepted (no page reload); URL synced via `history.replaceState`; Clear button shown/hidden dynamically; "No entries found" block toggled when filter matches nothing |
| `app/static/js/entry_form.js` | Real-time password strength indicator (5 levels: Very Weak → Very Strong) driven by length + character-set checks; fires on `input` event and pre-fills in edit mode |
| `app/static/js/password_generator.js` | New file: `generatePassword()` uses `crypto.getRandomValues` + Fisher-Yates shuffle; modal open/close (button, backdrop click, Escape key); "Use Password" fills `form-password` and fires `input` event so strength updates |

#### ✅ Completed (Sub-task 1 add-on — logging enhancements)

| File / Area | What was implemented |
|---|---|
| `app/middleware/auth_guard.py` | Upgraded from `DEBUG` to `INFO`; classifies redirect cause as `session_expired_or_no_cookie`, `pending_totp`, or `session_missing_key`; includes `user_id` and HTTP method in log line; added `/auth/timeout-notify` to exempt paths |
| `app/middleware/encrypted_session.py` | Distinguishes Fernet TTL expiry (logs `INFO`) from cookie tampering/key-rotation (logs `WARNING`) by attempting a TTL-free decode; fixed redundant `ValueError` subclasses in except clause |
| `app/routes/auth.py` | Added `GET /auth/timeout-notify` — exempt endpoint called by JS before inactivity redirect; reads `user_id` from the still-live session and logs `INFO "Client-side inactivity timeout fired"` |
| `app/static/js/session_timeout.js` | `logout()` now fires `fetch('/auth/timeout-notify', { keepalive: true })` before navigating so the timeout is recorded server-side with the user_id |

#### ✅ Completed (Sub-task 2 — clipboard auto-clear, dark mode, responsive layout)

| File / Area | What was implemented |
|---|---|
| `app/static/js/entry_detail.js` | `copyValue()` now shows a live "Clears in 30s" countdown on the button and calls `navigator.clipboard.writeText('')` after 30 s to wipe the clipboard; per-button `WeakMap` timers allow independent countdowns for username and password; clicking Copy again restarts the 30-second window |
| `app/static/css/dark.css` | New file: `html.dark` CSS overrides for all key Tailwind utility classes (backgrounds, text, borders, inputs, buttons, table rows, dividers); applied when `dark_mode.js` adds the `dark` class to `<html>` |
| `app/static/js/dark_mode.js` | New file: runs immediately on parse to apply saved preference before first paint (prevents white flash); toggles `dark` class on `<html>`; persists choice to `localStorage` under key `sv-dark-mode`; updates toggle button emoji (🌙 / ☀️) |
| `app/templates/base.html` | Added `<link rel="stylesheet" href="/static/css/dark.css">` after Tailwind; added `<script src="/static/js/dark_mode.js">` (non-deferred, runs before paint); added fixed bottom-right `#dark-mode-toggle` button (`z-40`, below modals and timeout banner) that appears on every page |
| `app/templates/vault.html` | Nav items now use `flex-wrap gap-2` so they wrap on small screens instead of overflowing; table wrapped in `<div class="overflow-x-auto">` for horizontal scroll on mobile; Website column and cells hidden on `< sm` with `hidden sm:table-cell` |
| `app/templates/entry_detail.html` | Header row uses `flex-wrap` so Edit/Delete buttons stack below the title on narrow screens; field rows use `flex-wrap` + `min-w-0` so long usernames/websites break correctly; Copy buttons have `min-w-[4rem]` to prevent label-jump during countdown; Notes `<p>` has `break-words` |

#### ❌ Still To Implement

| Sub-task | Features |
|---|---|
| Sub-task 3 | `POST /vault/import` — KeePass XML + LastPass CSV; `GET /vault/export` — KeePass XML + LastPass CSV |

---

### Phase 5 — Engineering Quality — Status: 🔴 Not Started

pytest ≥80% coverage, Ruff zero violations, full type hints, structured logging, README, `docs/architecture.md`, `docs/threat_model.md`. See `spec.md §Phase 5`.

---

### Phase 6 — DevSecOps + Cloud Deployment — Status: 🔴 Not Started

Dockerfile, docker-compose, GitHub Actions CI, pip-audit, AWS EC2 t3.micro (nginx + certbot + systemd), EBS volume for DB, nightly S3 backup. Then codify the same infra in **Terraform** (`terraform/`) with remote state in S3 + DynamoDB lock. See `spec.md §Phase 6` for the full two-step approach.

> ⚠️ **Rate limiter and reverse proxy:** When nginx is in front, `request.client.host` is the proxy's IP. Update `LoginRateLimitMiddleware` to read `X-Forwarded-For` only when `ENVIRONMENT=production`.

---

### Phase 7 — GenAI Integration — Status: 🔴 Not Started

Password Strength Analyzer, Smart Entry Assistant, Breach Detection via HaveIBeenPwned. Metadata-only — no sensitive data ever sent to external APIs. See `spec.md §Phase 7` and [GenAI Security Rules](#genai-security-rules-applies-to-all-phases).

---

### Phase 8 — Multi-User Support — Status: 🔴 Not Started

Registration, username-based login, user isolation, admin dashboard, per-user settings. Foundation already in place (`user_id` FK on all vault entries, WAL mode). See `spec.md §Phase 8`.

---

### Phase 9 — Mobile PWA — Status: 🔴 Not Started

Mobile-first layout, `manifest.json`, service worker, installable on Android home screen, pagination. No backend changes needed. See `spec.md §Phase 9`.

---

### Phase 10 — Browser Extension — Status: 🔴 Not Started

Chrome/Firefox extension with auto-fill + quick-search; `/api/v1/` REST API with JWT auth; `chrome.storage.session` for tokens. Prerequisites: Phase 6 (HTTPS) + Phase 8 (multi-user). See `spec.md §Phase 10`.

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
