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

All TOTP 2FA files implemented and hardened through code review. See `spec.md §Phase 3` and git history for full details.

> ⚠️ **TOTP secret storage:** Encrypted AES-GCM at rest in `users.totp_secret` — treat like a vault credential. Never log the plaintext secret.
>
> ⚠️ **Mid-login session state:** `session["pending_user_id"]` tracks a user past the password check but before TOTP. `AuthGuard` grants vault access only on a fully established `session["encryption_key"]` — never on `pending_user_id` alone.

---

### Phase 4 — UX Improvements — Status: ✅ Complete

All UX improvement files implemented and hardened through code review. See `spec.md §Phase 4` and git history for full details.

---

### Phase 5 — Engineering Quality — Status: 🟡 In Progress

pytest ≥80% coverage, Ruff zero violations, full type hints, structured logging, README, `docs/architecture.md`, `docs/threat_model.md`. See `spec.md §Phase 5`.

#### ✅ Completed

| File / Deliverable | What was implemented |
|---|---|
| `pytest-cov` + `.coveragerc` | Coverage tooling installed; `.coveragerc` configures source, omit patterns (tests, migrations), and `fail_under=80` |
| `requirements.txt` | Added `pytest-cov>=7.1.0` |
| `app/tests/test_helpers.py` | Unit tests for `none_if_empty`, `format_datetime`, `truncate` — `helpers.py` now at 100% |
| `app/tests/test_import_export.py` | Unit tests for `parse_keepass_xml`, `parse_lastpass_csv`, `build_keepass_xml`, `build_lastpass_csv` — `import_export.py` now at 95%; SonarQube S7498 (dict literal) and S2068 (hardcoded credential false positives) suppressed with `# NOSONAR` |
| `app/tests/test_vault_routes.py` | Integration tests for all vault routes (dashboard, import, export, create, detail, edit, delete) — `vault.py` now at 83% |
| **Coverage total** | **88%** (up from 74.66% baseline; target ≥80% ✅) |
| Full type hints (5.3) | Added missing return types to `database/session.py`, fixed `routes/auth.py` and `routes/vault.py` route return types (`-> Response` instead of narrow `HTMLResponse`/`RedirectResponse`); suppressed two framework false positives (`pydantic-settings` `call-arg`, Starlette ASGI `arg-type`); `mypy --ignore-missing-imports` now reports zero errors in production code |
| Structured security audit logging (5.4) | New `app/security/audit.py` with `log_event(event, **fields)` emitting newline-delimited JSON; dedicated `logs/audit.log` handler configured in `main.py` (separate from `app.log`, `propagate=False`); 18 security events wired across `auth_service`, `vault_service`, `routes/auth`, `routes/vault` covering login success/failure, MFA pending, TOTP verify/fail/lockout, recovery code used/failed/lockout, logout, vault setup, entry CRUD, import/export — no passwords, keys, or decrypted values ever logged |
| `README.md` (5.5) | Full project README: feature list, tech stack table, quick-start (clone → venv → install → .env → migrate → run), first-use guide, screenshots placeholder table, all dev commands, project structure tree, security architecture (encryption, KDF, session, known limitations, audit logging), test coverage note, phase status table |

#### ❌ Still To Implement

| Deliverable | Description |
|---|---|
| `docs/architecture.md` (5.6) | Component diagram, request lifecycle, crypto design, 2FA mid-login state machine — plain-English reference |
| `docs/threat_model.md` (5.7) | Assets, threats, mitigations, known limitations (server-side decryption, Python memory, TOTP replay window) |

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
