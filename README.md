# SecureVault

A local-first encrypted credential manager built as an educational portfolio project. All vault entries are encrypted at rest using AES-256-GCM with a key derived from your master password — the server never stores your password or any plaintext secrets.

---

## Features

- **AES-256-GCM encryption** — every username, password, and note is encrypted at the field level before being written to disk
- **Argon2id key derivation** — your master password is never stored; a vault encryption key is derived fresh on every login and held only in the encrypted session cookie
- **TOTP two-factor authentication** — optional TOTP 2FA (Google Authenticator, Authy) with QR-code setup, 8 single-use recovery codes, and a per-user enable/disable toggle
- **Encrypted session cookie** — Fernet-encrypted cookie (AES-128-CBC + HMAC-SHA256) so the vault key stored in the session is opaque to anyone who can read the raw cookie value
- **CSRF protection** — synchronizer-token pattern enforced on every mutating request
- **Login rate limiting** — per-IP failed-attempt counter with automatic lockout and `Retry-After` response header
- **Content Security Policy** — strict CSP + `X-Frame-Options` + `HSTS` headers stamped on every response
- **Import / export** — KeePass 2.x XML and LastPass CSV, with a plaintext-export warning prompt
- **Password generator** — configurable length and character sets, generated locally in the browser
- **Dark mode** — system-preference detection with a manual toggle, persisted across sessions
- **Search & category filtering** — live client-side search across title and website; category sidebar for quick filtering
- **Copy-to-clipboard with auto-clear** — copied passwords are wiped from the clipboard after 30 seconds
- **Password strength indicator** — real-time entropy feedback on the entry form

---

## Tech Stack

| Layer | Technology |
|---|---|
| Web framework | FastAPI 0.115+ |
| ASGI server | Uvicorn |
| Templates | Jinja2 |
| Database | SQLite via SQLAlchemy 2.0 + Alembic |
| Validation / settings | Pydantic v2 / pydantic-settings |
| Encryption | `cryptography` (AES-256-GCM, Fernet, HKDF) |
| Password hashing | `argon2-cffi` (Argon2id) |
| 2FA | `pyotp` + `qrcode` |
| Safe XML parsing | `defusedxml` |
| Frontend | Tailwind CSS (self-hosted), vanilla JS |
| Testing | pytest + pytest-cov + httpx |

---

## Quick Start

### Prerequisites

- Python 3.11+
- `pip` or [`uv`](https://github.com/astral-sh/uv)

### 1. Clone and create a virtual environment

```bash
git clone <repo-url>
cd Password_manager_project
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
# or, with uv:
uv pip install -r requirements.txt
```

### 3. Configure environment variables

Create a `.env` file in the project root:

```env
SECRET_KEY=your-secret-key-min-32-chars-change-this
ENVIRONMENT=development
SESSION_TIMEOUT_MINUTES=30
```

> **`SECRET_KEY`** — used to derive the session cookie encryption key via HKDF-SHA256. Generate a strong random value:
> ```bash
> python -c "import secrets; print(secrets.token_hex(32))"
> ```

### 4. Run database migrations

```bash
alembic upgrade head
```

### 5. Start the server

```bash
uvicorn app.main:app --reload
```

Then open [http://localhost:8000/setup](http://localhost:8000/setup) to create your vault.

---

## First Use

1. Navigate to `/setup` and choose a strong master password (minimum 8 characters).
2. Log in at `/login` — your vault key is derived from the password and stored only in the session.
3. Optionally enable TOTP 2FA at `/2fa/setup` and save the recovery codes shown once.
4. Create your first entry at `/entry/new`.

---

## Screenshots

> _Screenshots to be added after UI stabilisation._

| Page | Description |
|---|---|
| `/setup` | First-time vault initialisation |
| `/login` | Master password login (+ TOTP step if 2FA enabled) |
| `/vault` | Dashboard with search, category filter, and entry list |
| `/entry/new` | Entry creation form with password generator and strength meter |
| `/entry/{id}` | Entry detail view with copy-to-clipboard |
| `/2fa/setup` | QR-code TOTP setup with recovery codes |

---

## Development Commands

```bash
# Run all tests
pytest

# Run tests with coverage report
pytest --cov=app --cov-report=term-missing

# Run a single test file
pytest app/tests/test_encryption.py

# Lint
ruff check app/

# Lint with auto-fix
ruff check app/ --fix

# Type check
mypy app/ --ignore-missing-imports

# Create a new database migration
alembic revision --autogenerate -m "description"

# Apply pending migrations
alembic upgrade head

# Dependency vulnerability scan
pip-audit
```

---

## Project Structure

```
.
├── app/
│   ├── config/          # Pydantic settings (SECRET_KEY, ENVIRONMENT, SESSION_TIMEOUT_MINUTES)
│   ├── database/        # SQLAlchemy engine, session factory, WAL-mode pragma hook
│   ├── middleware/       # CSRF, rate limiting, encrypted session, CSP, auth guard
│   ├── migrations/      # Alembic migration scripts
│   ├── models/          # SQLAlchemy ORM models (User, VaultEntry, RecoveryCode)
│   ├── routes/          # FastAPI route handlers (auth.py, vault.py)
│   ├── schemas/         # Pydantic request/response schemas
│   ├── security/        # Encryption (AES-256-GCM + Fernet), hashing, TOTP, audit logger
│   ├── services/        # Business logic (auth_service, vault_service, import_export)
│   ├── static/          # CSS, JS assets
│   ├── templates/       # Jinja2 HTML templates
│   ├── tests/           # pytest unit and integration tests
│   ├── templates_config.py
│   └── main.py          # App factory: middleware stack, routers, error handlers
├── logs/
│   ├── app.log          # Operational debug log (rotating, 10 MB × 5)
│   └── audit.log        # Structured security audit log — newline-delimited JSON (rotating, 10 MB × 10)
├── alembic.ini
├── pytest.ini
├── requirements.txt
└── spec.md              # Full feature specification and phase roadmap
```

---

## Security Architecture

### What is encrypted

All sensitive vault fields (`username`, `password`, `notes`) are encrypted with AES-256-GCM before being written to the database. The `title`, `website`, and `category` columns are stored in plaintext and used for server-side search filtering.

### Key derivation

The master password itself is never stored. At login, Argon2id derives a 32-byte vault encryption key from the master password and a per-user random salt (`users.kdf_salt`). The derived key is placed in the encrypted session cookie and cleared from memory on logout.

A separate Argon2id hash of the master password (`users.password_hash`) is used only for login verification — it is never used for encryption.

### Session security

The session cookie is Fernet-encrypted (AES-128-CBC + HMAC-SHA256) using a key derived from `SECRET_KEY` via HKDF-SHA256. The cookie payload — including the vault encryption key — is fully opaque to any party without `SECRET_KEY`.

### Known limitations

- **Server-side decryption** — vault entries are decrypted on the server and rendered as plaintext HTML. This is "encrypted at rest", not zero-knowledge. A compromised server runtime can observe decrypted secrets during active requests. A future client-side WebCrypto architecture would eliminate this limitation.
- **Single-user** — the current schema supports one vault user. Multi-user support is planned for Phase 8.

### Audit logging

Security-relevant events (login success/failure, TOTP verify/fail/lockout, recovery code usage, vault entry CRUD, import/export) are written as structured JSON records to `logs/audit.log`, separate from the operational debug log. Passwords, decrypted values, and encryption keys are never written to any log.

---

## Running Tests

```bash
pytest app/tests/ -v
```

Current coverage: **88%** (`fail_under=80` enforced in `.coveragerc`).

---

## Development Phases

| Phase | Status | Description |
|---|---|---|
| 1 — MVP | ✅ Complete | Setup/login, Fernet encryption, CRUD, Tailwind UI, Alembic |
| 2 — Security Hardening | ✅ Complete | CSRF, rate limiting, AES-256-GCM, Argon2id KDF, encrypted session cookie |
| 3 — TOTP 2FA | ✅ Complete | TOTP setup, QR code, recovery codes, mid-login session step-up |
| 4 — UX Improvements | ✅ Complete | Search, categories, password generator, dark mode, import/export |
| 5 — Engineering Quality | 🟡 In Progress | pytest ≥80%, Ruff, type hints, audit logging, README, architecture doc, threat model |
| 6 — DevSecOps | 🔴 Not Started | Docker, GitHub Actions CI, pip-audit, AWS EC2 + nginx + TLS, Terraform |
| 7 — GenAI Integration | 🔴 Not Started | Claude API — password strength analyzer, breach detection (metadata only) |
| 8 — Multi-User | 🔴 Not Started | Registration, user isolation, admin dashboard |
| 9 — Mobile PWA | 🔴 Not Started | Mobile-first UI, manifest, service worker |
| 10 — Browser Extension | 🔴 Not Started | Chrome/Firefox extension, `/api/v1/` REST API, JWT auth |
