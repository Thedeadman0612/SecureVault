# SecureVault — Technical Specification

---

## Project Purpose

SecureVault is a local-first secure credential and sensitive information manager built for educational, portfolio, and secure software engineering learning purposes.

The application allows a user to:
- securely store credentials
- store sensitive notes
- manage secrets locally
- protect all sensitive information using strong encryption
- authenticate using a master password

> This project is NOT intended initially to be a production-grade commercial password manager.

---

## Primary Technical Goals

This project should help learn and demonstrate:
- modern backend engineering
- secure coding
- authentication & authorization
- encryption fundamentals
- database management
- API design
- frontend/backend integration
- AI-assisted development workflows
- DevSecOps concepts
- software architecture

---

## Core Technical Principles

### 1. Security First

Security is the highest priority.

The application MUST:
- never store plaintext passwords
- never log secrets
- use established cryptographic libraries only
- separate password hashing from encryption
- validate all inputs

### 2. Local-First Architecture

Initial versions are strictly local-only.

No:
- cloud sync
- multi-device sync
- remote APIs
- public internet exposure

### 3. Simplicity Over Complexity

Prefer:
- readability
- maintainability
- modularity
- educational clarity

Avoid:
- overengineering
- microservices
- premature optimization

---

## Recommended Technology Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI |
| Language | Python 3.12+ |
| Frontend Rendering | Plain HTML + CSS + vanilla JS |
| Styling | Tailwind CSS |
| Database | SQLite |
| ORM | SQLAlchemy |
| DB Migrations | Alembic |
| Validation | Pydantic |
| Encryption | cryptography (Fernet / AES-256-GCM) |
| Password Hashing | argon2-cffi |
| Session Handling | Starlette `SessionMiddleware` + `itsdangerous` |
| Testing | pytest |
| Package Manager | pip / uv |
| Deployment (later) | Docker |
| AI Integration (Phase 6) | `anthropic` Python SDK (Claude API) |
| Breach Detection (Phase 6) | HaveIBeenPwned REST API |
| Mobile — PWA (Phase 8) | `manifest.json` + Service Worker |
| Mobile — API Auth (Phase 9) | `PyJWT` (JWT — preferred over `python-jose` which has had CVEs and is less actively maintained) |
| Mobile — Android client (Phase 9) | Flutter (Dart) |

---

## High-Level System Architecture

```
Browser (HTML)          Android App (Phase 9)
     ↓                          ↓
     ↓              /api/v1/ (JSON + JWT)
     ↓                          ↓
     └──────────────────────────┘
                  ↓
     FastAPI Web Application
                  ↓
     Authentication Layer
       (Session cookie  /  JWT Bearer)
                  ↓
     Encryption Service
                  ↓
     Database Access Layer
                  ↓
       SQLite Database
```

---

## Directory Structure

```
app/
├── main.py
├── config/
├── routes/
├── services/
├── models/
├── schemas/
├── templates/
├── static/
├── security/
├── database/
├── middleware/
├── utils/
├── tests/
└── migrations/
```

---

## Development Philosophy

Claude Code should:
- generate clean modular code
- prioritize readability
- avoid unnecessary abstractions
- explain major decisions
- follow secure coding practices
- implement incrementally phase-by-phase

---

## Functional Requirements

### Authentication System

#### Initial Setup Flow

On first application startup, if no user exists:
- redirect to setup page
- require creation of master password

Setup process:
1. User enters master password
2. User confirms master password
3. Validate password strength
4. Hash master password using Argon2
5. Store only the password hash
6. Initialize empty encrypted vault

#### Login Flow

User must:
- enter master password
- authenticate successfully before vault access

System behavior:
- verify Argon2 hash
- create authenticated session
- deny access on invalid password

#### Session Management

Initial implementation uses Starlette `SessionMiddleware` with secure cookies backed by `itsdangerous`.

> **Known limitation (Phase 1):** Starlette's default `SessionMiddleware` signs cookies (tamper-proof via HMAC) but does **not** encrypt them — the session payload is base64-readable by the client. The `encryption_key` stored in the session is therefore visible to anyone who can read the cookie value. Phase 2 replaces this with an encrypted session backend so the payload is opaque to the client.

Requirements:
- inactivity timeout
- logout support
- session invalidation on logout

### Vault Management

Users must be able to:
- create entries
- view entries
- edit entries
- delete entries
- search entries
- categorize entries

### Vault Entry Structure

Each vault entry contains:

| Field | Notes |
|---|---|
| `id` | Primary key |
| `title` | Plaintext, used for search |
| `website` | Plaintext, used for search |
| `username_encrypted` | Encrypted before storage |
| `password_encrypted` | Encrypted before storage |
| `notes_encrypted` | Encrypted before storage |
| `category` | Plaintext |
| `created_at` | Timestamp |
| `updated_at` | Timestamp |

---

## Encryption Requirements

> **CRITICAL SECURITY REQUIREMENT:** Sensitive data MUST NEVER be stored plaintext in the database.

Sensitive fields that must be encrypted before persistence:
- `username`
- `password`
- `notes`

### Encryption Design

#### Algorithm

- **Phase 1:** Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256 under the hood — sufficient for local storage)
- **Phase 2+:** Upgrade to AES-256-GCM for stronger authenticated encryption

#### Key Derivation

The encryption key must be derived from the master password at login time and held in memory only for the duration of the session.

- **Phase 1:** PBKDF2HMAC (SHA-256, 600,000 iterations, random salt stored in DB)
- **Phase 2+:** Argon2id-based key derivation

#### Encryption Flow

```
Master Password (entered at login)
  ↓
Key Derivation Function (PBKDF2HMAC)
  ↓
Encryption Key (held in memory only)
  ↓
Encrypt Sensitive Fields (Fernet)
  ↓
Store Encrypted Ciphertext in DB
```

### Password Hashing

The master password MUST:
- NEVER be encrypted or reversible
- be hashed using Argon2 (via `argon2-cffi`)
- only be used for authentication verification

The password hash and the encryption key derivation are two separate operations. Argon2 verifies identity; PBKDF2HMAC derives the vault encryption key.

---

## Database Specification

Single local SQLite database file: `securevault.db`

Use SQLAlchemy ORM. Avoid raw SQL unless necessary. All queries must use parameterized inputs.

### Database Tables

#### `users`

| Field | Type | Notes |
|---|---|---|
| `id` | Integer | Primary key |
| `password_hash` | String | Argon2 hash |
| `kdf_salt` | String | Salt for key derivation (base64) |
| `created_at` | DateTime | |
| `updated_at` | DateTime | |

> Only one local user is supported initially.

#### `vault_entries`

| Field | Type | Notes |
|---|---|---|
| `id` | Integer | Primary key |
| `user_id` | Integer | Foreign key → `users.id` |
| `title` | String | Plaintext |
| `website` | String | Plaintext |
| `username_encrypted` | String | Encrypted (base64 Fernet token) |
| `password_encrypted` | String | Encrypted (base64 Fernet token) |
| `notes_encrypted` | String | Encrypted (base64 Fernet token) |
| `category` | String | Plaintext |
| `created_at` | DateTime | |
| `updated_at` | DateTime | |

---

## Frontend Requirements

### Rendering Approach

Use plain HTML + CSS + vanilla JS. Not React initially.

Reason:
- reduces complexity
- faster MVP
- lower frontend learning burden

### Styling

Use Tailwind CSS (CDN for Phase 1, compiled for later phases).

Goals:
- clean, readable UI
- responsive layout
- minimal styling complexity

Avoid excessive animations, heavy UI frameworks, or unnecessary complexity.

### Required Pages

#### Setup Page

Purpose: initialize master password on first run.

Fields:
- password
- confirm password

Validation:
- minimum length (12+ characters recommended)
- password match
- strength indicator (Phase 3)

#### Login Page

Fields:
- master password

Features:
- invalid login feedback
- secure session initialization

#### Vault Dashboard

Features:
- entry listing
- search bar (title + website)
- category filter
- add entry button
- logout button

#### Add / Edit Entry Page

Fields:
- title
- website
- username
- password
- notes
- category

Features:
- form validation
- password visibility toggle (Phase 3)

#### Entry Details Page

Features:
- decrypted display of all fields
- copy password to clipboard
- edit / delete actions

---

## API / Route Requirements

### Auth Routes

| Method | Route | Description |
|---|---|---|
| `GET` | `/setup` | Setup page (only if no user exists) |
| `POST` | `/setup` | Submit master password setup |
| `GET` | `/login` | Login page |
| `POST` | `/login` | Authenticate and create session |
| `POST` | `/logout` | Invalidate session |

### Vault Routes

| Method | Route | Description |
|---|---|---|
| `GET` | `/vault` | Dashboard (requires auth) |
| `GET` | `/entry/{id}` | View decrypted entry |
| `POST` | `/entry` | Create new entry |
| `PUT` | `/entry/{id}` | Update entry |
| `DELETE` | `/entry/{id}` | Delete entry |

---

## Security Requirements

### Sensitive Data Protection

The application MUST:
- never log secrets, passwords, or decrypted values
- never expose secrets in URLs or query parameters
- never expose plaintext database values in API responses

### Input Validation

All inputs must validate:
- empty / missing values
- length constraints
- malformed data
- injection attempts

Use Pydantic validation for request bodies and SQLAlchemy ORM parameterized queries for DB access.

### Error Handling

Application must:
- fail gracefully
- never expose stack traces to the browser
- display user-friendly error messages only

### CSRF Protection

Add CSRF protection in Phase 2 (e.g., `starlette-csrf` middleware or double-submit cookie pattern).

### Rate Limiting

Add login rate limiting in Phase 2 (e.g., `slowapi` or manual attempt counter with lockout).

---

## Logging Requirements

**Allowed:**
- auth attempt outcomes (success/failure, no credentials)
- application startup events
- non-sensitive errors

**Forbidden (never log):**
- passwords
- decrypted secrets
- encryption keys
- session tokens

---

## Clipboard Handling

Future enhancement: auto-clear copied passwords after a configurable timeout (e.g., 30 seconds).

Initial version may skip this.

---

## Search Requirements

User must be able to:
- search by title
- search by website
- filter by category

Search operates only on plaintext fields (`title`, `website`, `category`). Encrypted fields are never searched directly.

---

## Development Phases

### Phase 1 — MVP

**Goal:** Build a working local secure vault.

Requirements:
- FastAPI project setup with Pydantic config
- SQLite + SQLAlchemy models
- Alembic migration setup
- Setup and login flow (Argon2 hashing, PBKDF2 key derivation)
- Encryption service (Fernet)
- CRUD vault operations
- Frontend via plain HTML + CSS + vanilla JS
- Tailwind CSS (CDN)

**Deliverable:** Functional local secure vault application.

**Success Criteria:**
- [ ] App starts without errors with a valid `.env` file
- [ ] First run redirects to `/setup`; subsequent runs redirect to `/login`
- [ ] A user can create, view, edit, and delete vault entries end-to-end
- [ ] Encrypted fields in `securevault.db` are unreadable as plaintext when inspected directly
- [ ] Logout invalidates the session and redirects to `/login`

**Test Focus:**
- Fernet encrypt/decrypt round-trip produces the original value
- PBKDF2HMAC key derivation is deterministic for the same password + salt
- Argon2 hash and verify (correct password passes, wrong password fails)
- Vault CRUD operations against an in-memory SQLite test database
- `/setup` and `/login` integration tests covering valid and invalid inputs

### Phase 2 — Security Hardening

**Goal:** Improve security posture.

Requirements:
- stronger input validation
- improved session handling (secure cookies, HttpOnly, SameSite)
- **encrypted session backend** — replace Phase 1's signed-only `SessionMiddleware` with an encrypted session so the `encryption_key` in the session payload is opaque to the client
- CSRF protection
- login rate limiting / lockout — use `slowapi` with `InMemoryLimiter` (no Redis dependency) or a SQLite-backed attempt counter
- **Content Security Policy (CSP)** header on all responses — critical for a password manager since XSS = full vault compromise; start with a strict default-src policy and relax only for known CDNs
- improved key derivation (Argon2id)
- upgrade encryption to AES-256-GCM for all **new** writes; keep Fernet decrypt path permanently for legacy entries
- add `encryption_version` column to `vault_entries` (default `"fernet"`; updated to `"aesgcm"` after re-encryption)
- lazy re-encryption at read time: when a logged-in user reads a Fernet entry, decrypt it, re-encrypt with AES-GCM, save, and update `encryption_version` — the encryption key is already in session so no extra auth is needed
- secure error handling (no stack traces in responses)

> **Important:** Re-encryption cannot run inside an Alembic migration — the encryption key only exists in session memory after login and must never touch disk. Alembic adds the `encryption_version` column only (schema change). The data migration is a transparent lazy operation inside the service layer.

**Deliverable:** Security-improved application.

**Success Criteria:**
- [ ] Login is rate-limited; repeated failures trigger a lockout or delay
- [ ] CSRF tokens are required and validated on all state-changing routes
- [ ] Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`
- [ ] Session payload is encrypted — the `encryption_key` value is not readable in the raw cookie
- [ ] All responses include a CSP header; the browser console shows no CSP violations on normal usage
- [ ] All new vault writes use AES-256-GCM; existing Fernet entries are re-encrypted lazily on first read
- [ ] `encryption_version` column correctly reflects the algorithm used for each entry
- [ ] No stack traces or internal error details are ever exposed in the browser

**Test Focus:**
- Rate limiting triggers after N failed login attempts
- Requests without a valid CSRF token are rejected with 403
- AES-256-GCM encrypt/decrypt round-trip
- Argon2id key derivation produces a consistent, usable key
- Lazy migration: reading a `"fernet"` entry updates `encryption_version` to `"aesgcm"` and the ciphertext is valid AES-GCM afterwards
- Both algorithms decrypt their own ciphertext correctly; cross-decryption fails with `InvalidToken`
- CSP header is present on vault and entry routes; value includes `default-src 'self'`

### Phase 3 — UX Improvements

**Goal:** Improve usability.

Requirements:
- title/website text search and category filtering as query params on `GET /vault` (e.g. `?q=github&category=Work`) — no separate search route; `GET /vault/search` is reserved for Phase 6's AI-powered search
- password generator
- dark mode
- responsive layout improvements
- password visibility toggle
- copy-to-clipboard with auto-clear
- password strength indicator on setup/entry

**Deliverable:** User-friendly vault UI.

**Success Criteria:**
- [ ] `GET /vault?q=github` returns entries whose title or website contains "github"
- [ ] `GET /vault?category=Work` returns only Work-category entries
- [ ] Both filters combined (`?q=...&category=...`) work correctly
- [ ] Password generator produces a configurable-length, random password
- [ ] Copied passwords are cleared from the clipboard after the configured timeout
- [ ] Dark mode toggle persists across page navigations

**Test Focus:**
- Search filtering logic on `GET /vault?q=` (title match, website match, no results case)
- Category filter works independently and combined with `?q=`
- Password generator meets length and character-set requirements
- Clipboard auto-clear fires after the configured timeout

### Phase 4 — Engineering Quality

**Goal:** Make project portfolio-quality.

Requirements:
- pytest coverage (unit + integration)
- linting (ruff or flake8)
- full type hints
- structured logging
- **security audit logging** — log security-relevant events (login success/failure, vault CRUD, session invalidation) to a dedicated `docs/security_audit_log.md` format or structured log stream; must never include passwords, keys, or decrypted values
- README with screenshots
- architecture documentation (`docs/architecture.md` — component diagram, request lifecycle, crypto design)
- threat model document (`docs/threat_model.md` — assets, threats, mitigations, known limitations)

**Deliverable:** Professional-grade project repository.

**Success Criteria:**
- [ ] `pytest` passes with ≥80% code coverage
- [ ] `ruff check app/` reports zero violations
- [ ] All public functions and modules carry full type hints
- [ ] Structured logs capture auth events without leaking any sensitive values
- [ ] README is complete with setup instructions and architecture diagram

**Test Focus:**
- Full regression suite passes cleanly with no skipped tests
- Log output captured in tests contains no passwords, keys, or session tokens
- Security audit log entries are emitted for login success, login failure, and vault delete operations

### Phase 5 — DevSecOps

**Goal:** Learn deployment and DevSecOps concepts.

Requirements:
- Dockerfile
- docker-compose
- GitHub Actions CI pipeline
- dependency scanning (e.g., `pip-audit`)
- secret scanning (e.g., `trufflehog` or GitHub secret scanning)
- container hardening (non-root user, minimal base image)

**Deliverable:** Deployable containerized application.

**Success Criteria:**
- [ ] `docker build` succeeds and the container starts the app correctly
- [ ] `docker-compose up` brings the full stack up from a cold machine
- [ ] GitHub Actions CI runs tests and lint on every push and fails on violations
- [ ] `pip-audit` reports no known critical vulnerabilities
- [ ] Container process runs as a non-root user

**Test Focus:**
- Container smoke test: app responds to HTTP requests after `docker-compose up`
- CI pipeline passes cleanly on a fresh runner with no cached state

### Phase 6 — GenAI Integration

**Goal:** Add AI-powered security intelligence to the vault while keeping all sensitive data strictly local. The Claude API is used to analyse metadata only — decrypted passwords, usernames, and notes are never sent to any external service.

> **Critical security constraint:** Only plaintext metadata (`title`, `website`, `category`, password complexity metrics, timestamps) may be transmitted to the Claude API. Decrypted passwords, usernames, notes, encryption keys, and session tokens must never leave the local machine.

Requirements:
- Add `app/schemas/ai_metadata.py` — defines `VaultMetadataForAI` Pydantic model containing **only** safe fields: `title`, `website`, `category`, `password_length`, `has_uppercase`, `has_numbers`, `has_symbols`, `created_at`, `updated_at`. This DTO is the only type accepted by `ai_service` functions — structural enforcement of the metadata-only constraint, not just a naming convention.
- Add `app/services/ai_service.py` — Anthropic Claude API client; accepts `list[VaultMetadataForAI]` (never raw entry objects); metadata extraction helpers; all AI feature functions; function signatures must never include `password`, `username`, or `notes` parameters
- Add `app/routes/ai.py` — thin route handlers delegating to `ai_service`; convert `VaultEntry` ORM objects to `VaultMetadataForAI` DTOs before any `ai_service` call
- Add `ANTHROPIC_API_KEY` and `HIBP_API_KEY` to `.env` and `app/config/settings.py`

**Features:**

| Feature | Endpoint | Description |
|---|---|---|
| 6.1 Password Strength Analyzer | `GET /vault/analyze` | Sends metadata only to Claude; returns prioritised recommendations (potential reuse indicators flagged by same length + complexity metrics — approximation only, actual reuse detection requires comparing passwords which is forbidden; stale passwords ≥6 months; weak by metrics; incomplete entries); dashboard button + modal |
| 6.2 Security Audit Assistant | `GET /vault/audit` | Full vault security score 0–100; score breakdown (strength, age, reuse, coverage); prioritised action list |
| 6.3 Smart Entry Assistant | `POST /entry/smart-fill` | User pastes any text; Claude extracts title, website, username, category; pre-fills add-entry form; user reviews before saving |
| 6.4 Auto-categorization | (inline, new-entry form) | Real-time category suggestion when user types title + website; shown as clickable chip; accepted or ignored |
| 6.5 Natural Language Vault Search | `GET /vault/ai-search?q=` | Deliberately separate from Phase 3's text search on `GET /vault?q=`; Claude interprets free-text query and maps to entry filters (e.g. "streaming services" → Netflix/Spotify); responses cached in-memory keyed on query string for 5 minutes to avoid duplicate API calls |
| 6.6 Breach Detection | `GET /vault/breach-check` | Checks website domain names (never passwords) against HaveIBeenPwned API; results stored in a `breach_cache(domain, is_breached, checked_at)` SQLite table — survives server restarts; re-fetched if `checked_at` is older than 24 h; breach badges on dashboard |

**Deliverable:** AI-enhanced vault dashboard with local-first security intelligence and zero sensitive-data leakage.

**Success Criteria:**
- [ ] `/vault/analyze` returns recommendations without sending any decrypted field to the Claude API (verified by inspecting outbound payloads in tests)
- [ ] `/entry/smart-fill` pre-fills the form correctly from pasted unstructured text
- [ ] `/vault/breach-check` returns breach status for vault domains; no credentials are included in the HIBP request
- [ ] All AI routes return a graceful error message (not a 500) when `ANTHROPIC_API_KEY` is missing or the API is unreachable
- [ ] `ai_service.py` contains no function signature that accepts `password`, `username`, or `notes` as a parameter

**Test Focus:**
- Metadata extraction helper strips encrypted fields — assert output dict contains no `*_encrypted` keys and no raw plaintext credentials
- Claude API client is called with a payload containing only safe fields (mock the API; assert request body)
- Natural language search (`GET /vault/ai-search?q=`) maps sample queries to the correct entry filters; 5-minute in-memory cache returns same result without a second API call for identical queries within the window
- Breach check result is stored in `breach_cache` SQLite table — assert the HIBP API is called only once for repeated requests within 24 h; assert result survives a simulated server restart (read from DB, not memory)

---

### Phase 7 — Multi-User Support

**Goal:** Extend the vault to support multiple independent users, each with their own isolated encrypted vault.

> **Database note:** SQLite is retained intentionally — it handles concurrent reads fine and write contention is negligible for a personal vault with a small number of concurrent users. A migration to PostgreSQL is a non-goal for this project; the local-first, portfolio scope does not justify the operational complexity.

Requirements:
- Add `username` and `email` fields to the `User` model
- Add a registration route (`GET /register`, `POST /register`) with username/email/password fields
- Update login to look up user by username instead of assuming a single local user
- Ensure all vault queries filter by `user_id` so no user can access another's entries
- Derive each user's encryption key from their own master password — keys are never shared
- Update all frontend pages with username/email fields where needed
- Add user isolation tests verifying one user cannot read or modify another user's entries

**Deliverable:** Multi-user capable application with strict per-user vault isolation.

**Success Criteria:**
- [ ] Multiple users can register and log in independently
- [ ] User A cannot read, edit, or delete User B's vault entries
- [ ] Each user's vault is encrypted with their own derived key — keys are never shared
- [ ] All vault queries are filtered by `user_id` with no bypass path

**Test Focus:**
- User isolation: authenticated request as User A attempting to access User B's entry returns 403/404
- Each user's encrypted data is decryptable only with their own key
- Registration validation rejects duplicate usernames and weak passwords

### Phase 8 — Mobile PWA

**Goal:** Make SecureVault accessible on Android devices as an installable Progressive Web App, requiring no new backend code.

Requirements:
- Add `app/static/manifest.json` — app name, short name, icons (192×192 and 512×512 PNG), theme colour, `display: standalone`
- Add `app/static/sw.js` — service worker that pre-caches Tailwind CSS and static assets so the shell loads offline
- Link manifest and register the service worker in `base.html`
- Add `<meta name="mobile-web-app-capable">` and `<meta name="apple-mobile-web-app-capable">` to `base.html`
- Audit and fix any responsive layout issues at 375px–430px viewport widths
- Mobile-first Tailwind CSS breakpoints; touch-friendly targets ≥44×44 px; responsive table → card layout on small screens
- Paginate vault entries (10 per page)

**Deliverable:** SecureVault installable via "Add to Home Screen" on Android Chrome; opens in standalone mode without browser chrome.

**Success Criteria:**
- [ ] Chrome's "Add to Home Screen" prompt appears when visiting the app on Android
- [ ] App opens in standalone mode (no browser URL bar)
- [ ] Static assets load from service worker cache when the server is unreachable
- [ ] All pages are usable without horizontal scrolling on a 390px-wide screen

**Limitation:** The phone and the server must be on the same Wi-Fi network (local-first constraint). The app is not accessible over the public internet unless the server is exposed via a reverse proxy or VPN.

**Test Focus:**
- Lighthouse PWA audit passes installability checks
- Service worker caches the app shell on first load
- Responsive layout tests at 375px, 390px, and 430px viewport widths

---

### Phase 9 — Native Android Client

**Goal:** Build a native Android app (Flutter recommended) that communicates with SecureVault via a new JSON REST API, using JWT authentication instead of browser session cookies.

**Prerequisites:** Phase 7 (multi-user) must be complete — a single-user vault has limited value as a networked app. Phase 5 (Docker/deployment) and an HTTPS certificate are also required.

**Backend changes required:**

| Area | Change |
|---|---|
| `app/routes/api.py` | New router at `/api/v1/` — mirrors all vault CRUD + auth routes, returns JSON instead of HTML |
| `app/schemas/api.py` | JSON request/response schemas for the REST API layer |
| `app/security/tokens.py` | JWT access token (short-lived, 15 min) + refresh token (long-lived) generation and verification via `PyJWT` — preferred over `python-jose` which has had CVEs and is less actively maintained |
| `app/models/revoked_token.py` | `RevokedToken` ORM model — stores revoked refresh token JTIs with expiry; checked only on token refresh, not on every request |
| `POST /api/v1/login` | Returns `{ access_token, refresh_token }` on success; never sets a cookie |
| `POST /api/v1/refresh` | Accepts a refresh token, checks it against `revoked_tokens` table, returns a new access token |
| `POST /api/v1/logout` | Revokes the refresh token — marks its JTI as revoked in the `revoked_tokens` table; access tokens expire naturally after their short TTL (do not blacklist access tokens per-request) |
| `app/middleware/auth_guard.py` | Extend to accept `Authorization: Bearer <token>` for `/api/v1/*` routes alongside the existing session cookie check for HTML routes |
| `app/main.py` | CORS configuration — required for browser-based clients (PWA or React SPA served from a different origin); native Flutter HTTP calls do not require CORS headers but including them is harmless and future-proofs the API |

**Mobile client (new top-level directory `mobile/`):**

| Component | Detail |
|---|---|
| Framework | Flutter (Dart) — cross-platform, single codebase for Android and iOS |
| HTTP client | `dio` package — handles JWT token refresh transparently |
| Secure storage | `flutter_secure_storage` — stores the refresh token in Android Keystore |
| Biometric unlock | `local_auth` — optional Face/Fingerprint unlock to derive the in-memory key |
| Architecture | Repository pattern: `AuthRepository`, `VaultRepository` → `ChangeNotifier` state → Flutter widgets |

**Deliverable:** Flutter Android app that logs in, lists, creates, views, edits, and deletes vault entries via the JSON API; refresh token stored in Android Keystore.

**Success Criteria:**
- [ ] `POST /api/v1/login` returns valid JWT tokens and rejects wrong passwords with 401
- [ ] All `/api/v1/` routes require a valid Bearer token; requests without one return 401
- [ ] HTML routes continue to work unchanged (no regression on the web UI)
- [ ] Flutter app installs and runs on Android API 26+ (Android 8+)
- [ ] Refresh token is persisted in Android Keystore, not in plain shared preferences
- [ ] Token refresh happens transparently — the user is not logged out when the access token expires

**Test Focus:**
- JWT token generation, verification, and expiry (`PyJWT`)
- API routes return 401 for missing/expired tokens and 200 for valid ones
- Logout revokes the refresh token — subsequent refresh attempts with the same token return 401
- Access tokens continue to work until natural expiry after logout (by design — short TTL mitigates this)
- HTML routes are unaffected by the new API middleware
- Flutter widget tests for login flow and vault list

---

## Testing Requirements

### Unit Tests

Required for:
- encryption service (encrypt/decrypt round-trip)
- key derivation logic
- password hashing and verification
- CRUD service functions
- input validation functions

### Manual Test Cases

Must verify:
- first-run setup flow
- valid login
- invalid login (wrong password)
- CRUD operations on vault entries
- encryption/decryption correctness
- session expiration behavior
- logout invalidates session

---

## Coding Standards

### General Rules

- small, focused functions with single responsibility
- meaningful naming (no abbreviations)
- avoid deeply nested logic — prefer early returns
- modular architecture matching the directory structure
- comments where the WHY is non-obvious

### Security Rules

**NEVER:**
- hardcode secrets or keys
- print or log sensitive data
- disable encryption for debugging
- store plaintext credentials

**ALWAYS:**
- validate all inputs at system boundaries
- sanitize outputs before rendering
- use established cryptographic libraries
- use parameterized DB queries via ORM

### AI-Assisted Development Rules

Claude Code should:
- explain complex security concepts inline
- prefer explicit, readable code over clever one-liners
- avoid over-engineering
- implement incrementally by phase
- prioritize security correctness over brevity

---

## Non-Goals (Initially Out of Scope)

- browser extension or password autofill
- cloud sync or remote storage
- AI features beyond metadata analysis (no sending of decrypted vault data to any external API — ever)
- multi-user support (planned for Phase 7)
- mobile application (PWA planned for Phase 8; native Android client planned for Phase 9)
- OAuth or SSO login
- biometric authentication (considered for Phase 9 Android client only)
- zero-knowledge cloud architecture
- enterprise features

---

## Future Enhancements (Optional)

- TOTP / 2FA support
- encrypted backup export/import
- audit logs
- desktop packaging (e.g., PyInstaller or Tauri)
- React frontend migration
- secure memory handling (zeroize secrets after use)
- HTTPS via reverse proxy (nginx)
- cloud sync experiments
- **browser-side encryption** — long-term direction: derive the vault key client-side using WebCrypto API so the server never sees the raw key (true zero-knowledge); requires a React or HTMX SPA to manage the in-browser key lifecycle; not feasible with server-rendered Jinja2 templates alone

---

## README Requirements

Repository README must include:
- project overview and purpose
- architecture diagram
- setup and run instructions
- screenshots of key pages
- security design notes
- development roadmap
- learning objectives

---

## Threat Model Considerations

The application should be designed with awareness of:

| Threat | Mitigation |
|---|---|
| Local DB theft | All sensitive fields encrypted; key is never stored |
| Brute force login | Rate limiting + Argon2 slow hashing |
| Session hijacking | Secure, HttpOnly, SameSite cookies; encrypted session backend (Phase 2) |
| Accidental log exposure | Strict logging policy; no secrets logged |
| Shoulder surfing | Password masking; visibility toggle |
| Insecure local storage | No plaintext secrets on disk |
| XSS attack | Content Security Policy (Phase 2); Jinja2 auto-escaping; XSS = full vault compromise for a password manager (attacker can read decrypted values from the DOM) |
| Server-side decryption (not zero-knowledge) | **Known limitation:** decryption happens on the server — the server briefly holds plaintext in memory; mitigated by minimising plaintext lifetime, never logging it, and clearing session on logout; true zero-knowledge requires client-side WebCrypto (Future Enhancement) |
| Memory zeroing | **Known limitation:** Python's GC and immutable strings make reliable secret zeroing impractical; after logout the key is cleared from the session dict but may linger in heap memory until collected; documented as a known limitation rather than a fixable bug |

---

## Final Philosophy

This project exists to:
- learn secure engineering practices
- practice full-stack development
- understand encryption and key management concepts
- explore AI-assisted coding workflows
- build portfolio-quality engineering work

**Security, readability, and incremental progress are more important than feature quantity.**
