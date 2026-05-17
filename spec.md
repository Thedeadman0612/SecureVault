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

---

## High-Level System Architecture

```
Browser
  ↓
FastAPI Web Application
  ↓
Authentication Layer
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

### Phase 2 — Security Hardening

**Goal:** Improve security posture.

Requirements:
- stronger input validation
- improved session handling (secure cookies, HttpOnly, SameSite)
- CSRF protection
- login rate limiting / lockout
- improved key derivation (Argon2id)
- upgrade encryption to AES-256-GCM
- secure error handling (no stack traces in responses)

**Deliverable:** Security-improved application.

### Phase 3 — UX Improvements

**Goal:** Improve usability.

Requirements:
- search and category filtering
- password generator
- dark mode
- responsive layout improvements
- password visibility toggle
- copy-to-clipboard with auto-clear
- password strength indicator on setup/entry

**Deliverable:** User-friendly vault UI.

### Phase 4 — Engineering Quality

**Goal:** Make project portfolio-quality.

Requirements:
- pytest coverage (unit + integration)
- linting (ruff or flake8)
- full type hints
- structured logging
- README with screenshots
- architecture documentation
- threat model document

**Deliverable:** Professional-grade project repository.

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

### Phase 6 — Multi-User Support

**Goal:** Extend the vault to support multiple independent users, each with their own isolated encrypted vault.

Requirements:
- Add `username` and `email` fields to the `User` model
- Add a registration route (`GET /register`, `POST /register`) with username/email/password fields
- Update login to look up user by username instead of assuming a single local user
- Ensure all vault queries filter by `user_id` so no user can access another's entries
- Derive each user's encryption key from their own master password — keys are never shared
- Update all frontend pages with username/email fields where needed
- Add user isolation tests verifying one user cannot read or modify another user's entries

**Deliverable:** Multi-user capable application with strict per-user vault isolation.

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
- multi-user support (planned for Phase 6)
- mobile application
- OAuth or SSO login
- biometric authentication
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
| Session hijacking | Secure, HttpOnly, SameSite cookies |
| Accidental log exposure | Strict logging policy; no secrets logged |
| Shoulder surfing | Password masking; visibility toggle |
| Insecure local storage | No plaintext secrets on disk |

---

## Final Philosophy

This project exists to:
- learn secure engineering practices
- practice full-stack development
- understand encryption and key management concepts
- explore AI-assisted coding workflows
- build portfolio-quality engineering work

**Security, readability, and incremental progress are more important than feature quantity.**
