"""
app/middleware/encrypted_session.py

Encrypted session cookie middleware — replaces Starlette's SessionMiddleware.

THE PROBLEM WITH SessionMiddleware
------------------------------------
Starlette's built-in SessionMiddleware uses `itsdangerous.TimestampSigner` to
SIGN the cookie.  Signing guarantees integrity (the server can detect if the
cookie has been tampered with) but NOT confidentiality — the cookie payload is
base64-encoded JSON that anyone who can read the cookie can decode:

    Cookie value:   <b64url(json_bytes)>.<timestamp>.<hmac>
    Browser decode: base64decode(first_segment) → JSON in plaintext
    Visible fields: {"encryption_key": "...", "user_id": 1, "csrf_token": "..."}

The vault encryption key is stored in the session.  A signed-only cookie means
any attacker who intercepts the cookie (via a network capture, a browser
extension, or XSS before CSP was added) can read the encryption key in
plaintext — without needing the server's SECRET_KEY at all.

THE FIX: Fernet Encryption
----------------------------
Fernet (AES-128-CBC + HMAC-SHA256) provides both:
  • Confidentiality — the ciphertext is opaque without the key.
  • Integrity       — any tampering raises `InvalidToken` on decrypt.
  • Freshness       — Fernet tokens embed a timestamp; `decrypt(ttl=N)`
                      rejects tokens older than N seconds, implementing
                      session expiry at the crypto layer.

After this change, the cookie value is a Fernet ciphertext.  An attacker who
intercepts it sees only random-looking bytes — no JSON, no encryption_key.

KEY DERIVATION (no new environment variable needed)
----------------------------------------------------
The encryption key is derived from the existing SECRET_KEY via HKDF-SHA256:

    HKDF(secret_key, salt="securevault-session-v2", info="encrypted-session-cookie")
    → 32 raw bytes → base64url-encoded → valid Fernet key

HKDF is a one-way KDF: knowing the derived key does not help an attacker
recover SECRET_KEY.  The fixed salt and info strings ensure that if SECRET_KEY
is later reused in a different context, the derived keys are domain-separated.

If SECRET_KEY is rotated, all existing sessions become invalid (users are
redirected to /login).  This is acceptable and correct security behaviour.

WIRE-UP POSITION IN STACK (main.py add_middleware call order)
-------------------------------------------------------------
Identical to the SessionMiddleware it replaces — middle-outer:

    app.add_middleware(AuthGuard)                          # innermost
    app.add_middleware(CSRFMiddleware)                     # middle-inner
    app.add_middleware(EncryptedSessionMiddleware, ...)    # middle-outer
    app.add_middleware(CSPMiddleware)                      # outermost

AuthGuard and CSRFMiddleware both access request.session (= scope["session"]).
EncryptedSessionMiddleware sets scope["session"] before they run, so they
require no changes.

COOKIE LIFECYCLE
----------------
On every incoming request:
  1. Read the session cookie from the request headers.
  2. Fernet-decrypt it (raises InvalidToken if tampered/expired).
  3. JSON-deserialise the plaintext → scope["session"] dict.
  4. On failure (tampered / expired / missing): set scope["session"] = {}.

On every outgoing response (http.response.start):
  • If scope["session"] is non-empty  → encrypt + set the cookie.
  • If scope["session"] is empty AND a session cookie existed in the request
    → send Max-Age=0 to delete the browser's cookie (handles logout and
    tampered-cookie cleanup).
  • If scope["session"] is empty AND no cookie existed → do nothing.
"""

import base64
import json
import logging

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from starlette.datastructures import MutableHeaders
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

# Fixed HKDF parameters — changing these invalidates all existing sessions.
# The "v2" suffix in the salt documents that this is the Phase 2 encrypted
# session scheme; "v1" was the Phase 1 signed-only scheme.
_HKDF_SALT = b"securevault-session-v2"
_HKDF_INFO = b"encrypted-session-cookie"


class EncryptedSessionMiddleware:
    """Store session data in an AES-encrypted (Fernet) cookie.

    Drop-in replacement for Starlette's SessionMiddleware.  All existing code
    that reads/writes ``request.session`` continues to work unchanged because
    both middlewares expose the session via the same ``scope["session"]`` dict.

    Parameters
    ----------
    app:
        The ASGI application to wrap.
    secret_key:
        The application's SECRET_KEY.  A Fernet encryption key is derived from
        it via HKDF-SHA256 — no additional environment variable is required.
    max_age:
        Session lifetime in seconds.  Fernet's built-in TTL check enforces this
        at the crypto layer (token is rejected if older than ``max_age`` seconds).
        Defaults to 600 s (10 minutes) — same as Phase 2 session timeout.
    session_cookie:
        Name of the session cookie.  Defaults to ``"sv_session"`` to match the
        previous SessionMiddleware configuration.
    https_only:
        If True, add the ``Secure`` flag so the cookie is only sent over HTTPS.
        Set to False in local development (``ENVIRONMENT=development``).
    same_site:
        ``SameSite`` cookie attribute.  ``"strict"`` (the hardened Phase 2
        default) means the cookie is never sent on any cross-site request.
    """

    def __init__(
        self,
        app: ASGIApp,
        secret_key: str,
        max_age: int = 600,
        session_cookie: str = "sv_session",
        https_only: bool = True,
        same_site: str = "strict",
    ) -> None:
        self.app = app
        self._fernet = Fernet(self._derive_fernet_key(secret_key))
        self._max_age = max_age
        self._session_cookie = session_cookie
        self._https_only = https_only
        self._same_site = same_site

    # ------------------------------------------------------------------
    # Key derivation
    # ------------------------------------------------------------------

    @staticmethod
    def _derive_fernet_key(secret_key: str) -> bytes:
        """Derive a Fernet-compatible key from the application SECRET_KEY.

        Uses HKDF-SHA256 to produce 32 raw bytes, then base64url-encodes them
        to satisfy Fernet's key format requirement (URL-safe base64, 32 bytes
        of entropy).

        The derivation is deterministic: the same SECRET_KEY always produces
        the same Fernet key, so existing sessions survive server restarts.
        """
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=_HKDF_SALT,
            info=_HKDF_INFO,
        )
        raw_key = kdf.derive(secret_key.encode("utf-8"))
        return base64.urlsafe_b64encode(raw_key)

    # ------------------------------------------------------------------
    # ASGI interface
    # ------------------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Process one ASGI event: decrypt session on the way in, encrypt on the way out."""
        # Pass non-HTTP scopes (lifespan, websocket handshake) straight through.
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        connection = HTTPConnection(scope)
        # Track whether a session cookie existed so we know to delete it on
        # logout (scope["session"] cleared → empty dict → send Max-Age=0).
        had_session_cookie = self._session_cookie in connection.cookies

        scope["session"] = self._load_session(connection)

        async def send_wrapper(message: dict) -> None:
            """Intercept http.response.start to inject the Set-Cookie header."""
            if message["type"] == "http.response.start":
                session: dict = scope["session"]
                headers = MutableHeaders(scope=message)

                if session:
                    # Non-empty session — encrypt and (re-)set the cookie.
                    token = self._fernet.encrypt(
                        json.dumps(session).encode("utf-8")
                    )
                    headers.append(
                        "Set-Cookie",
                        self._build_cookie(token.decode("utf-8")),
                    )
                elif had_session_cookie:
                    # Cookie existed but session is now empty.
                    # Two causes:
                    #   (a) Logout: auth_service calls session.clear() → {}.
                    #   (b) Tampered/expired cookie: _load_session returned {}.
                    # Either way, instruct the browser to delete the cookie.
                    headers.append("Set-Cookie", self._delete_cookie())

            await send(message)

        await self.app(scope, receive, send_wrapper)

    # ------------------------------------------------------------------
    # Session load / cookie helpers
    # ------------------------------------------------------------------

    def _load_session(self, connection: HTTPConnection) -> dict:
        """Decrypt and deserialise the session cookie.

        Returns an empty dict on any failure (missing cookie, tampered
        ciphertext, expired TTL, malformed JSON).  Failures are logged at
        WARNING level — no stack trace, no sensitive values in the log.
        """
        raw = connection.cookies.get(self._session_cookie)
        if raw is None:
            return {}
        try:
            # ttl=max_age enforces session expiry at the Fernet layer.
            decrypted = self._fernet.decrypt(raw.encode("utf-8"), ttl=self._max_age)
            return json.loads(decrypted)
        except InvalidToken:
            # Distinguish TTL expiry from tampering/key-rotation by attempting
            # a decode with no TTL constraint. If that succeeds the cookie is
            # structurally valid but simply too old — unambiguous inactivity
            # expiry. If it still fails the cookie is tampered or was issued
            # under a different SECRET_KEY.
            try:
                self._fernet.decrypt(raw.encode("utf-8"))
                # Decodes fine without TTL → expired (not tampered).
                logger.info(
                    "Session cookie expired (inactivity TTL=%ds exceeded) "
                    "— starting fresh session.", self._max_age
                )
            except InvalidToken:
                logger.warning(
                    "Session cookie rejected (tampered or key-rotated) "
                    "— starting fresh session."
                )
            return {}
        except ValueError:  # covers json.JSONDecodeError and UnicodeDecodeError (both ⊂ ValueError)
            # Should not happen if we always encrypt our own JSON, but
            # handle defensively in case of a rare encoding edge case.
            logger.warning(
                "Session cookie decrypted successfully but JSON was invalid "
                "— starting fresh session."
            )
            return {}

    def _build_cookie(self, value: str) -> str:
        """Build a Set-Cookie header string for a live session."""
        parts = [
            f"{self._session_cookie}={value}",
            "Path=/",
            "HttpOnly",
            f"Max-Age={self._max_age}",
            f"SameSite={self._same_site}",
        ]
        if self._https_only:
            parts.append("Secure")
        return "; ".join(parts)

    def _delete_cookie(self) -> str:
        """Build a Set-Cookie header string that deletes the session cookie."""
        parts = [
            f"{self._session_cookie}=",
            "Path=/",
            "HttpOnly",
            "Max-Age=0",
            f"SameSite={self._same_site}",
        ]
        if self._https_only:
            parts.append("Secure")
        return "; ".join(parts)
