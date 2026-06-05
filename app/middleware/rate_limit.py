"""
app/middleware/rate_limit.py

Failed-attempt login lockout middleware.

WHY NOT JUST RATE-LIMIT ALL REQUESTS?
--------------------------------------
Generic rate limiting (e.g. 5 requests/minute regardless of outcome) has two
problems for a password manager:
  1. A slow attacker who spreads attempts over time bypasses a per-minute limit.
  2. Legitimate users who reload the login page repeatedly get blocked even
     though they made zero failed attempts.

Instead, we track FAILED authentication attempts specifically:
  • Only 401 responses from POST /login increment the counter.
  • A 303 redirect (successful login) resets the counter.
  • 403 (CSRF failure), 422 (bad form data), 500 (server error) are ignored.

LOCKOUT SEMANTICS
------------------
After MAX_FAILURES consecutive failures from the same IP address:
  • Every subsequent POST /login from that IP returns 429 Too Many Requests.
  • The lockout expires after LOCKOUT_SECONDS seconds (default: 15 minutes).
  • A successful login within the failure window resets the counter.
  • Server restart clears all counters (in-memory store only).

IN-MEMORY STORE — WHY NO DATABASE?
-------------------------------------
This is a local-first, single-process app.  An in-memory dict (with a
threading.Lock for safety) is sufficient.  Advantages over SQLite:
  • Zero I/O on every login request.
  • No migration needed.
  • No risk of locking or disk-full errors on the attempt-counter writes.
Disadvantage: counters reset on server restart.  Acceptable — this is a
personal vault, not a bank.  A restart during an attack window is rare and
the attacker would need to start counting again from zero.
Sub-lockout records (failures that never reached max_failures) are evicted
after _DEFAULT_FAILURE_WINDOW_SECONDS (1 hour) of inactivity so the dict
does not grow unboundedly under a slow-crawl attack from many IPs.

MIDDLEWARE POSITION IN STACK (main.py add_middleware call order)
----------------------------------------------------------------
  app.add_middleware(AuthGuard)                   # innermost
  app.add_middleware(LoginRateLimitMiddleware)     # inside CSRF — only genuine attempts
  app.add_middleware(CSRFMiddleware)               # blocks tokenless bots before RLL
  app.add_middleware(EncryptedSessionMiddleware)   # decodes session first
  app.add_middleware(CSPMiddleware)                # outermost

Placing LoginRateLimitMiddleware INSIDE CSRFMiddleware means:
  • Bots without a valid CSRF token get a 403 from CSRF and never reach the
    rate limiter — they cannot inflate the failure counter.
  • Only requests that passed CSRF validation (i.e., had a real session) are
    counted.  These are genuine password attempts.

The 429 lockout response still gets the CSP header because CSPMiddleware is
outermost and wraps every response.

IP ADDRESS NOTE
----------------
We track by `request.client.host` — the direct TCP connection IP.
Behind a reverse proxy (Nginx, Traefik) this would be the proxy's IP, not
the user's.  For a local-first app served directly by uvicorn there is no
proxy, so `client.host` is correct.  Phase 5 (Docker / deployment) should
revisit this if a proxy is added.
"""

import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from threading import Lock

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

# Maximum consecutive failures before lockout.
_DEFAULT_MAX_FAILURES: int = 5

# How long a locked-out IP must wait before trying again (seconds).
_DEFAULT_LOCKOUT_SECONDS: int = 900  # 15 minutes

# How long a sub-lockout record (failures < max_failures, no lockout triggered)
# is kept in the in-memory store before being evicted.  Prevents unbounded
# growth under a slow-crawl attack that never reaches the lockout threshold.
_DEFAULT_FAILURE_WINDOW_SECONDS: int = 3600  # 1 hour

# HTTP status codes emitted by POST /login that we care about.
_STATUS_FAILURE: int = 401   # wrong password
_STATUS_SUCCESS: int = 303   # redirect to /vault after successful login


# ---------------------------------------------------------------------------
# Attempt tracker
# ---------------------------------------------------------------------------


@dataclass
class _AttemptRecord:
    """Per-IP state stored in the tracker."""

    failures: int = 0
    # monotonic clock value (time.monotonic()) when the lockout ends; 0.0 = not locked.
    locked_until: float = 0.0
    # monotonic clock value of the most recent failed attempt; 0.0 = no attempts yet.
    last_failure_at: float = 0.0


class _LoginAttemptTracker:
    """Thread-safe, in-memory store of failed login attempts per IP address.

    Intended to be instantiated once per ``LoginRateLimitMiddleware`` instance.
    The middleware holds the only reference, so tests that create a fresh
    middleware per test fixture automatically get a clean tracker.
    """

    def __init__(
        self,
        max_failures: int = _DEFAULT_MAX_FAILURES,
        lockout_seconds: int = _DEFAULT_LOCKOUT_SECONDS,
        failure_window_seconds: int = _DEFAULT_FAILURE_WINDOW_SECONDS,
    ) -> None:
        self._max_failures = max_failures
        self._lockout_seconds = lockout_seconds
        self._failure_window_seconds = failure_window_seconds
        self._records: dict[str, _AttemptRecord] = {}
        self._lock = Lock()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def is_locked(self, ip: str) -> tuple[bool, int]:
        """Return ``(locked, seconds_remaining)`` for the given IP.

        If the lockout period has expired this call also resets the record so
        the IP gets a fresh failure counter.
        """
        with self._lock:
            record = self._records.get(ip)
            if record is None:
                return False, 0

            now = time.monotonic()
            if record.locked_until > now:
                return True, int(record.locked_until - now)

            # Lockout has expired — clean up so the next failure starts fresh.
            if record.locked_until > 0:
                del self._records[ip]
                return False, 0

            # No active lockout — evict sub-lockout records whose failure window
            # has elapsed.  Prevents unbounded memory growth from IPs that fail
            # fewer than max_failures times and never trigger a lockout.
            if (
                record.last_failure_at > 0
                and (now - record.last_failure_at) >= self._failure_window_seconds
            ):
                del self._records[ip]
            return False, 0

    def record_failure(self, ip: str) -> int:
        """Increment the failure counter for ``ip``.

        Triggers a lockout when ``max_failures`` is reached.
        Returns the updated failure count.
        """
        with self._lock:
            if ip not in self._records:
                self._records[ip] = _AttemptRecord()
            record = self._records[ip]
            record.failures += 1
            record.last_failure_at = time.monotonic()

            if record.failures >= self._max_failures:
                record.locked_until = time.monotonic() + self._lockout_seconds
                logger.warning(
                    "Login lockout triggered — IP=%s failures=%d lockout=%ds",
                    ip,
                    record.failures,
                    self._lockout_seconds,
                )
            else:
                logger.info(
                    "Failed login attempt — IP=%s failures=%d/%d",
                    ip,
                    record.failures,
                    self._max_failures,
                )

            return record.failures

    def record_success(self, ip: str) -> None:
        """Reset the failure counter for ``ip`` after a successful login."""
        with self._lock:
            self._records.pop(ip, None)

    def failure_count(self, ip: str) -> int:
        """Return the current failure count for ``ip`` (0 if no record)."""
        with self._lock:
            record = self._records.get(ip)
            return record.failures if record is not None else 0

    def reset_all(self) -> None:
        """Clear every record.  Used in tests to restore a clean state."""
        with self._lock:
            self._records.clear()


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class LoginRateLimitMiddleware(BaseHTTPMiddleware):
    """Enforce a failed-attempt lockout on ``POST /login``.

    All other routes are passed through without inspection.

    Parameters
    ----------
    app:
        The ASGI application to wrap.
    max_failures:
        Number of consecutive wrong-password attempts before lockout.
        Defaults to 5.
    lockout_seconds:
        How long the IP is locked out after hitting ``max_failures``.
        Defaults to 900 s (15 minutes).
    """

    def __init__(
        self,
        app,
        max_failures: int = _DEFAULT_MAX_FAILURES,
        lockout_seconds: int = _DEFAULT_LOCKOUT_SECONDS,
        _tracker_override: _LoginAttemptTracker | None = None,
    ) -> None:
        super().__init__(app)
        # Accept an externally-created tracker so callers (e.g. main.py) can
        # expose it via app.state for test-reset access without reaching into
        # the middleware internals.
        self._tracker = _tracker_override or _LoginAttemptTracker(
            max_failures=max_failures,
            lockout_seconds=lockout_seconds,
        )

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Pass non-login requests straight through; enforce lockout on POST /login."""
        # Only intercept POST /login — every other route is unaffected.
        if request.method != "POST" or request.url.path != "/login":
            return await call_next(request)

        # Safely extract the client IP; fall back to loopback for test clients
        # that don't set request.client.
        ip: str = request.client.host if request.client else "127.0.0.1"

        # ── Pre-flight lockout check ────────────────────────────────────────
        locked, remaining = self._tracker.is_locked(ip)
        if locked:
            logger.warning(
                "Login attempt blocked — IP=%s locked for %ds more", ip, remaining
            )
            return HTMLResponse(
                content=_lockout_page(remaining),
                status_code=429,
                headers={"Retry-After": str(remaining)},
            )

        # ── Forward the request ─────────────────────────────────────────────
        response: Response = await call_next(request)

        # ── Post-flight counter update ──────────────────────────────────────
        if response.status_code == _STATUS_FAILURE:
            # Wrong password — record the failure.
            self._tracker.record_failure(ip)
        elif response.status_code == _STATUS_SUCCESS:
            # Successful login — reset the failure counter.
            self._tracker.record_success(ip)
        # All other status codes (422, 500, etc.) are ignored.

        return response


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _lockout_page(seconds_remaining: int) -> str:
    """Minimal inline HTML page returned when a lockout is active.

    Intentionally avoids Jinja2 — the middleware runs before the route layer
    and must be self-contained.  The same pattern is used by CSRFMiddleware
    and the global error handlers in main.py.
    """
    minutes = seconds_remaining // 60
    secs = seconds_remaining % 60

    if minutes > 0:
        time_str = f"{minutes} minute{'s' if minutes != 1 else ''}"
        if secs:
            time_str += f" {secs} second{'s' if secs != 1 else ''}"
    else:
        time_str = f"{seconds_remaining} second{'s' if seconds_remaining != 1 else ''}"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureVault — Too Many Attempts</title>
</head>
<body>
  <h1>429 — Too Many Failed Attempts</h1>
  <p>Your IP address has been temporarily locked after too many incorrect
     password attempts.</p>
  <p>Please try again in <strong>{time_str}</strong>.</p>
  <a href="/login">Return to login</a>
</body>
</html>"""
