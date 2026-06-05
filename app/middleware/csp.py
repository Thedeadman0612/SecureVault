"""
app/middleware/csp.py

Content-Security-Policy (CSP) middleware.

WHY CSP MATTERS FOR A PASSWORD MANAGER
---------------------------------------
This app renders decrypted vault credentials in plain HTML.  If an attacker
can inject a <script> tag (XSS), they can silently read every password from
the DOM and exfiltrate it.  CSP instructs the browser to refuse to execute
any script not explicitly allowed by the policy — providing a critical
browser-level defence even if a template accidentally renders user-controlled
content without escaping.

WHAT EACH DIRECTIVE DOES
--------------------------
default-src 'self'
    Catch-all fallback for any resource type not explicitly listed.
    Only same-origin resources are allowed unless overridden below.

script-src 'self'
    Scripts may only be loaded from our own origin (/static/js/*).
    NO 'unsafe-inline' → inline <script> tags are blocked.
    NO 'unsafe-eval'   → eval() and new Function() are blocked.
    This is the primary XSS mitigation.  Tailwind is self-hosted at
    /static/js/tailwind.min.js (downloaded from cdn.tailwindcss.com in
    Phase 2) so no external CDN domain is needed here.

style-src 'self' 'unsafe-inline'
    Tailwind Play CDN dynamically injects a <style> element with generated
    CSS at runtime.  'unsafe-inline' for *styles* is accepted because:
      • Styles cannot exfiltrate clipboard contents or make network requests.
      • The main CSS-based attack (overlay clickjacking) is already blocked
        by frame-ancestors 'none'.
    Phase 5 will compile Tailwind to a static CSS file, eliminating this
    exception entirely.

img-src 'self' data:
    Allows same-origin images and data: URIs (e.g. base64-encoded icons
    used in future phases).

font-src 'self'
    Same-origin fonts only.  If a web font CDN is added in a later phase,
    add its origin here.

connect-src 'self'
    fetch(), XMLHttpRequest, WebSocket connections to same origin only.
    Prevents a successful XSS from POSTing vault data to an external server.

frame-ancestors 'none'
    Disallows embedding this app in an <iframe>, <frame>, <object>, or
    <embed> from any origin — clickjacking protection.

X-Frame-Options: DENY
    Legacy clickjacking protection for browsers that pre-date CSP's
    frame-ancestors (IE 11, older Edge, some mobile browsers).  Redundant
    with frame-ancestors 'none' but set alongside it per defence-in-depth.

X-Content-Type-Options: nosniff
    Instructs browsers never to MIME-sniff a response away from its declared
    Content-Type.  Without this, IE/Chrome on some versions could interpret a
    malformed response body as JavaScript and execute it — bypassing the
    script-src 'self' restriction.  One-liner with no downside.

base-uri 'self'
    Prevents a <base href="https://evil.com"> injection from redirecting all
    relative URLs to an attacker-controlled origin.

form-action 'self'
    Form submissions may only target the same origin.  An XSS that injects
    a <form action="https://evil.com"> cannot harvest credentials.

object-src 'none'
    Disables Flash, Java applets, and other browser plugins entirely.
    These are legacy attack surfaces with no legitimate use here.

MIDDLEWARE POSITION IN STACK (main.py add_middleware call order)
-----------------------------------------------------------------
CSPMiddleware is added LAST so it becomes the OUTERMOST layer.  This means
it intercepts every response — including error pages returned by inner
middleware (CSRF 403, Session errors) — and stamps the CSP header on all
of them.  CSP needs no session data, so its position relative to
SessionMiddleware is not security-relevant.

  app.add_middleware(AuthGuard)              # innermost
  app.add_middleware(CSRFMiddleware)         # middle-inner
  app.add_middleware(SessionMiddleware, ...) # middle-outer
  app.add_middleware(CSPMiddleware)          # outermost — added last
"""

from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# ---------------------------------------------------------------------------
# Policy definition
# ---------------------------------------------------------------------------

# Repeated token used across multiple CSP directives.
_SELF = "'self'"

# Each entry is (directive, value).  Keeping them in a dict makes it easy to
# document each directive and to override individual values in tests.
_CSP_DIRECTIVES: dict[str, str] = {
    "default-src": _SELF,
    # No 'unsafe-inline', no 'unsafe-eval', no external CDN — see module doc.
    "script-src": _SELF,
    # 'unsafe-inline' needed for Tailwind's runtime style injection.
    # Removed in Phase 5 when Tailwind is compiled to a static CSS file.
    "style-src": f"{_SELF} 'unsafe-inline'",
    "img-src": f"{_SELF} data:",
    "font-src": _SELF,
    "connect-src": _SELF,
    "frame-ancestors": "'none'",
    "base-uri": _SELF,
    "form-action": _SELF,
    "object-src": "'none'",
}

# Pre-build the header value once at import time — it never changes per request.
CSP_HEADER_VALUE: str = "; ".join(
    f"{directive} {value}" for directive, value in _CSP_DIRECTIVES.items()
)

# The standard header name.  All modern browsers support it.
# X-Content-Security-Policy (IE) and X-WebKit-CSP (old WebKit) are legacy
# aliases we don't need for this local-first app.
_CSP_HEADER_NAME = "Content-Security-Policy"

# Legacy clickjacking guard for browsers that pre-date CSP's frame-ancestors.
# Set alongside frame-ancestors 'none' in the CSP header — redundancy is
# intentional here (defence-in-depth).
_X_FRAME_OPTIONS_NAME  = "X-Frame-Options"
_X_FRAME_OPTIONS_VALUE = "DENY"

# Prevents MIME-type sniffing: the browser must honour the declared
# Content-Type and never guess that a non-script resource is JavaScript.
_X_CONTENT_TYPE_OPTIONS_NAME  = "X-Content-Type-Options"
_X_CONTENT_TYPE_OPTIONS_VALUE = "nosniff"


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class CSPMiddleware(BaseHTTPMiddleware):
    """Stamp every HTTP response with security headers.

    This middleware sits at the outermost layer of the stack so it adds headers
    to ALL responses — including error pages produced by inner middleware before
    a route handler is ever invoked.

    Headers set on every response:
      Content-Security-Policy     — primary XSS + clickjacking defence.
      X-Frame-Options: DENY       — legacy clickjacking guard (pre-CSP browsers).
      X-Content-Type-Options: nosniff — blocks MIME-type sniffing attacks.

    No request-side logic is needed: headers are added on the response path only.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers[_CSP_HEADER_NAME] = CSP_HEADER_VALUE
        response.headers[_X_FRAME_OPTIONS_NAME] = _X_FRAME_OPTIONS_VALUE
        response.headers[_X_CONTENT_TYPE_OPTIONS_NAME] = _X_CONTENT_TYPE_OPTIONS_VALUE
        return response
