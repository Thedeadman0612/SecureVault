/**
 * session_timeout.js
 *
 * Auto-redirects to /login after a period of inactivity matching the
 * server-side SESSION_TIMEOUT_MINUTES setting (read from the
 * <meta name="sv-timeout" content="<seconds>"> tag in base.html).
 *
 * Only runs on authenticated pages. Skipped on /login, /setup, and /2fa/*.
 *
 * 60 seconds before logout: shows a dismissible warning banner.
 * On any user activity: resets the timer and removes the banner.
 */
(function () {
  'use strict';

  // Skip non-authenticated pages — nothing to guard there.
  const _SKIP_PREFIXES = ['/login', '/setup', '/2fa/'];
  if (_SKIP_PREFIXES.some(function (p) { return window.location.pathname.startsWith(p); })) {
    return;
  }

  // Read timeout from the <meta> tag set by base.html.
  // Fall back to 600 s (10 min) if the tag is absent.
  var meta = document.querySelector('meta[name="sv-timeout"]');
  var timeoutMs = meta ? parseInt(meta.content, 10) * 1000 : 600000;
  var warningMs = Math.min(60000, Math.floor(timeoutMs / 2));

  var logoutTimer = null;
  var warningTimer = null;
  var warningEl = null;

  function removeWarning() {
    if (warningEl) {
      warningEl.remove();
      warningEl = null;
    }
  }

  function showWarning() {
    if (warningEl) return;

    var secs = Math.round(warningMs / 1000);

    warningEl = document.createElement('div');
    warningEl.setAttribute('role', 'alert');
    warningEl.style.cssText = [
      'position:fixed', 'bottom:0', 'left:0', 'right:0',
      'background:#dc2626', 'color:#fff',
      'padding:12px 16px', 'z-index:9999', 'font-size:14px',
      'display:flex', 'align-items:center', 'justify-content:center', 'gap:12px',
    ].join(';');

    var msg = document.createElement('span');
    msg.textContent = 'Your session will expire in ' + secs + ' seconds due to inactivity.';

    var btn = document.createElement('button');
    btn.textContent = 'Stay logged in';
    btn.style.cssText = [
      'padding:4px 14px', 'background:#fff', 'color:#dc2626',
      'border:none', 'border-radius:4px', 'cursor:pointer', 'font-weight:600',
    ].join(';');
    btn.addEventListener('click', reset);

    warningEl.appendChild(msg);
    warningEl.appendChild(btn);
    document.body.appendChild(warningEl);
  }

  function logout() {
    window.location.href = '/login';
  }

  function reset() {
    clearTimeout(logoutTimer);
    clearTimeout(warningTimer);
    removeWarning();
    warningTimer = setTimeout(showWarning, timeoutMs - warningMs);
    logoutTimer  = setTimeout(logout, timeoutMs);
  }

  // Reset on any user interaction.
  ['mousemove', 'keydown', 'mousedown', 'touchstart', 'scroll', 'click'].forEach(function (evt) {
    document.addEventListener(evt, reset, { passive: true });
  });

  // Kick off the timer when the page loads.
  reset();
}());
