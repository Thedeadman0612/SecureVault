/**
 * app/static/js/entry_detail.js
 *
 * Handles all interactive behaviour on the entry detail page:
 *   - Delete confirmation dialog
 *   - Copy username / password to clipboard with auto-clear countdown
 *   - Password visibility toggle (show / hide)
 *
 * WHY A HIDDEN INPUT FOR THE PASSWORD
 * ------------------------------------
 * Content-Security-Policy's script-src 'self' blocks inline <script> tags, so
 * we cannot write:
 *     <script>const _password = "{{ entry.password }}";</script>
 * Instead, the Jinja2 template renders the server-side value into a hidden
 * <input id="sv-password-value" value="{{ entry.password }}">.
 * Jinja2's auto-escape converts special characters (e.g. " → &quot;) in HTML
 * attribute contexts.  When JavaScript reads input.value, the browser
 * automatically unescapes those entities, so the original string is recovered
 * byte-for-byte.  Security is identical to the previous JS-literal approach —
 * the password is already in the HTML page in both cases.
 *
 * CLIPBOARD AUTO-CLEAR
 * ---------------------
 * After copying any value the clipboard is wiped after CLIPBOARD_CLEAR_SECS
 * seconds.  A live countdown is shown on the button ("Clears in 28s") so the
 * user knows when the sensitive value will be gone.  Clicking Copy again while
 * a countdown is running restarts the timer from the beginning.
 */

/** Seconds after which the clipboard is automatically cleared. */
const CLIPBOARD_CLEAR_SECS = 30;

// WeakMaps — per-button timer state. WeakMap keys are the button elements so
// GC can collect entries if a button is ever removed from the DOM.
/** @type {WeakMap<HTMLElement, ReturnType<typeof setTimeout>>} */
const _clearTimers = new WeakMap();
/** @type {WeakMap<HTMLElement, ReturnType<typeof setInterval>>} */
const _countdownIntervals = new WeakMap();
/** @type {WeakMap<HTMLElement, string>} */
const _origLabels = new WeakMap();

/**
 * Copy `value` to the clipboard, then show a live countdown on `btn` and
 * clear the clipboard when it reaches zero.
 *
 * Clicking while a countdown is already running restarts the 30-second window.
 *
 * @param {string} value - The string to copy.
 * @param {HTMLElement} btn - The button element to update.
 */
function copyValue(value, btn) {
  // Cancel any in-progress countdown for this button.
  const existingClear    = _clearTimers.get(btn);
  const existingInterval = _countdownIntervals.get(btn);
  if (existingClear    !== undefined) clearTimeout(existingClear);
  if (existingInterval !== undefined) clearInterval(existingInterval);

  // Persist the original label so it can be restored after the countdown.
  if (!_origLabels.has(btn)) {
    _origLabels.set(btn, btn.textContent ?? 'Copy');
  }
  const orig = _origLabels.get(btn) ?? 'Copy';

  navigator.clipboard.writeText(value).then(() => {
    btn.classList.add('text-green-600');
    let remaining = CLIPBOARD_CLEAR_SECS;
    btn.textContent = `Clears in ${remaining}s`;

    function tick() {
      remaining--;
      if (remaining > 0) {
        btn.textContent = `Clears in ${remaining}s`;
      } else {
        clearInterval(_countdownIntervals.get(btn));
      }
    }
    const intervalId = setInterval(tick, 1000);
    _countdownIntervals.set(btn, intervalId);

    function onExpire() {
      clearInterval(intervalId);
      navigator.clipboard.writeText('').catch(() => {});
      btn.textContent = orig;
      btn.classList.remove('text-green-600');
      _clearTimers.delete(btn);
      _countdownIntervals.delete(btn);
    }
    _clearTimers.set(btn, setTimeout(onExpire, CLIPBOARD_CLEAR_SECS * 1000));

  }).catch(() => {
    // Clipboard API unavailable (non-HTTPS, sandboxed iframe, or permission denied).
    btn.textContent = 'Failed';
    setTimeout(() => { btn.textContent = orig; }, 1500);
  });
}

document.addEventListener('DOMContentLoaded', () => {

  // ── Read server-rendered password from the hidden input ─────────────────
  const passwordInput = /** @type {HTMLInputElement|null} */ (
    document.getElementById('sv-password-value')
  );
  const _password = passwordInput ? passwordInput.value : '';

  // ── Delete confirmation ──────────────────────────────────────────────────
  const deleteForm = document.getElementById('delete-form');
  if (deleteForm) {
    deleteForm.addEventListener('submit', (e) => {
      if (!confirm('Delete this entry? This cannot be undone.')) {
        e.preventDefault();
      }
    });
  }

  // ── Copy username ────────────────────────────────────────────────────────
  const copyUsernameBtn = document.getElementById('copy-username-btn');
  if (copyUsernameBtn) {
    copyUsernameBtn.addEventListener('click', function () {
      copyValue(this.dataset.copy ?? '', this);
    });
  }

  // ── Password toggle ──────────────────────────────────────────────────────
  const passwordDisplay = document.getElementById('password-display');
  const toggleBtn = document.getElementById('toggle-password-btn');

  if (toggleBtn && passwordDisplay) {
    toggleBtn.addEventListener('click', () => {
      const showing = toggleBtn.textContent.trim() === 'Hide';
      passwordDisplay.textContent = showing ? '••••••••' : _password;
      passwordDisplay.classList.toggle('tracking-widest', showing);
      toggleBtn.textContent = showing ? 'Show' : 'Hide';
    });
  }

  // ── Copy password ────────────────────────────────────────────────────────
  const copyPasswordBtn = document.getElementById('copy-password-btn');
  if (copyPasswordBtn) {
    copyPasswordBtn.addEventListener('click', function () {
      copyValue(_password, this);
    });
  }

});
