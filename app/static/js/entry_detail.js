/**
 * app/static/js/entry_detail.js
 *
 * Handles all interactive behaviour on the entry detail page:
 *   - Delete confirmation dialog
 *   - Copy username to clipboard
 *   - Password visibility toggle (show / hide)
 *   - Copy password to clipboard
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
 * WHY data-copy FOR THE USERNAME
 * --------------------------------
 * The Copy button for the username previously used:
 *     onclick="copyValue({{ entry.username | tojson }}, this)"
 * Inline event handlers are also blocked by script-src 'self'.  We use a
 * data-copy attribute instead and read it in addEventListener.
 */

document.addEventListener('DOMContentLoaded', () => {

  // ── Read server-rendered password from the hidden input ─────────────────
  // The hidden <input id="sv-password-value"> is rendered by entry_detail.html.
  const passwordInput = /** @type {HTMLInputElement|null} */ (
    document.getElementById('sv-password-value')
  );
  const _password = passwordInput ? passwordInput.value : '';

  // ── Delete confirmation ──────────────────────────────────────────────────
  // Replaces: onsubmit="return confirm('Delete this entry? ...')"
  const deleteForm = document.getElementById('delete-form');
  if (deleteForm) {
    deleteForm.addEventListener('submit', (e) => {
      if (!confirm('Delete this entry? This cannot be undone.')) {
        e.preventDefault();
      }
    });
  }

  // ── Copy-to-clipboard helper ─────────────────────────────────────────────
  /**
   * Write `value` to the clipboard and briefly show "Copied!" on `btn`.
   *
   * @param {string} value - The string to copy.
   * @param {HTMLElement} btn - The button element to update.
   */
  function copyValue(value, btn) {
    navigator.clipboard.writeText(value).then(() => {
      const orig = btn.textContent;
      btn.textContent = 'Copied!';
      btn.classList.add('text-green-600');
      setTimeout(() => {
        btn.textContent = orig;
        btn.classList.remove('text-green-600');
      }, 1500);
    });
  }

  // ── Copy username ────────────────────────────────────────────────────────
  // Replaces: onclick="copyValue({{ entry.username | tojson }}, this)"
  // The username value is stored in data-copy on the button by the template.
  const copyUsernameBtn = document.getElementById('copy-username-btn');
  if (copyUsernameBtn) {
    copyUsernameBtn.addEventListener('click', function () {
      copyValue(this.dataset.copy ?? '', this);
    });
  }

  // ── Password toggle ──────────────────────────────────────────────────────
  // Replaces: onclick="togglePassword()"
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
  // Replaces: onclick="copyValue(_password, this)"
  const copyPasswordBtn = document.getElementById('copy-password-btn');
  if (copyPasswordBtn) {
    copyPasswordBtn.addEventListener('click', function () {
      copyValue(_password, this);
    });
  }

});
