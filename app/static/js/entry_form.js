/**
 * app/static/js/entry_form.js
 *
 * Handles the password visibility toggle on the entry create/edit form.
 *
 * Replaces the inline onclick="toggleVisibility('form-password', 'toggle-form-password')"
 * attribute, which is blocked by Content-Security-Policy's script-src 'self'.
 * An addEventListener call in an external file is CSP-compliant.
 */

document.addEventListener('DOMContentLoaded', () => {
  const toggleBtn = document.getElementById('toggle-form-password');
  const input = /** @type {HTMLInputElement|null} */ (
    document.getElementById('form-password')
  );

  if (toggleBtn && input) {
    toggleBtn.addEventListener('click', () => {
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      toggleBtn.textContent = show ? 'Hide' : 'Show';
    });
  }
});
