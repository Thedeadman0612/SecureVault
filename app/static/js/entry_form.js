/**
 * app/static/js/entry_form.js
 *
 * Handles the password visibility toggle and real-time strength indicator on
 * the entry create/edit form.
 *
 * Inline event attributes (onclick, oninput) are blocked by CSP's
 * script-src 'self'. All handlers are attached via addEventListener here.
 */

/** @param {string} password */
function getStrengthLevel(password) {
  let score = 0;
  if (password.length >= 8)  score++;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  const levels = [
    { label: 'Very Weak',   colorClass: 'bg-red-500',    labelClass: 'text-red-600',    width: '16%' },
    { label: 'Very Weak',   colorClass: 'bg-red-500',    labelClass: 'text-red-600',    width: '16%' },
    { label: 'Weak',        colorClass: 'bg-orange-500', labelClass: 'text-orange-600', width: '33%' },
    { label: 'Fair',        colorClass: 'bg-yellow-500', labelClass: 'text-yellow-600', width: '50%' },
    { label: 'Strong',      colorClass: 'bg-lime-500',   labelClass: 'text-lime-700',   width: '75%' },
    { label: 'Very Strong', colorClass: 'bg-green-500',  labelClass: 'text-green-600',  width: '100%' },
    { label: 'Very Strong', colorClass: 'bg-green-500',  labelClass: 'text-green-600',  width: '100%' },
  ];
  return levels[score];
}

/** @param {string} password */
function updateStrengthIndicator(password) {
  const container = document.getElementById('strength-bar-container');
  const bar       = document.getElementById('strength-bar');
  const label     = document.getElementById('strength-label');

  if (!container || !bar || !label) return;

  if (!password) {
    container.classList.add('hidden');
    return;
  }

  const level = getStrengthLevel(password);
  container.classList.remove('hidden');
  bar.className   = `h-full rounded-full transition-all duration-300 ${level.colorClass}`;
  bar.style.width = level.width;
  label.textContent = level.label;
  label.className   = `text-xs mt-0.5 font-medium ${level.labelClass}`;
}

document.addEventListener('DOMContentLoaded', () => {
  const toggleBtn = document.getElementById('toggle-form-password');
  const input     = /** @type {HTMLInputElement|null} */ (
    document.getElementById('form-password')
  );

  if (toggleBtn && input) {
    toggleBtn.addEventListener('click', () => {
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      toggleBtn.textContent = show ? 'Hide' : 'Show';
    });

    input.addEventListener('input', () => updateStrengthIndicator(input.value));

    // Show strength for pre-filled values (edit mode).
    if (input.value) updateStrengthIndicator(input.value);
  }
});
