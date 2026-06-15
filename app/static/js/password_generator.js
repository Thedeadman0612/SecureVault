/**
 * app/static/js/password_generator.js
 *
 * Password generator modal for the entry create/edit form.
 *
 * Uses crypto.getRandomValues() for cryptographically secure randomness.
 * No inline event attributes — all handlers use addEventListener (CSP compliant).
 */

const _LOWER   = 'abcdefghijklmnopqrstuvwxyz';
const _UPPER   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const _NUMBERS = '0123456789';
const _SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?';

/**
 * Generate a cryptographically random password.
 *
 * Guarantees at least one character from each enabled character class, then
 * fills the remainder with characters drawn uniformly from the full pool.
 * Result is Fisher-Yates shuffled using crypto.getRandomValues().
 *
 * @param {number}  length
 * @param {boolean} useUpper
 * @param {boolean} useNumbers
 * @param {boolean} useSymbols
 * @returns {string}
 */
function generatePassword(length, useUpper, useNumbers, useSymbols) {
  let pool = _LOWER;
  /** @type {string[]} */
  const required = [];

  if (useUpper)   { pool += _UPPER;   required.push(_UPPER); }
  if (useNumbers) { pool += _NUMBERS; required.push(_NUMBERS); }
  if (useSymbols) { pool += _SYMBOLS; required.push(_SYMBOLS); }

  // Seed array big enough for required chars + remaining fill
  const rand = new Uint32Array(length + required.length);
  crypto.getRandomValues(rand);

  const chars = [];
  required.forEach((charset, i) => {
    chars.push(charset[rand[length + i] % charset.length]);
  });

  for (let i = chars.length; i < length; i++) {
    chars.push(pool[rand[i] % pool.length]);
  }

  // Fisher-Yates shuffle with fresh randomness
  const shuffleRand = new Uint32Array(length);
  crypto.getRandomValues(shuffleRand);
  for (let i = length - 1; i > 0; i--) {
    const j = shuffleRand[i] % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join('');
}

document.addEventListener('DOMContentLoaded', () => {
  const openBtn    = document.getElementById('generate-password-btn');
  const modal      = document.getElementById('password-generator-modal');
  const closeBtn   = document.getElementById('gen-close-btn');
  const generateBtn= document.getElementById('gen-generate-btn');
  const useBtn     = document.getElementById('gen-use-btn');
  const display    = document.getElementById('generated-password-display');
  const lengthSlider = /** @type {HTMLInputElement|null} */ (document.getElementById('gen-length'));
  const lengthDisplay = document.getElementById('length-display');
  const uppercaseChk  = /** @type {HTMLInputElement|null} */ (document.getElementById('gen-uppercase'));
  const numbersChk    = /** @type {HTMLInputElement|null} */ (document.getElementById('gen-numbers'));
  const symbolsChk    = /** @type {HTMLInputElement|null} */ (document.getElementById('gen-symbols'));
  const passwordInput = /** @type {HTMLInputElement|null} */ (document.getElementById('form-password'));
  const toggleBtn     = document.getElementById('toggle-form-password');

  if (!openBtn || !modal) return;

  let lastGenerated = '';

  function generate() {
    if (!lengthSlider || !uppercaseChk || !numbersChk || !symbolsChk) return;
    const length = parseInt(lengthSlider.value, 10);
    lastGenerated = generatePassword(
      length,
      uppercaseChk.checked,
      numbersChk.checked,
      symbolsChk.checked,
    );
    if (display) display.textContent = lastGenerated;
  }

  function openModal() {
    generate();
    modal.classList.remove('hidden');
  }

  function closeModal() {
    modal.classList.add('hidden');
  }

  openBtn.addEventListener('click', openModal);
  if (closeBtn) closeBtn.addEventListener('click', closeModal);

  // Close on backdrop click (click outside the inner card).
  modal.addEventListener('click', (e) => {
    if (e.target === modal) closeModal();
  });

  // Close on Escape key.
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !modal.classList.contains('hidden')) closeModal();
  });

  if (generateBtn) generateBtn.addEventListener('click', generate);

  if (lengthSlider && lengthDisplay) {
    lengthSlider.addEventListener('input', () => {
      lengthDisplay.textContent = lengthSlider.value;
      generate();
    });
  }

  [uppercaseChk, numbersChk, symbolsChk].forEach((chk) => {
    if (chk) chk.addEventListener('change', generate);
  });

  if (useBtn) {
    useBtn.addEventListener('click', () => {
      if (passwordInput && lastGenerated) {
        passwordInput.value = lastGenerated;
        // Make the filled password visible so the user can see what was applied.
        passwordInput.type = 'text';
        if (toggleBtn) toggleBtn.textContent = 'Hide';
        // Fire input event so the strength indicator in entry_form.js updates.
        passwordInput.dispatchEvent(new Event('input'));
      }
      closeModal();
    });
  }
});
