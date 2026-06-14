/**
 * app/static/js/dark_mode.js
 *
 * Dark mode toggle — persisted to localStorage across page navigations.
 *
 * Adds / removes the `dark` class on <html>. dark.css uses `html.dark`
 * selectors to override Tailwind utility classes.
 *
 * Preference key: "sv-dark-mode" (value "on" | absent)
 *
 * The script runs as soon as it is parsed (no DOMContentLoaded wait) so that
 * the class is applied before the page paints, preventing a white flash in
 * dark mode.
 */
(function () {
  'use strict';

  var STORAGE_KEY = 'sv-dark-mode';

  function isDark() {
    return localStorage.getItem(STORAGE_KEY) === 'on';
  }

  function applyTheme(dark) {
    if (dark) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }

  function updateToggleBtn(dark) {
    var btn = document.getElementById('dark-mode-toggle');
    if (!btn) return;
    btn.textContent = dark ? '☀️' : '🌙'; // ☀️ or 🌙
    btn.setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
    btn.setAttribute('title',      dark ? 'Light mode' : 'Dark mode');
  }

  // Apply saved preference immediately (before DOM is ready).
  applyTheme(isDark());

  // Wire up the toggle button once the DOM is ready.
  document.addEventListener('DOMContentLoaded', function () {
    updateToggleBtn(isDark());

    var btn = document.getElementById('dark-mode-toggle');
    if (!btn) return;

    btn.addEventListener('click', function () {
      var nowDark = !isDark();
      if (nowDark) {
        localStorage.setItem(STORAGE_KEY, 'on');
      } else {
        localStorage.removeItem(STORAGE_KEY);
      }
      applyTheme(nowDark);
      updateToggleBtn(nowDark);
    });
  });
}());
