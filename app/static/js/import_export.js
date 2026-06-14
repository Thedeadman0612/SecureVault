/**
 * app/static/js/import_export.js
 *
 * Auto-submits the import form as soon as a file is selected from the file
 * picker. Without this, the user would have to click a separate Submit button
 * after choosing a file — the label-trigger-file-input pattern already
 * provides the "click to choose" UX, so auto-submit is the natural next step.
 *
 * CSP compliance: inline onchange handlers are blocked by script-src 'self',
 * so this external file attaches the listener via addEventListener.
 */

document.addEventListener('DOMContentLoaded', () => {
  const fileInput = document.getElementById('import-file');
  const form      = document.getElementById('import-form');
  const label     = document.getElementById('import-label');

  if (!fileInput || !form) return;

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length === 0) return;
    // Update the label text so the user can see which file was selected
    // before the page navigates away.
    if (label) label.textContent = `Importing "${fileInput.files[0].name}"…`;
    form.submit();
  });
});
