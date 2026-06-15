/**
 * app/static/js/vault_search.js
 *
 * Live client-side filtering for the vault dashboard.
 * Filters entry rows as the user types without a page reload.
 * URL is synced via history.replaceState so filtered states remain bookmarkable.
 */

document.addEventListener('DOMContentLoaded', () => {
  const form        = document.getElementById('vault-search-form');
  const qInput      = /** @type {HTMLInputElement|null}  */ (document.getElementById('vault-search-q'));
  const catSelect   = /** @type {HTMLSelectElement|null} */ (document.getElementById('vault-search-category'));
  const clearBtn    = document.getElementById('vault-clear-btn');
  const clearBtnEmpty = document.getElementById('vault-clear-btn-empty');
  const tableWrap   = document.getElementById('vault-entries-table');
  const emptyBlock  = document.getElementById('vault-empty-filtered');
  const countEl     = document.getElementById('vault-entry-count');
  const rows        = /** @type {NodeListOf<HTMLElement>} */ (
    document.querySelectorAll('[data-vault-entry]')
  );

  if (!qInput && !catSelect) return;

  function filterRows() {
    const q   = qInput    ? qInput.value.trim().toLowerCase()  : '';
    const cat = catSelect ? catSelect.value                     : '';

    let visible = 0;
    rows.forEach(row => {
      const title   = row.dataset.title    || '';
      const website = row.dataset.website  || '';
      const rowCat  = row.dataset.category || '';

      const matchQ   = !q   || title.includes(q)  || website.includes(q);
      const matchCat = !cat || rowCat === cat;

      const show = matchQ && matchCat;
      row.classList.toggle('hidden', !show);
      if (show) visible++;
    });

    // Update entry count label
    if (countEl) {
      countEl.textContent = visible > 0
        ? `(${visible} ${visible === 1 ? 'entry' : 'entries'})`
        : '';
    }

    // Toggle table / no-results block
    const hasFilter = Boolean(q || cat);
    if (tableWrap)  tableWrap.classList.toggle('hidden', visible === 0);
    if (emptyBlock) emptyBlock.classList.toggle('hidden', !(visible === 0 && hasFilter));

    // Show Clear button only when a filter is active
    if (clearBtn) clearBtn.classList.toggle('hidden', !hasFilter);

    // Sync URL without a page reload so the filter state is bookmarkable
    const params = new URLSearchParams();
    if (q)   params.set('q', q);
    if (cat) params.set('category', cat);
    const url = params.toString() ? `/vault?${params}` : '/vault';
    history.replaceState(null, '', url);
  }

  // Debounced live search while typing
  let debounceTimer;
  if (qInput) {
    qInput.addEventListener('input', () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(filterRows, 150);
    });
  }

  // Instant filter on category change
  if (catSelect) catSelect.addEventListener('change', filterRows);

  // Prevent form submit (Enter key / Search button) from reloading the page
  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      clearTimeout(debounceTimer);
      filterRows();
    });
  }

  // Clear handler — shared by the toolbar Clear button and the no-results Clear filter button
  function clearFilter() {
    if (qInput)    qInput.value    = '';
    if (catSelect) catSelect.value = '';
    filterRows();
    if (qInput) qInput.focus();
  }

  if (clearBtn)      clearBtn.addEventListener('click', clearFilter);
  if (clearBtnEmpty) clearBtnEmpty.addEventListener('click', clearFilter);

  // Apply initial filter from URL params (handles direct navigation / page refresh)
  filterRows();
});
