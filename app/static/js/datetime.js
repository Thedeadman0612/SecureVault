/**
 * app/static/js/datetime.js
 *
 * UTC → local-time converter.
 *
 * Any element with a data-utc="<ISO-Z>" attribute has its textContent
 * replaced with the browser's local representation of that UTC instant.
 * The server always stores and renders UTC; this script converts to the
 * user's own timezone without any server-side timezone knowledge.
 *
 * Example usage in a Jinja2 template:
 *   <time data-utc="{{ entry.created_at.strftime('%Y-%m-%dT%H:%M:%S') }}Z">
 *     {{ format_datetime(entry.created_at) }}
 *   </time>
 * The format_datetime() output is the server-side fallback shown briefly
 * before this script runs, or permanently if JavaScript is disabled.
 *
 * Why external? — Content-Security-Policy's script-src 'self' directive
 * blocks inline <script> tags. Moving to an external file allows a strict
 * CSP with no 'unsafe-inline' needed for scripts.
 */

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-utc]').forEach(el => {
    const d = new Date(el.dataset.utc);
    if (!Number.isNaN(d.getTime())) {
      el.textContent = d.toLocaleString(undefined, {
        year: 'numeric', month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit',
      });
    }
  });
});
