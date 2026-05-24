#!/usr/bin/env bash
#
# update_progress.sh
#
# Stop hook for SecureVault. Fires when Claude Code finishes responding.
#
# Logic:
#   1. Look for uncommitted/modified Python files in app/ (skip stubs: __init__.py
#      and migrations/). If none found → exit 0 (nothing to do).
#   2. Check a sentinel file to avoid infinite loops: if CLAUDE.md was updated
#      less than 90 seconds ago by this hook, skip.
#   3. Otherwise → touch sentinel + output decision:block JSON so Claude re-activates
#      and updates the Progress Tracker in CLAUDE.md before truly stopping.
#
# The sentinel lives in /tmp so it auto-clears on reboot and doesn't pollute the repo.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SENTINEL="/tmp/sv_progress_tracker_updated"
COOLDOWN_SECONDS=90

# ── 1. Find modified Python files in app/ (excluding __init__.py + migrations) ──
CHANGED=$(
  git -C "$PROJECT_DIR" status --porcelain 2>/dev/null \
    | awk '{print $NF}' \
    | grep -E '^app/.*\.py$' \
    | grep -v '__init__\.py' \
    | grep -v 'migrations/' \
    || true
)

# Nothing meaningful changed → nothing to do
if [ -z "$CHANGED" ]; then
  exit 0
fi

# ── 2. Sentinel check — avoid triggering again right after Claude updates CLAUDE.md ──
if [ -f "$SENTINEL" ]; then
  NOW=$(date +%s)
  # macOS uses -f %m; Linux uses -c %Y
  MTIME=$(stat -f %m "$SENTINEL" 2>/dev/null || stat -c %Y "$SENTINEL" 2>/dev/null || echo 0)
  if [ $((NOW - MTIME)) -lt $COOLDOWN_SECONDS ]; then
    exit 0
  fi
fi

# ── 3. Touch sentinel and ask Claude to update CLAUDE.md ──
touch "$SENTINEL"

# Output JSON — decision:block re-activates Claude with the reason as its next task.
# Keep the reason concise and actionable so Claude knows exactly what to do.
printf '%s' '{
  "decision": "block",
  "reason": "Uncommitted Python implementation files were detected in app/. Before finishing, update the Progress Tracker section in CLAUDE.md: (1) Check each Python file listed in the ❌ Still To Implement table — if it now has real implementation code (not just a one-line stub comment), move it to the ✅ Completed table with a short description of what was implemented. (2) Ensure the ❌ Still To Implement table only lists files that are genuinely still stubs. Do not modify any code files — only update CLAUDE.md."
}'
