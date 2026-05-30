---
description: Run tests then commit if passing. Usage: /safe-commit "commit message"
---

Before committing, run this safety check:

Step 1 — Run tests:

```bash
pytest app/tests/ -v
```

If ANY test fails:
→ Stop immediately
→ Show which tests failed
→ Do NOT commit
→ Ask user to fix failures first

If ALL tests pass:
→ Show git status
→ Show git diff --stat
→ Ask user to confirm staged files are correct
→ Then run:

```bash
git add .
git commit -m "$ARGUMENTS"
```

Step 3 — After commit:
→ Show git log --oneline -5
→ Confirm commit was successful
