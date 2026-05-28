---
description: Create and apply Alembic migration. Usage: /migrate "description"
---

Run Alembic migration with description from $ARGUMENTS:

Step 1 — Generate migration:
```bash
alembic revision --autogenerate -m "$ARGUMENTS"
```

Step 2 — Show the generated file contents

Step 3 — Ask user to confirm before applying

Step 4 — If confirmed, apply:
```bash
alembic upgrade head
```

Step 5 — Verify with SQLite MCP that schema updated correctly