---
description: Run the test suite. Usage: /run-tests [optional-file]
---

Run pytest with:

If $ARGUMENTS is empty:
```bash
pytest app/tests/ -v
```

If $ARGUMENTS is provided:
```bash
pytest $ARGUMENTS -v
```

Report:
- Number of tests passed/failed
- Any failing test names
- Suggest fixes for failures