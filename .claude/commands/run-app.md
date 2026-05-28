---
description: Start the SecureVault development server. Usage: /run-app
---

Run the FastAPI development server with:

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Before starting:
1. Verify virtual environment is activated (venv)
2. Verify securevault.db exists — if not, run: alembic upgrade head
3. Verify .env file exists — if not, tell the user to create it from .env.example

After starting, tell the user:
- App is running at: http://localhost:8000
- API docs disabled (production mode)
- Press Ctrl+C to stop