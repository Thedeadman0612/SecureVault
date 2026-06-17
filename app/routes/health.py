"""
app/routes/health.py

Liveness/readiness probe for orchestration (Docker HEALTHCHECK, load balancer,
systemd). Exempt from AuthGuard — see app/middleware/auth_guard.py.

Checks DB connectivity rather than returning a bare 200, since the most
common real failure mode in this app's single-process deployment is the
SQLite file being unreachable (bad volume mount, permissions) while the
ASGI server itself is still up and would otherwise look healthy.
"""

import logging

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/health", response_model=None)
async def health(response: Response, db: Session = Depends(get_db)) -> dict[str, str]:
    """Report liveness and database connectivity.

    Returns:
        ``{"status": "ok"}`` with HTTP 200 when the database responds.
        ``{"status": "unavailable"}`` with HTTP 503 if the query fails — the
        database connection is unreachable.
    """
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        logger.warning("Health check failed: database query did not succeed.")
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "unavailable"}

    return {"status": "ok"}
