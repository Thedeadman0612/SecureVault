"""
app/tests/test_health.py

Tests for the GET /health liveness/readiness probe (app/routes/health.py).

What we test
-------------
1. The endpoint is reachable without a session (exempt from AuthGuard).
2. It returns 200 + {"status": "ok"} when the database responds.
3. It returns 503 + {"status": "unavailable"} when the database is broken.
4. It does not require a CSRF token (GET is a safe method).
"""

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.session import get_db
from app.main import app
from app.models.user import Base

_TEST_DB_URL = "sqlite://"  # in-memory SQLite


@pytest.fixture(scope="module")
def test_engine():
    engine = create_engine(
        _TEST_DB_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="module")
def client(test_engine) -> Generator[TestClient, None, None]:
    """TestClient with an in-memory DB and the full middleware stack."""
    TestingSessionLocal = sessionmaker(
        autocommit=False, autoflush=False, bind=test_engine
    )

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


class TestHealthEndpoint:
    def test_health_returns_200_without_session(self, client: TestClient):
        """No cookies are set — confirms /health is exempt from AuthGuard."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_reports_ok_status(self, client: TestClient):
        response = client.get("/health")
        assert response.json() == {"status": "ok"}

    def test_health_does_not_require_csrf_token(self, client: TestClient):
        """GET is a safe method — CSRFMiddleware never checks GET requests."""
        response = client.get("/health")
        assert response.status_code != 403

    def test_health_returns_503_when_db_query_fails(self, client: TestClient, test_engine):
        """A session that connects but fails on query execution → 503, not 200.

        This simulates the realistic failure mode (DB file unreachable,
        locked, or corrupted) as opposed to a dependency-resolution failure,
        which FastAPI would surface as an unhandled 500 before the route body
        — and the route's own try/except — ever runs.
        """

        class _BrokenSession:
            def execute(self, *_args, **_kwargs):
                raise RuntimeError("simulated database outage")

            def close(self) -> None:
                pass  # no-op: nothing to clean up on a fake session

        def broken_get_db():
            yield _BrokenSession()

        app.dependency_overrides[get_db] = broken_get_db
        try:
            response = client.get("/health")
        finally:
            # Restore the working override for subsequent tests in this module.
            TestingSessionLocal = sessionmaker(
                autocommit=False, autoflush=False, bind=test_engine
            )

            def override_get_db():
                db = TestingSessionLocal()
                try:
                    yield db
                finally:
                    db.close()

            app.dependency_overrides[get_db] = override_get_db

        assert response.status_code == 503
        assert response.json() == {"status": "unavailable"}
