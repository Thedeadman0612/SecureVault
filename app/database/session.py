from collections.abc import Generator
from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.config.settings import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},
)


# ---------------------------------------------------------------------------
# SQLite WAL mode
# ---------------------------------------------------------------------------
# Enable Write-Ahead Logging on every new SQLite connection.
#
# WHY WAL?
#   The default SQLite journal mode (DELETE / rollback journal) uses exclusive
#   write locks — a writer blocks ALL readers for the duration of the
#   transaction, and a reader blocks writers.  Under uvicorn with multiple
#   concurrent requests this causes unnecessary contention even for a
#   single-user vault.
#
# WAL behaviour:
#   • Readers never block writers and writers never block readers.
#   • Multiple simultaneous readers are allowed without any locking.
#   • Only one writer at a time (SQLite's fundamental limit), but writes no
#     longer starve concurrent reads.
#   • WAL files are automatically checkpointed back into the main DB file;
#     no manual maintenance is required.
#   • The journal_mode pragma is connection-scoped, so it must be applied on
#     every new connection via a SQLAlchemy engine event.
#
# SYNCHRONOUS = NORMAL:
#   Paired with WAL, PRAGMA synchronous=NORMAL provides a good durability /
#   performance trade-off — SQLite only syncs at WAL checkpoints rather than
#   on every write, which is safe because WAL itself is crash-consistent.
#
# This is a one-time, connection-level configuration change that requires no
# schema migration and is fully backwards-compatible with existing databases.


@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_connection: Any, _connection_record: Any) -> None:
    """Apply WAL mode and NORMAL sync on every new SQLite connection."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_db() -> Generator[Session, None, None]:
    """Yield a SQLAlchemy session and guarantee cleanup on every exit path.

    On a normal request the caller commits before returning; the session is
    then closed in the finally block.  On any exception the session is rolled
    back before closing — prevents a dirty, half-written transaction from
    being returned to the connection pool where it could corrupt the next
    request.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
