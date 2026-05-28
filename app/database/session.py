from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config.settings import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_db():
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
