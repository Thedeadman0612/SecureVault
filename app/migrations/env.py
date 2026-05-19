from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.config.settings import settings
from app.database.base import Base

# Import all models so Alembic can detect them in Base.metadata
import app.models.user  # noqa: F401
import app.models.vault_entry  # noqa: F401

config = context.config

# Wire up Python logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Override the placeholder sqlalchemy.url with the value from .env
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Generate SQL scripts without a live DB connection (used for review/preview)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply migrations against a live DB connection (the normal path)."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
