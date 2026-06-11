# Import all models so Alembic autogenerate can see every table in metadata.
from app.models.recovery_code import RecoveryCode as RecoveryCode  # noqa: F401
from app.models.user import User as User  # noqa: F401
from app.models.vault_entry import VaultEntry as VaultEntry  # noqa: F401
