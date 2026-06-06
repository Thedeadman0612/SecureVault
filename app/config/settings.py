from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    SECRET_KEY: str
    DATABASE_URL: str = "sqlite:///./securevault.db"

    # Controls environment-specific security behaviour (e.g. https_only on the
    # session cookie).  Accepted values: "development" | "production".
    # Default is "production" — fail-secure: forgetting to set this variable
    # gives you production-grade cookie security, not relaxed dev settings.
    # Set ENVIRONMENT=development in your .env file for local development only.
    ENVIRONMENT: str = "production"

    # Idle session timeout.  Reduced from 30 → 10 minutes in Phase 2 per
    # OWASP Session Management Cheat Sheet §Session Expiration.
    SESSION_TIMEOUT_MINUTES: int = 10

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
