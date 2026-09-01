from pydantic_settings import BaseSettings
from pydantic import field_validator
from functools import lru_cache


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://cyvrix:cyvrix_dev@localhost:5432/cyvrix"
    redis_url: str = "redis://localhost:6379/0"
    github_app_id: str = ""
    github_app_private_key: str = ""
    github_clone_url_base: str = "https://github.com"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    max_repo_size_mb: int = 500
    scan_timeout_minutes: int = 10
    max_deps_per_batch: int = 1000
    max_llm_calls_per_scan: int = 20
    investigate_severities: list[str] = ["HIGH", "CRITICAL"]
    environment: str = "development"
    secret_key: str = ""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str, info) -> str:
        env = info.data.get("environment", "development")
        if env == "production":
            if not v:
                raise ValueError(
                    "SECRET_KEY is required in production. "
                    "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
                )
            if v in ("", "dev-secret-key-change-in-production", "changeme"):
                raise ValueError(
                    "SECRET_KEY must not be a known development default in production."
                )
            if len(v) < 32:
                raise ValueError("SECRET_KEY must be at least 32 characters in production.")
        return v

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, v: str, info) -> str:
        env = info.data.get("environment", "development")
        if env == "production":
            if "cyvrix_dev" in v:
                raise ValueError("DATABASE_URL contains development credentials. Not allowed in production.")
            if not v.startswith("postgresql"):
                raise ValueError("DATABASE_URL must use PostgreSQL in production.")
        return v

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
