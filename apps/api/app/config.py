from pydantic_settings import BaseSettings
from pydantic import field_validator
from functools import lru_cache


class Settings(BaseSettings):
    # Database
    database_url: str = "postgresql+asyncpg://cyvrix:cyvrix_dev@localhost:5432/cyvrix"
    database_url_sync: str = "postgresql://cyvrix:cyvrix_dev@localhost:5432/cyvrix"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # GitHub App
    github_app_id: str = ""
    github_app_private_key: str = ""
    github_webhook_secret: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""

    # LLM
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"

    # App
    app_url: str = "http://localhost:3000"
    api_url: str = "http://localhost:8000"
    cors_origins: str = "http://localhost:3000"
    environment: str = "development"
    debug: bool = False

    # Authentication / Session
    secret_key: str = ""
    session_ttl_seconds: int = 86400  # 24 hours
    session_cookie_name: str = "cyvrix_session"
    cookie_secure: bool = False  # Must be True in production HTTPS
    cookie_same_site: str = "lax"

    # Rate limiting
    auth_rate_limit_per_minute: int = 30
    scan_rate_limit_per_hour: int = 10

    # Scan limits
    max_repo_size_mb: int = 500
    scan_timeout_minutes: int = 10
    max_deps_per_batch: int = 1000
    max_deps_total: int = 10000
    max_manifests: int = 50
    max_file_size_mb: int = 10
    max_manifest_lines: int = 50000
    max_llm_calls_per_scan: int = 20
    investigate_severities: list[str] = ["HIGH", "CRITICAL"]

    # Investigation limits
    investigation_max_files_searched: int = 20
    investigation_max_files_read: int = 3
    investigation_max_lines_per_file: int = 200
    investigation_max_content_per_file: int = 8000
    investigation_max_prompt_bytes: int = 32000
    investigation_max_output_tokens: int = 1000
    investigation_max_retries: int = 1
    investigation_connect_timeout: float = 10.0
    investigation_read_timeout: float = 60.0

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    @field_validator("cookie_secure")
    @classmethod
    def validate_cookie_secure(cls, v: bool, info) -> bool:
        env = info.data.get("environment", "development")
        if env == "production" and v is not True:
            raise ValueError(
                "COOKIE_SECURE must be true in production (HTTPS required). "
                "Set COOKIE_SECURE=true in your environment."
            )
        return v

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
                    "SECRET_KEY must not be a known development default in production. "
                    "Generate a strong random secret."
                )
            if len(v) < 32:
                raise ValueError("SECRET_KEY must be at least 32 characters in production.")
        return v

    @field_validator("debug")
    @classmethod
    def validate_debug(cls, v: bool, info) -> bool:
        env = info.data.get("environment", "development")
        if env == "production" and v is True:
            raise ValueError(
                "DEBUG must be false in production. "
                "Set DEBUG=false in your environment."
            )
        return v

    @property
    def cors_origin_list(self) -> list[str]:
        """Parse comma-separated CORS_ORIGINS into a list."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
