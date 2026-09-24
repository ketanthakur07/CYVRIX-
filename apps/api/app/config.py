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

    # V3.1 action proposals (proposal creation only — no execution exists)
    action_proposal_rate_limit_per_hour: int = 20

    # V3.2 approvals (authorization data only — still no execution)
    approval_rate_limit_per_hour: int = 30
    approval_ttl_minutes: int = 60
    step_up_max_age_minutes: int = 15

    # V3.3 execution authorization (the final deterministic gate — no execution)
    execution_authorization_rate_limit_per_hour: int = 30

    # V3.4 sandboxed execution (isolated local processing only — no Git/GitHub writes)
    executor_service_token: str = ""  # service identity for the internal executor API
    execution_admission_rate_limit_per_hour: int = 10

    # V3.7 operational controls (server-owned; clients can never raise them)
    ops_max_concurrent_executions: int = 5
    ops_max_concurrent_executions_per_repository: int = 2
    ops_max_execution_duration_seconds: int = 900
    ops_lease_ttl_seconds: int = 120
    ops_breaker_max_failures: int = 3
    ops_rate_limit_per_hour: int = 30
    ops_reconciliation_rate_limit_per_hour: int = 10

    # V3.8 audit integrity. The checkpoint MAC key is deliberately NOT a
    # database value: it lives in configuration (outside the attacker's
    # DB write reach). Empty disables checkpointing (chain stays
    # tamper-EVIDENT for content/link tampering; tail-truncation
    # anchoring is then documented as NOT available).
    audit_checkpoint_key: str = ""
    audit_alert_rate_limit_per_hour: int = 60

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

    @field_validator(
        "ops_max_concurrent_executions",
        "ops_max_concurrent_executions_per_repository",
        "ops_max_execution_duration_seconds",
        "ops_lease_ttl_seconds",
        "ops_breaker_max_failures",
        "ops_rate_limit_per_hour",
        "ops_reconciliation_rate_limit_per_hour",
        "audit_alert_rate_limit_per_hour",
    )
    @classmethod
    def validate_ops_limits_positive(cls, v: int, info) -> int:
        """V3.7: operational limits must be bounded positive integers.

        Fail closed at startup: there is no representation for
        'unlimited' — a non-positive or absurd value stops startup."""
        bounds = {
            "ops_max_concurrent_executions": (1, 10_000),
            "ops_max_concurrent_executions_per_repository": (1, 1_000),
            "ops_max_execution_duration_seconds": (1, 86_400),
            "ops_lease_ttl_seconds": (10, 3_600),
            "ops_breaker_max_failures": (1, 100),
            "ops_rate_limit_per_hour": (1, 1_000),
            "ops_reconciliation_rate_limit_per_hour": (1, 1_000),
            "audit_alert_rate_limit_per_hour": (1, 10_000),
        }
        low, high = bounds[info.field_name]
        if not isinstance(v, int) or v < low or v > high:
            raise ValueError(
                f"{info.field_name} must be between {low} and {high} "
                "(operational limits are bounded; unlimited is not supported)"
            )
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
