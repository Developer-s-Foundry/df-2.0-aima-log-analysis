"""Application configuration management."""

from typing import List, Optional
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application Settings
    app_name: str = Field(default="log-analysis-service", description="Application name")
    app_version: str = Field(default="1.0.0", description="Application version")
    environment: str = Field(default="development", description="Environment (dev/staging/prod)")
    debug: bool = Field(default=False, description="Debug mode")
    log_level: str = Field(default="INFO", description="Logging level")

    # Server Configuration
    host: str = Field(default="0.0.0.0", description="Server host")
    port: int = Field(default=8000, ge=1, le=65535, description="Server port")
    workers: int = Field(default=4, ge=1, description="Number of workers")

    # Database Configuration
    database_url: str = Field(
        default="postgresql+asyncpg://postgres:password@localhost:5432/log_analysis_db",
        description="Database connection URL",
    )
    database_pool_size: int = Field(default=20, ge=1, description="Database pool size")
    database_max_overflow: int = Field(default=10, ge=0, description="Max overflow connections")
    database_pool_timeout: int = Field(default=30, ge=1, description="Pool timeout in seconds")
    database_pool_recycle: int = Field(
        default=3600, ge=1, description="Pool recycle time in seconds"
    )

    # RabbitMQ Configuration
    rabbitmq_host: str = Field(default="localhost", description="RabbitMQ host")
    rabbitmq_port: int = Field(default=5672, ge=1, le=65535, description="RabbitMQ port")
    rabbitmq_user: str = Field(default="guest", description="RabbitMQ username")
    rabbitmq_password: str = Field(default="guest", description="RabbitMQ password")
    rabbitmq_vhost: str = Field(default="/", description="RabbitMQ virtual host")
    rabbitmq_prefetch_count: int = Field(
        default=10, ge=1, description="RabbitMQ prefetch count"
    )
    rabbitmq_reconnect_delay: int = Field(
        default=5, ge=1, description="RabbitMQ reconnect delay in seconds"
    )

    # Queue Names
    log_analysis_queue: str = Field(
        default="log_analysis_queue", description="Input queue for logs"
    )
    recommendation_queue: str = Field(
        default="recommendation_queue", description="Output queue for recommendations"
    )
    alerts_queue: str = Field(default="alerts_queue", description="Output queue for alerts")

    # JWT Authentication
    jwt_secret_key: str = Field(
        default="your-super-secret-jwt-key-change-this-in-production",
        description="JWT secret key",
    )
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_expiration_minutes: int = Field(
        default=60, ge=1, description="JWT expiration in minutes"
    )
    api_gateway_public_key: Optional[str] = Field(
        default=None, description="API Gateway public key for JWT verification"
    )

    # Processing Configuration
    batch_size: int = Field(default=100, ge=1, description="Batch processing size")
    processing_interval_seconds: int = Field(
        default=5, ge=1, description="Processing interval in seconds"
    )
    max_concurrent_batches: int = Field(
        default=5, ge=1, description="Maximum concurrent processing batches"
    )

    # Anomaly Detection Thresholds
    error_rate_threshold: float = Field(
        default=10.0, ge=0, description="Error rate threshold percentage"
    )
    anomaly_score_threshold: float = Field(
        default=0.85, ge=0, le=1, description="Anomaly detection score threshold"
    )
    min_pattern_frequency: int = Field(
        default=5, ge=1, description="Minimum pattern frequency for detection"
    )

    # Metrics & Monitoring
    prometheus_port: int = Field(
        default=9090, ge=1, le=65535, description="Prometheus metrics port"
    )
    enable_metrics: bool = Field(default=True, description="Enable metrics collection")
    metrics_path: str = Field(default="/metrics", description="Metrics endpoint path")

    # Rate Limiting
    rate_limit_enabled: bool = Field(default=True, description="Enable rate limiting")
    rate_limit_requests: int = Field(
        default=100, ge=1, description="Rate limit requests per period"
    )
    rate_limit_period: int = Field(
        default=60, ge=1, description="Rate limit period in seconds"
    )

    # CORS Settings
    cors_enabled: bool = Field(default=True, description="Enable CORS")
    cors_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8080"],
        description="Allowed CORS origins",
    )
    cors_methods: List[str] = Field(
        default=["GET", "POST", "PUT", "DELETE", "OPTIONS"], description="Allowed CORS methods"
    )
    cors_headers: List[str] = Field(default=["*"], description="Allowed CORS headers")

    # Security
    allowed_hosts: List[str] = Field(
        default=["localhost", "127.0.0.1"], description="Allowed hosts"
    )
    trusted_proxies: List[str] = Field(default=[], description="Trusted proxy addresses")

    # Retry Configuration
    max_retry_attempts: int = Field(default=3, ge=1, description="Maximum retry attempts")
    retry_backoff_factor: int = Field(default=2, ge=1, description="Retry backoff factor")
    retry_max_delay_seconds: int = Field(
        default=60, ge=1, description="Maximum retry delay in seconds"
    )

    # Feature Flags
    enable_real_time_processing: bool = Field(
        default=True, description="Enable real-time log processing"
    )
    enable_pattern_clustering: bool = Field(
        default=True, description="Enable pattern clustering"
    )
    enable_ml_anomaly_detection: bool = Field(
        default=True, description="Enable ML-based anomaly detection"
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        allowed_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed_levels:
            raise ValueError(f"Log level must be one of {allowed_levels}")
        return v.upper()

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        """Validate environment."""
        allowed_envs = ["development", "staging", "production"]
        if v.lower() not in allowed_envs:
            raise ValueError(f"Environment must be one of {allowed_envs}")
        return v.lower()

    @property
    def rabbitmq_url(self) -> str:
        """Construct RabbitMQ connection URL."""
        return (
            f"amqp://{self.rabbitmq_user}:{self.rabbitmq_password}@"
            f"{self.rabbitmq_host}:{self.rabbitmq_port}{self.rabbitmq_vhost}"
        )

    @property
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        """Check if running in development."""
        return self.environment == "development"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
