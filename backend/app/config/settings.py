"""Application settings and configuration management."""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Platform configuration loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_env: Literal["development", "staging", "production", "test"] = "development"
    app_name: str = "Multi-Agent Cyber AI"
    app_version: str = "0.1.0"
    debug: bool = True
    secret_key: str = "change-this-in-production-secret-key-32-chars-min"
    api_prefix: str = "/api"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 1
    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]

    # PostgreSQL Database
    postgres_user: str = "cyber_user"
    postgres_password: str = "cyber_password"
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "cyber_security_db"
    database_url: str = (
        "postgresql+asyncpg://cyber_user:cyber_password@localhost:5432/cyber_security_db"
    )
    db_echo: bool = False
    db_pool_size: int = 20
    db_max_overflow: int = 10
    db_pool_recycle: int = 1800
    db_connect_timeout: float = 5.0
    db_max_retries: int = 3
    db_retry_delay_sec: float = 1.0

    # Redis Cache & Ephemeral State
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str | None = None
    redis_db: int = 0
    redis_url: str = "redis://localhost:6379/0"
    redis_timeout_sec: float = 2.0
    redis_max_connections: int = 50
    redis_retry_on_timeout: bool = True
    stream_maxlen: int = 100000

    # Message Broker (Kafka / Redpanda)
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_client_id: str = "cyber-ai-backend"
    kafka_retries: int = 5
    kafka_retry_backoff_ms: int = 300
    kafka_request_timeout_ms: int = 5000
    kafka_max_block_ms: int = 4000
    kafka_enable_auto_commit: bool = False
    kafka_auto_offset_reset: Literal["earliest", "latest"] = "latest"

    # Google Gemini AI
    gemini_api_key: str | None = None
    gemini_model_reasoning: str = "gemini-1.5-pro"
    gemini_model_fast: str = "gemini-1.5-flash"
    gemini_temperature: float = 0.1
    gemini_max_output_tokens: int = 4096

    # Threat Intelligence & Vector Store
    faiss_index_path: str = "data/indexes/mitre_attack_faiss"
    embedding_model_name: str = "all-MiniLM-L6-v2"
    misp_url: str | None = None
    misp_api_key: str | None = None
    virustotal_api_key: str | None = None
    alienvault_otx_key: str | None = None

    # Detection & Agents
    event_batch_size: int = 100
    correlation_time_window_sec: int = 300
    max_agent_concurrency: int = 12
    anomaly_zscore_threshold: float = 3.0

    # Network Scanning Boundary Constraints (Strict RFC1918 + Loopback)
    allowed_scan_ranges: list[str] = Field(
        default_factory=lambda: [
            "127.0.0.1/32",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]
    )

    # Observability
    log_level: str = "INFO"
    log_format: Literal["json", "console"] = "json"
    prometheus_metrics_enabled: bool = True
    prometheus_port: int = 9090


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings singleton instance."""
    return Settings()
