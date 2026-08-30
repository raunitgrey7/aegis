"""Central configuration. Everything is overridable via environment variables prefixed AEGIS_."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_DIR = Path(__file__).resolve().parent
BACKEND_DIR = PACKAGE_DIR.parent
REPO_DIR = BACKEND_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env", extra="ignore")

    # --- runtime ---
    env: str = "development"
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: list[str] = ["http://localhost:3000"]

    # --- persistence ---
    database_url: str = f"sqlite:///{(BACKEND_DIR / 'aegis.db').as_posix()}"
    redis_url: str | None = None  # e.g. redis://localhost:6379/0 ; None -> in-memory bus
    event_stream: str = "aegis:events"
    consumer_group: str = "aegis-detectors"

    # --- security ---
    jwt_secret: str = Field(default="change-me-in-production-please-32-bytes-min")
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 480
    ingest_api_key: str = "aegis-dev-ingest-key"
    admin_username: str = "admin"
    admin_password: str = "admin"
    max_request_bytes: int = 2 * 1024 * 1024
    max_events_per_batch: int = 5000
    rate_limit_per_minute: int = 600
    default_tenant: str = "default"

    # --- detection ---
    rules_dir: Path = PACKAGE_DIR / "rules"
    threat_intel_dir: Path = PACKAGE_DIR / "data" / "threat_intel"
    mitre_catalog: Path = PACKAGE_DIR / "data" / "mitre" / "techniques.yaml"
    correlation_window_seconds: int = 3600
    incident_min_score: float = 40.0

    # --- AI ---
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"
    embedding_model: str = "nomic-embed-text"
    llm_timeout_seconds: float = 90.0
    llm_enabled: bool = True

    # --- observability ---
    otel_enabled: bool = False
    otel_endpoint: str = "http://localhost:4317"


@lru_cache
def get_settings() -> Settings:
    return Settings()
