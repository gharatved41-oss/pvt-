"""Application configuration using Pydantic Settings."""

from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration settings for VulnTwin AI backend application."""

    APP_NAME: str = "VulnTwin AI"
    API_VERSION: str = "v1"
    API_V1_STR: str = "/api/v1"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"  # "development", "test", or "production"
    DATABASE_URL: str = "sqlite:///./vulntwin.db"

    # Threat Intelligence Provider Settings
    THREAT_INTEL_PROVIDER: str = "mock"  # "mock" or "virustotal"
    VT_API_KEY: Optional[str] = None
    THREAT_INTEL_TIMEOUT_SECONDS: float = 4.0
    THREAT_INTEL_WARN_EXTERNAL: bool = True

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=".env",
        extra="ignore",
    )


settings: Settings = Settings()
