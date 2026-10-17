"""Application configuration using Pydantic Settings."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration settings for VulnTwin AI backend application."""

    APP_NAME: str = "VulnTwin AI"
    API_VERSION: str = "v1"
    API_V1_STR: str = "/api/v1"
    DEBUG: bool = False
    DATABASE_URL: str = "sqlite:///./vulntwin.db"

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=".env",
        extra="ignore",
    )


settings: Settings = Settings()
