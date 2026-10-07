"""Configuration settings for AutoSecTwin.
Follows 12-factor principles, using environment variables with safe defaults.
"""
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    PROJECT_NAME: str = "VulnTwin AI"
    TAGLINE: str = "Detect. Validate. Remediate. Secure."
    VERSION: str = "3.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Environment
    ENV: str = Field(default="development", description="development, staging, or production")
    DEBUG: bool = True
    
    # Database
    DATABASE_URL: str = "sqlite:///./autosectwin.db"
    
    # Risk Scoring Thresholds
    RISK_THRESHOLD_LOW: int = 24
    RISK_THRESHOLD_GUARDED: int = 49
    RISK_THRESHOLD_SUSPICIOUS: int = 74
    # 75-100 is HIGH
    
    # SSRF Protection
    BLOCKED_IP_NETWORKS: List[str] = [
        "127.0.0.0/8",       # Loopback
        "10.0.0.0/8",        # Private Class A
        "172.16.0.0/12",     # Private Class B
        "192.168.0.0/16",    # Private Class C
        "169.254.0.0/16",    # Link-local & cloud metadata
        "0.0.0.0/8",         # Current network
        "::1/128",           # IPv6 loopback
        "fc00::/7",          # IPv6 unique local
        "fe80::/10",         # IPv6 link-local
    ]
    
    # Threat Intelligence Adapters
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    URLSCAN_API_KEY: str = ""
    
    # AI Explanation Settings
    OPENAI_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    AI_ENABLED: bool = False  # Deterministic rule explanation used if AI keys not provided
    
    # Timeouts & Limits (milliseconds or seconds)
    HTTP_TIMEOUT_SECONDS: float = 6.0
    MAX_URL_LENGTH: int = 2048
    MAX_RESPONSE_BYTES: int = 512 * 1024  # 512 KB
    
    # Freshness Thresholds (seconds)
    FRESHNESS_FRESH_SECONDS: int = 3600        # < 1 hour
    FRESHNESS_RECENT_SECONDS: int = 86400      # 1-24 hours
    # > 24 hours = STALE
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
