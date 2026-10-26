import os
from pydantic import BaseModel
from typing import List

class Settings(BaseModel):
    PROJECT_NAME: str = "Vuln TWin"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = os.getenv("VULN_TWIN_SECRET_KEY", "vuln-twin-super-secure-production-secret-key-32bytes-min")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./vuln_twin.db")
    
    # NVD API (Optional)
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
    NVD_API_TIMEOUT: int = int(os.getenv("NVD_API_TIMEOUT", "10"))
    
    # Security & CORS
    CORS_ORIGINS: List[str] = [
        "*",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://192.168.1.103:5173",
        "http://192.168.1.102:5173",
    ]
    
    # Lab Environment Settings
    TWIN_PROVIDER: str = os.getenv("TWIN_PROVIDER", "mock_isolated")
    TWIN_ISOLATION_NETWORK: str = "192.168.100.0/24-isolated-lab"
    MAX_VALIDATION_TIMEOUT_SECONDS: int = 45

settings = Settings()
