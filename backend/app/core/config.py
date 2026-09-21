from pydantic_settings import BaseSettings
from typing import List
import os

class Settings(BaseSettings):
    PROJECT_NAME: str = "CyberShield Scan"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    
    # Environment & Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "cybershield-scan-super-secret-production-key-change-in-prod-2026")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 # 24 hours
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./cybershield.db")
    
    # CORS
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://127.0.0.1:3000", "*"]
    
    # Scanner safe concurrency defaults
    DEFAULT_CONCURRENCY_LIMIT: int = 100
    DEFAULT_TIMEOUT_SECONDS: float = 1.5
    
    class Config:
        case_sensitive = True

settings = Settings()
