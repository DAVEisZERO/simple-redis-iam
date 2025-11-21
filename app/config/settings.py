from typing import List, Any
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr


"""
################################################################################
###                                   DOCS                                   ###
################################################################################

Settings Configuration Module
------------------
Centralized configuration management using Pydantic Settings. Loads environment
variables from .env file with type validation and secure secret handling.
Supports both SECURE and INSECURE operation modes for development/testing.

"""

THIS_DIR = Path(__file__).resolve().parent
ENV_PATH = THIS_DIR.parent.parent / ".env"

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ENV_PATH , env_file_encoding="utf-8", extra="ignore")
    
    redis_password: SecretStr
    redis_username: str
    redis_host: str
    redis_port: int

    smtp_server: str
    smtp_port: int
    smtp_username: str
    smtp_password: SecretStr

    otp_expire_minutes: int
    otp_length: int

    opaque_token_length: int

    security_mode: str = "SECURE"  # or "INSECURE"
    allowed_origins: List[str] = []
    redirect_url: str

SETTINGS = Settings()