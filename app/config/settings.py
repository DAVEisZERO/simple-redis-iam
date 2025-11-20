from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path
from pydantic import SecretStr

THIS_DIR = Path(__file__).resolve().parent
ENV_PATH = THIS_DIR.parent.parent / ".env"

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ENV_PATH , env_file_encoding="utf-8", extra="ignore")
    
    redis_password: SecretStr
    redis_username: str
    redis_host: str
    redis_port: int

    security_mode: str = "SECURE"  # or "INSECURE"
    allowed_origins: list[str] 

SETTINGS = Settings()