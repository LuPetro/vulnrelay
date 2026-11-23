from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNRELAY_", extra="ignore", env_file=".env")

    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    database_url: str = "sqlite:///./data/vulnrelay.db"
    sync_interval_minutes: int = Field(default=30, ge=1)
    log_level: str = "INFO"
    nvd_api_key: SecretStr = SecretStr("")
    api_token: SecretStr = SecretStr("")
    ui_dir: str = "./frontend/dist"
    opencve_enabled: bool = False
    opencve_batch_size: int = Field(default=25, ge=1, le=100)
    ai_base_url: str = ""
    ai_allow_private_hosts: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
