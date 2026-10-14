from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GUARDRAIL_", env_file=".env", extra="ignore")

    api_key: str | None = None
    max_request_bytes: int = Field(default=250_000, ge=1_024, le=10_000_000)


@lru_cache
def get_settings() -> Settings:
    return Settings()

