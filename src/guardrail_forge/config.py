from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GUARDRAIL_", env_file=".env", extra="ignore")

    api_key: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()

