"""
Central configuration — reads from environment variables.
All secrets live in .env, never in source code.
"""

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # ── Database ───────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://asm:asm@localhost:5432/asm"

    # ── Redis ──────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── API Keys (optional — demo mode if absent) ──────────────
    shodan_api_key:     str = ""
    censys_api_id:      str = ""
    censys_api_secret:  str = ""
    github_token:       str = ""  # raises GitHub rate limit from 10 to 30 req/min

    # ── App ────────────────────────────────────────────────────
    debug:           bool = False
    report_dir:      str  = "/app/reports"
    max_concurrent_scans: int = 5

    # ── Cache TTL overrides (hours) ────────────────────────────
    cache_ttl_dns:    int = 6
    cache_ttl_shodan: int = 12
    cache_ttl_github: int = 1

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    return Settings()