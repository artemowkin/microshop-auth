from typing import Literal
from pathlib import Path

from pydantic import BaseSettings


BASE_DIR = Path(__file__).parent


class Settings(BaseSettings):
    secret_key: str
    environment: Literal['dev', 'prod'] = 'dev'
    database_url: str
    redis_url: str
    access_token_expire_seconds: int = 30 * 60 # 30 minutes
    refresh_token_expire_seconds: int = 30 * 24 * 60 * 60 # 30 days

    class Config:
        env_file = BASE_DIR.parent / '.env'


settings = Settings()
