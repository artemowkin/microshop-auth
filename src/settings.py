from typing import Literal
from pathlib import Path

from pydantic import BaseSettings


BASE_DIR = Path(__file__).parent


class Settings(BaseSettings):
    secret_key: str
    environment: Literal['dev', 'prod'] = 'dev'
    database_url: str

    class Config:
        env_file = BASE_DIR.parent / '.env'


settings = Settings()

print(settings.database_url)
