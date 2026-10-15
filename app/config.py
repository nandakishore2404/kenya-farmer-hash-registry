import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "Farmer Hash Registry"
    ENV: str = os.getenv("ENV", "development")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./registry.db")
    SERVER_KEY: str = os.getenv("SERVER_KEY", "prod_server_secret_rekey_key_9876543210")
    ADMIN_KEY: str = os.getenv("ADMIN_KEY", "admin_secret_management_key_xyz")
    SUPPRESSION_THRESHOLD: int = 5  # Privacy k-anonymity rule: suppress counts < 5

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
