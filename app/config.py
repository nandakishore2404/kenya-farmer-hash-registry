import os
from typing import Optional
from pydantic_settings import BaseSettings

COMMITTED_INSECURE_KEYS = {
    "prod_server_secret_rekey_key_9876543210",
    "admin_secret_management_key_xyz",
    "postgres_secret_password",
    "test_server_secret_rekey_key_abc123",
    "test_admin_key_super_secret"
}

class Settings(BaseSettings):
    APP_NAME: str = "Farmer Hash Registry"
    ENV: str = os.getenv("ENV", "development")
    DATABASE_URL: Optional[str] = os.getenv("DATABASE_URL", None)
    SERVER_KEY: Optional[str] = os.getenv("SERVER_KEY", None)
    ADMIN_KEY: Optional[str] = os.getenv("ADMIN_KEY", None)
    PILOT_START_DATE: str = os.getenv("PILOT_START_DATE", "2026-10-01")
    SUPPRESSION_THRESHOLD: int = 5  # Privacy k-anonymity rule: suppress counts < 5
    DASHBOARD_USER: str = os.getenv("DASHBOARD_USER", "admin")
    DASHBOARD_PASSWORD: Optional[str] = os.getenv("DASHBOARD_PASSWORD", None)
    SEED_TEST_PARTNERS: bool = os.getenv("SEED_TEST_PARTNERS", "false").lower() in ("true", "1", "yes")

    class Config:
        env_file = ".env"
        extra = "ignore"

    def validate_production_security(self):
        """
        Enforce strict validation when ENV is not 'development'.
        Refuses startup if keys are missing, shorter than 32 characters, or equal to known committed test strings.
        """
        if self.ENV != "development":
            if not self.SERVER_KEY:
                raise ValueError("Production configuration error: SERVER_KEY is required and cannot be empty.")
            if len(self.SERVER_KEY.strip()) < 32:
                raise ValueError("Production configuration error: SERVER_KEY must be at least 32 characters long.")
            if self.SERVER_KEY.strip() in COMMITTED_INSECURE_KEYS:
                raise ValueError("Production configuration error: SERVER_KEY matches a known insecure committed placeholder.")

            if not self.ADMIN_KEY:
                raise ValueError("Production configuration error: ADMIN_KEY is required and cannot be empty.")
            if len(self.ADMIN_KEY.strip()) < 32:
                raise ValueError("Production configuration error: ADMIN_KEY must be at least 32 characters long.")
            if self.ADMIN_KEY.strip() in COMMITTED_INSECURE_KEYS:
                raise ValueError("Production configuration error: ADMIN_KEY matches a known insecure committed placeholder.")

            if not self.DATABASE_URL:
                raise ValueError("Production configuration error: DATABASE_URL is required.")

            if not self.DASHBOARD_PASSWORD:
                raise ValueError("Production configuration error: DASHBOARD_PASSWORD is required in production.")

        # In development, provide safe fallbacks if not explicitly provided
        if not self.SERVER_KEY:
            self.SERVER_KEY = "dev_server_rekey_key_default_32_bytes_long!!"
        if not self.ADMIN_KEY:
            self.ADMIN_KEY = "dev_admin_key_default_32_bytes_long_xyz!!"
        if not self.DATABASE_URL:
            self.DATABASE_URL = "sqlite:///./registry.db"
        if not self.DASHBOARD_PASSWORD:
            self.DASHBOARD_PASSWORD = "dev_dashboard_password"

settings = Settings()
settings.validate_production_security()
