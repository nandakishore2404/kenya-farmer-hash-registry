import os
from typing import Optional
from pydantic_settings import BaseSettings

COMMITTED_INSECURE_KEYS = {
    # Legacy committed keys from previous audit
    "prod_server_secret_rekey_key_9876543210",
    "admin_secret_management_key_xyz",
    "postgres_secret_password",
    "test_server_secret_rekey_key_abc123",
    "test_admin_key_super_secret",
    # Development fallbacks in config.py
    "dev_server_rekey_key_default_32_bytes_long!!",
    "dev_admin_key_default_32_bytes_long_xyz!!",
    "dev_dashboard_password",
    # Placeholders from .env.example
    "test_server_secret_rekey_key_abc1234567890",
    "test_admin_key_super_secret_management_xyz",
    "change_me_in_production",
    "change_this_dashboard_password_in_prod",
    # Shared test keys
    "partner_shared_pilot_secret",
    "test_partner_a_api_key_2026",
    "test_partner_b_api_key_2026",
    "test_partner_c_api_key_2026",
    "alpha_api_key_pilot_2026",
    "beta_api_key_pilot_2026",
    "gamma_api_key_pilot_2026",
}

class Settings(BaseSettings):
    APP_NAME: str = "Farmer Hash Registry"
    ENV: str = "production"
    DATABASE_URL: Optional[str] = None
    SERVER_KEY: Optional[str] = None
    ADMIN_KEY: Optional[str] = None
    PILOT_START_DATE: str = "2026-10-01"
    SUPPRESSION_THRESHOLD: int = 5  # Privacy k-anonymity rule: suppress counts < 5
    DASHBOARD_USER: str = "admin"
    DASHBOARD_PASSWORD: Optional[str] = None
    SEED_TEST_PARTNERS: bool = False

    class Config:
        env_file = ".env"
        extra = "ignore"

    def validate_production_security(self):
        """
        Enforce strict validation when ENV is not 'development'.
        Refuses startup if keys are missing, shorter than 32 characters, contain CHANGE_ME,
        match known committed placeholders, use SQLite, or enable test partner seeding.
        """
        if self.ENV != "development":
            # 1. SERVER_KEY
            if not self.SERVER_KEY:
                raise ValueError("Production configuration error: SERVER_KEY is required and cannot be empty.")
            server_key_clean = self.SERVER_KEY.strip()
            if "CHANGE_ME" in server_key_clean:
                raise ValueError("Production configuration error: SERVER_KEY contains placeholder 'CHANGE_ME'.")
            if len(server_key_clean) < 32:
                raise ValueError("Production configuration error: SERVER_KEY must be at least 32 characters long.")
            if server_key_clean in COMMITTED_INSECURE_KEYS:
                raise ValueError("Production configuration error: SERVER_KEY matches a known insecure committed placeholder.")

            # 2. ADMIN_KEY
            if not self.ADMIN_KEY:
                raise ValueError("Production configuration error: ADMIN_KEY is required and cannot be empty.")
            admin_key_clean = self.ADMIN_KEY.strip()
            if "CHANGE_ME" in admin_key_clean:
                raise ValueError("Production configuration error: ADMIN_KEY contains placeholder 'CHANGE_ME'.")
            if len(admin_key_clean) < 32:
                raise ValueError("Production configuration error: ADMIN_KEY must be at least 32 characters long.")
            if admin_key_clean in COMMITTED_INSECURE_KEYS:
                raise ValueError("Production configuration error: ADMIN_KEY matches a known insecure committed placeholder.")

            # 3. DATABASE_URL
            if not self.DATABASE_URL:
                raise ValueError("Production configuration error: DATABASE_URL is required.")
            if "CHANGE_ME" in self.DATABASE_URL:
                raise ValueError("Production configuration error: DATABASE_URL contains placeholder 'CHANGE_ME'.")
            if self.DATABASE_URL.lower().startswith("sqlite"):
                raise ValueError("Production configuration error: SQLite cannot be used in production.")

            # 4. DASHBOARD_PASSWORD
            if not self.DASHBOARD_PASSWORD:
                raise ValueError("Production configuration error: DASHBOARD_PASSWORD is required in production.")
            dash_pwd_clean = self.DASHBOARD_PASSWORD.strip()
            if "CHANGE_ME" in dash_pwd_clean:
                raise ValueError("Production configuration error: DASHBOARD_PASSWORD contains placeholder 'CHANGE_ME'.")
            if dash_pwd_clean in COMMITTED_INSECURE_KEYS:
                raise ValueError("Production configuration error: DASHBOARD_PASSWORD matches a known insecure committed placeholder.")
            if self.DASHBOARD_USER == "admin" and len(dash_pwd_clean) < 16:
                raise ValueError("Production configuration error: DASHBOARD_PASSWORD must be at least 16 characters for admin user.")

            # 5. SEED_TEST_PARTNERS
            if self.SEED_TEST_PARTNERS:
                raise ValueError("Production configuration error: SEED_TEST_PARTNERS must be False in production.")

        else:
            # In development, provide safe fallbacks if not explicitly provided
            used_fallbacks = []
            if not self.SERVER_KEY:
                self.SERVER_KEY = "dev_server_rekey_key_default_32_bytes_long!!"
                used_fallbacks.append("SERVER_KEY")
            if not self.ADMIN_KEY:
                self.ADMIN_KEY = "dev_admin_key_default_32_bytes_long_xyz!!"
                used_fallbacks.append("ADMIN_KEY")
            if not self.DATABASE_URL:
                self.DATABASE_URL = "sqlite:///./registry.db"
                used_fallbacks.append("DATABASE_URL")
            if not self.DASHBOARD_PASSWORD:
                self.DASHBOARD_PASSWORD = "dev_dashboard_password"
                used_fallbacks.append("DASHBOARD_PASSWORD")
            if used_fallbacks:
                print(f"\n[SECURITY WARNING] Development fallback keys in use: {', '.join(used_fallbacks)}. Never run in production with these keys.\n")

settings = Settings()
settings.validate_production_security()
