import os
from typing import Optional, List
from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings

N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

BURNED_SCALARS_HEX = {
    "7a2f3e1b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f",
    "5d8a9f1b2c3e4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f91",
    "5cfa51060880d8d043bf65b215457a97ade09f39b2d00ee6de4083ee4d87c7a8",
    "9fe8ad784aa9c596b091060eeaf91ef3330eae2954251a91018aa76699983a85",
}
BURNED_SCALAR_INTS = {int(h, 16) % N_ORDER for h in BURNED_SCALARS_HEX}

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
    # Burned VOPRF Evaluator Scalars from public repository history (permanently burned)
    "0x7a2f3e1b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f",
    "7a2f3e1b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f",
    "0x5d8a9f1b2c3e4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f91",
    "5d8a9f1b2c3e4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f91",
    "0x5cfa51060880d8d043bf65b215457a97ade09f39b2d00ee6de4083ee4d87c7a8",
    "5cfa51060880d8d043bf65b215457a97ade09f39b2d00ee6de4083ee4d87c7a8",
    "0x9fe8ad784aa9c596b091060eeaf91ef3330eae2954251a91018aa76699983a85",
    "9fe8ad784aa9c596b091060eeaf91ef3330eae2954251a91018aa76699983a85",
}

class SensitiveStr(SecretStr):
    """
    Secret string that prevents disclosure in exceptions, logs, str(), f-strings, and repr() formats.
    Both str() and repr() display masked asterisks '**********'.
    To retrieve the plaintext value for intentional cryptographic or authentication operations,
    callers must explicitly invoke .get_secret_value().
    """
    def encode(self, *args, **kwargs):
        return self.get_secret_value().encode(*args, **kwargs)

    def strip(self, *args, **kwargs):
        return self.get_secret_value().strip(*args, **kwargs)

    def startswith(self, *args, **kwargs):
        return self.get_secret_value().startswith(*args, **kwargs)

    def lower(self):
        return self.get_secret_value().lower()

    def __len__(self):
        return len(self.get_secret_value())

    def __eq__(self, other):
        val = self.get_secret_value()
        if isinstance(other, SecretStr):
            return val == other.get_secret_value()
        return val == other

class Settings(BaseSettings):
    APP_NAME: str = "Farmer Hash Registry"
    ENV: str = "production"

    @field_validator("ENV", mode="before")
    @classmethod
    def normalize_env(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError("ENV must be a non-empty string.")
        norm = v.strip().lower()
        valid_envs = {"production", "development", "staging"}
        if norm not in valid_envs:
            raise ValueError(f"Invalid ENV '{v}'. Must be one of {sorted(list(valid_envs))}.")
        return norm
    DATABASE_URL: Optional[str] = None
    SERVER_KEY: Optional[SensitiveStr] = None
    ADMIN_KEY: Optional[SensitiveStr] = None

    # 2-of-3 Split-Key Evaluator Configuration
    EVALUATOR_PARTY_ID: Optional[str] = "safic"  # safic | operator | independent
    EVALUATOR_PARTY_INDEX: Optional[int] = 1     # 1 | 2 | 3
    EVALUATOR_SHARE_K: Optional[SensitiveStr] = None  # This party's 64-hex secret share
    EVALUATOR_KEY_ID: str = "ke-pilot-v4"
    EVALUATOR_PEER_PUBKEYS: Optional[str] = None  # Comma-separated base64 Ki for parties 1, 2, 3
    EVALUATOR_AGGREGATE_PUB: Optional[str] = None # Pinned base64 K

    # Quota and rate-limiting configuration
    PARTNER_DAILY_QUOTA: int = 10000
    PARTNER_QUOTA_WINDOW_HOURS: int = 24
    MAX_CLOCK_SKEW_SECONDS: int = 900
    SIM_REASSIGNMENT_DORMANCY_DAYS: int = 90
    CURVE_BACKEND: str = "pure_python"  # pure_python | native

    PILOT_START_DATE: str = "2026-10-01"
    SUPPRESSION_THRESHOLD: int = 5  # Privacy k-anonymity rule: suppress counts < 5
    DASHBOARD_USER: str = "admin"
    DASHBOARD_PASSWORD: Optional[SensitiveStr] = None
    SEED_TEST_PARTNERS: bool = False

    class Config:
        env_file = ".env"
        extra = "ignore"

    def __init__(self, **values):
        super().__init__(**values)
        self.validate_production_security()

    def validate_production_security(self):
        """
        Enforce strict validation across environments.
        Refuses startup if single-key EVALUATOR_SECRET_K is present, shares are invalid/burned,
        peer public keys do not match, or SQLite is used in production.
        """
        # CRITICAL REGRESSION GATE: Refuse startup if deprecated EVALUATOR_SECRET_K is present anywhere
        raw_secret_k = os.environ.get("EVALUATOR_SECRET_K")
        if raw_secret_k is not None:
            raise ValueError(
                "FATAL CONFIGURATION ERROR: EVALUATOR_SECRET_K is present in the environment. "
                "The system has migrated to a 2-of-3 split-key architecture. "
                "EVALUATOR_SECRET_K is strictly forbidden and must be removed from all configurations."
            )

        # Split-Key Evaluator Share Validation
        if self.EVALUATOR_SHARE_K is not None:
            raw_share = self.EVALUATOR_SHARE_K.get_secret_value() if hasattr(self.EVALUATOR_SHARE_K, "get_secret_value") else str(self.EVALUATOR_SHARE_K)
            clean_share = raw_share.strip()
            if not clean_share:
                raise ValueError("Evaluator configuration error: EVALUATOR_SHARE_K cannot be empty.")

            if "change_me" in clean_share.lower() or clean_share.lower() in COMMITTED_INSECURE_KEYS:
                raise ValueError("Evaluator configuration error: EVALUATOR_SHARE_K matches a known burned or insecure placeholder key.")

            hex_share = clean_share[2:] if clean_share.startswith(("0x", "0X")) else clean_share
            if len(hex_share) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hex_share):
                raise ValueError("Evaluator configuration error: EVALUATOR_SHARE_K must be exactly 64 hexadecimal characters.")

            share_val = int(hex_share, 16) % N_ORDER
            if share_val == 0:
                raise ValueError("Evaluator configuration error: EVALUATOR_SHARE_K cannot be zero modulo curve order.")

            if share_val in BURNED_SCALAR_INTS:
                raise ValueError("Evaluator configuration error: EVALUATOR_SHARE_K matches a known burned scalar from public repository history.")

            # Validate peer public keys configuration
            if self.EVALUATOR_PEER_PUBKEYS:
                peer_keys = [k.strip() for k in self.EVALUATOR_PEER_PUBKEYS.split(",") if k.strip()]
                if len(peer_keys) != 3:
                    raise ValueError(f"Evaluator configuration error: EVALUATOR_PEER_PUBKEYS must contain exactly 3 keys, found {len(peer_keys)}.")

                # If party index is configured (1, 2, or 3), verify derived Ki matches corresponding peer pubkey
                if self.EVALUATOR_PARTY_INDEX in (1, 2, 3):
                    from app.crypto.voprf import point_mul, GENERATOR_G, GroupElement
                    import base64
                    derived_pt = point_mul(share_val, GENERATOR_G.pt)
                    derived_b64 = base64.b64encode(GroupElement(derived_pt).to_bytes()).decode("utf-8")
                    expected_b64 = peer_keys[self.EVALUATOR_PARTY_INDEX - 1]
                    if derived_b64 != expected_b64:
                        raise ValueError(
                            f"Evaluator configuration error: derived Ki for party index {self.EVALUATOR_PARTY_INDEX} "
                            f"does not match published peer public key '{expected_b64}'."
                        )

        # Curve Backend Validation
        backend = (self.CURVE_BACKEND or "pure_python").strip().lower()
        if backend not in ("pure_python", "native"):
            raise ValueError(f"Invalid CURVE_BACKEND '{self.CURVE_BACKEND}'. Must be 'pure_python' or 'native'.")

        if self.ENV == "production":
            if backend == "native":
                from app.crypto.voprf import _NATIVE_AVAILABLE
                if not _NATIVE_AVAILABLE:
                    raise ValueError("Production configuration error: CURVE_BACKEND='native' is configured but native bindings are unavailable.")

            # 1. SERVER_KEY
            server_key_str = self.SERVER_KEY.get_secret_value() if self.SERVER_KEY else None
            if not server_key_str or not server_key_str.strip():
                raise ValueError("Production configuration error: SERVER_KEY is required and cannot be empty.")
            server_key_clean = server_key_str.strip()
            if "CHANGE_ME" in server_key_clean:
                raise ValueError("Production configuration error: SERVER_KEY contains placeholder 'CHANGE_ME'.")
            if len(server_key_clean) < 32:
                raise ValueError("Production configuration error: SERVER_KEY must be at least 32 characters long.")
            if server_key_clean in COMMITTED_INSECURE_KEYS or server_key_clean.lower() == "none":
                raise ValueError("Production configuration error: SERVER_KEY matches a known insecure committed placeholder.")

            # 2. ADMIN_KEY
            admin_key_str = self.ADMIN_KEY.get_secret_value() if self.ADMIN_KEY else None
            if not admin_key_str or not admin_key_str.strip():
                raise ValueError("Production configuration error: ADMIN_KEY is required and cannot be empty.")
            admin_key_clean = admin_key_str.strip()
            if "CHANGE_ME" in admin_key_clean:
                raise ValueError("Production configuration error: ADMIN_KEY contains placeholder 'CHANGE_ME'.")
            if len(admin_key_clean) < 32:
                raise ValueError("Production configuration error: ADMIN_KEY must be at least 32 characters long.")
            if admin_key_clean in COMMITTED_INSECURE_KEYS:
                raise ValueError("Production configuration error: ADMIN_KEY matches a known insecure committed placeholder.")

            # 3. DATABASE_URL
            if not self.DATABASE_URL or not self.DATABASE_URL.strip():
                raise ValueError("Production configuration error: DATABASE_URL is required and cannot be empty.")
            db_clean = self.DATABASE_URL.strip().lower()
            if "change_me" in db_clean:
                raise ValueError("Production configuration error: DATABASE_URL contains placeholder 'CHANGE_ME'.")
            if "sqlite" in db_clean:
                raise ValueError("Production configuration error: SQLite cannot be used in production (strictly forbidden).")

            # 4. DASHBOARD_PASSWORD
            dash_pw_str = self.DASHBOARD_PASSWORD.get_secret_value() if self.DASHBOARD_PASSWORD else None
            if not dash_pw_str or not dash_pw_str.strip():
                raise ValueError("Production configuration error: DASHBOARD_PASSWORD is required and cannot be empty.")
            dash_pw_clean = dash_pw_str.strip()
            if "change_me" in dash_pw_clean.lower() or dash_pw_clean in COMMITTED_INSECURE_KEYS:
                raise ValueError("Production configuration error: DASHBOARD_PASSWORD matches a known insecure placeholder.")
            if self.DASHBOARD_USER == "admin" and len(dash_pw_clean) < 16:
                raise ValueError("Production configuration error: DASHBOARD_PASSWORD must be at least 16 characters.")

            # 5. SEED_TEST_PARTNERS
            if self.SEED_TEST_PARTNERS:
                raise ValueError("Production configuration error: SEED_TEST_PARTNERS must be False in production.")

            # 6. EVALUATOR_SHARE_K
            share_str = self.EVALUATOR_SHARE_K.get_secret_value() if self.EVALUATOR_SHARE_K else None
            if not share_str or not share_str.strip():
                raise ValueError("Production configuration error: EVALUATOR_SHARE_K is required and cannot be empty.")

            # 7. EVALUATOR_PEER_PUBKEYS
            if not self.EVALUATOR_PEER_PUBKEYS or not self.EVALUATOR_PEER_PUBKEYS.strip():
                raise ValueError("Production configuration error: EVALUATOR_PEER_PUBKEYS is required and cannot be empty.")

            # 8. EVALUATOR_AGGREGATE_PUB
            if not self.EVALUATOR_AGGREGATE_PUB or not self.EVALUATOR_AGGREGATE_PUB.strip():
                raise ValueError("Production configuration error: EVALUATOR_AGGREGATE_PUB is required and cannot be empty.")

settings = Settings()
