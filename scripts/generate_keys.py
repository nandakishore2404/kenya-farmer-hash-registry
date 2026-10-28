import os
import sys
import secrets
import string
import hmac
import hashlib

def generate_key(num_bytes: int = 32) -> str:
    """Generates a high-entropy hex-encoded cryptographic secret."""
    return secrets.token_hex(num_bytes)

def main():
    print("=======================================================")
    print("  KENYA FARMER HASH REGISTRY - KEY GENERATOR")
    print("=======================================================\n")
    
    partner_key = generate_key(32)
    server_key = generate_key(32)
    admin_key = generate_key(32)
    evaluator_secret_k = generate_key(32)
    dashboard_pass = secrets.token_urlsafe(16)
    
    print(f"PARTNER_KEY (Shared pilot secret for delivery partners):")
    print(f"  {partner_key}\n")
    print(f"SERVER_KEY (Private server-rekeying key for SAFIC registry):")
    print(f"  {server_key}\n")
    print(f"ADMIN_KEY (Private key for administrative inspection):")
    print(f"  {admin_key}\n")
    print(f"EVALUATOR_SECRET_K (Evaluator master private key scalar for VOPRF epoch ke-pilot-v3):")
    print(f"  {evaluator_secret_k}\n")
    print(f"DASHBOARD_PASSWORD (Password for HTTP Basic Auth):")
    print(f"  {dashboard_pass}\n")
    print("-------------------------------------------------------")
    print("Save these values directly into your production .env file.")
    print("Never commit this file or the generated keys to Git.")
    print("=======================================================")

    if "--write-env" in sys.argv:
        env_path = ".env"
        if not os.path.exists(env_path):
            with open(env_path, "w", encoding="utf-8") as f:
                f.write(f"ENV=development\n")
                f.write(f"DATABASE_URL=sqlite:///./local.db\n")
                f.write(f"SERVER_KEY={server_key}\n")
                f.write(f"ADMIN_KEY={admin_key}\n")
                f.write(f"EVALUATOR_SECRET_K={evaluator_secret_k}\n")
                f.write(f"EVALUATOR_KEY_ID=ke-pilot-v3\n")
                f.write(f"PARTNER_KEY=partner_shared_pilot_secret\n")
                f.write(f"PILOT_START_DATE=2026-10-01\n")
                f.write(f"DASHBOARD_USER=admin\n")
                f.write(f"DASHBOARD_PASSWORD=dev_dashboard_password\n")
                f.write(f"SEED_TEST_PARTNERS=true\n")
            print(f"Created local {env_path} with fresh development keys!")
        else:
            print(f"{env_path} already exists. Not overwriting.")

if __name__ == "__main__":
    main()
