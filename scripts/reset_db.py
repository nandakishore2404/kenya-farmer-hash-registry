import os
import sys

# Ensure root in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.config import settings
from app.database import Base, engine
from app.main import init_db

def reset_local_db():
    print("Resetting local database...")
    db_file = "local.db"
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
            print(f"Removed {db_file}")
        except Exception as e:
            print(f"Note: Could not delete {db_file} directly (may be open): {e}")
            
    # Drop and recreate all tables via SQLAlchemy metadata
    Base.metadata.drop_all(bind=engine)
    init_db()
    print("Database reset complete. Seeded Test Partners A, B, and C.")

if __name__ == "__main__":
    reset_local_db()
