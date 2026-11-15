"""Database connection credentials module."""
import os

# VULNERABILITY: Hardcoded database password (Bandit B105 / CWE-798)
DATABASE_PASSWORD = "super_secret_db_password_9921"

def get_connection_string() -> str:
    return f"postgresql://admin:{DATABASE_PASSWORD}@db.production:5432/app"

