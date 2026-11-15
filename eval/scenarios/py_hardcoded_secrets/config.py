"""Application configuration with hardcoded secret key."""
import os

# VULNERABILITY: Hardcoded API secret (Bandit B105 / CWE-798)
API_SECRET_KEY = "sk_live_9928347102938471928374"

def get_api_key() -> str:
    return API_SECRET_KEY

