"""Unit tests checking elimination of hardcoded secrets."""
import os
import config
from jwt_auth import sign_token

def test_secret_not_hardcoded():
    # Hardcoded string must be eliminated
    assert config.API_SECRET_KEY != "sk_live_9928347102938471928374", "Hardcoded API secret detected in codebase!"

def test_dynamic_key_loading(monkeypatch):
    monkeypatch.setenv("API_SECRET_KEY", "env_provided_token_123")
    token = sign_token({"user_id": "usr_42"})
    assert "usr_42" in token

