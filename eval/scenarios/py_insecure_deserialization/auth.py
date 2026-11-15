"""Authentication middleware reading session."""
from typing import Optional
from session import load_session_data

def verify_user_session(cookie_bytes: bytes) -> Optional[str]:
    data = load_session_data(cookie_bytes)
    return data.get("user_id")

