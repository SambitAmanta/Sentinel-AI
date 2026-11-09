"""User service demonstrating cross-file function calls."""
import sqlite3
from typing import Optional, Dict, Any
from db import get_user_by_id

def authenticate_and_get_profile(conn: sqlite3.Connection, user_id: str) -> Optional[Dict[str, Any]]:
    """Fetches user profile by calling db.get_user_by_id."""
    user = get_user_by_id(conn, user_id)
    if user:
        user["status"] = "ACTIVE"
    return user

