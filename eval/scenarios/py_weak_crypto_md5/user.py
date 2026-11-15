"""User registration service."""
from typing import Dict, Any
from hasher import hash_password

def create_user_record(username: str, plain_pass: str) -> Dict[str, Any]:
    digest = hash_password(plain_pass)
    return {"user": username, "hash": digest}

