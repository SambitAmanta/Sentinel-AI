"""Token signer consuming configuration key."""
from typing import Dict, Any
from config import get_api_key

def sign_token(payload: Dict[str, Any]) -> str:
    key = get_api_key()
    return f"{payload.get('user_id')}.{key}"

